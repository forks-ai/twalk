"""The persona process: subscribe, gate, think, suggest.

This is the loop every persona runs, so that a persona author writes only
the part that is theirs — what to suggest — and gets the rest by
construction:

1. a **durable** pull consumer on ``inbound.message.received``, so a
   restart resumes where it stopped instead of losing events, and a second
   one on ``consent.state.changed`` for the grants that reach backwards;
2. the **trigger-type gate** (:func:`twalk_sdk.trigger.triggers_a_persona`),
   which refuses to wake a persona on anything but an inbound message — the
   user's own messages (``outbound.message.sent``, ADR 0018) are on the bus
   and are not a persona's business, and the consent gate cannot stop them
   because they carry no consent extension to read;
3. the **consent gate** (:mod:`twalk_sdk.consent`), applied before the
   author's handler is called and before the LLM client is ever touched: a
   ``pending`` or ``revoked`` event produces no event and no completion
   request, and no persona code runs on it;
4. ``persona.thinking.emitted`` the moment processing starts, so oversight
   can show activity in real time;
5. the **disclosure** (:mod:`twalk_sdk.disclosure`, ADR 0031): once the
   handler has returned a suggestion, the loop asks the model which
   language the reply is in — unless the author said — and selects the
   contract's sentence for it, *"Rédigé avec mon assistant IA."*, which
   travels as a field of its own and which the Companion Gateway appends
   to the reply at approval;
6. ``persona.suggest.produced`` from whatever the handler returns, with the
   contract's deterministic id, ``Nats-Msg-Id`` set, the trigger's
   ``network``, ``consent`` and trace carried through, and the expiry the
   operator's suggestion policy gives it (:mod:`twalk_sdk.policy`) — so no
   persona can publish a draft that stays approvable for ever.

Beside that loop runs a second one, on the owner's own decisions, for a
single purpose (issue #364): **a grant reaches the messages that were still
waiting for it**. The gate above is right at the instant a message arrives
and wrong a minute later — a contact becomes interesting precisely because
they just wrote — so a grant taken within
:attr:`twalk_sdk.config.Config.reach` of a message's arrival wakes the
persona on that message, read off the stream where it already is. Nothing is
re-published and nothing is re-labelled: the trigger keeps its own arrival
time and its own id, it goes through the same door a live message goes
through, and every event that comes out has the same deterministic id it
would have had — so a replay that runs twice publishes nothing twice.

Three things the loop refuses to do, the first two learned from a real
model on a real deployment (issues #162 and #164):

* it does not **retry an answer that will not change**. A trigger whose
  completion failed is redelivered — an endpoint is briefly away often
  enough to be worth it — unless the failure is one the same request would
  reproduce, and a model that spent its whole budget reasoning is exactly
  that (:mod:`twalk_sdk.completion`). Those are terminated on the first try,
  with a message naming the remedy, because every attempt is billed;
* it does not leave the **language fallback** implicit. ADR 0016 has a
  persona answer in the incoming message's language and fall back to the
  user's own only when it cannot tell, so the preference is configuration
  (``TWALK_USER_LANGUAGE``) — and when it is unset the log says what will
  happen instead of the gap passing unmentioned;
* it does not **publish a reply it cannot disclose**. A reply in a language
  the contract has no sentence for is no suggestion at all (ADR 0031): the
  delivery is terminated with one ``ERROR`` line naming the language the
  model answered, and never retried, because the model would answer the
  same language again. A silent fallback into the wrong language is a
  sentence nobody reads; a named refusal is one an operator can act on.

The persona talks to the bus itself (ADR 0008): the Hermes runtime starts
it as a process and supervises it, but never sits between it and the bus.

What a persona author writes:

```python
from twalk_sdk import Persona, Suggestion, system, user

persona = Persona.from_env()


@persona.on_inbound_message
async def draft(message, context):
    if not message.body:
        return None
    reply = await context.llm.complete(
        [system("Draft a reply."), user(message.body)]
    )
    return Suggestion(body=reply)


if __name__ == "__main__":
    persona.run()
```
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import time
from dataclasses import dataclass, replace
from datetime import timedelta
from typing import Any, Awaitable, Callable, Dict, Optional, Union

import nats
import nats.errors
import nats.js.errors
from nats.aio.msg import Msg
from nats.js import JetStreamContext
from nats.js.api import AckPolicy, ConsumerConfig, DeliverPolicy

from .config import Config
from .consent import (
    CONSENT_CHANGED_TYPE,
    GRANTED,
    Grant,
    consent_of,
    grant_in,
    is_granted,
)
from .completion import LlmError
from .disclosure import DisclosureError, LanguageAskFailed, sentence_for
from .envelope import (
    FIRST_ATTEMPT,
    Suggestion,
    nats_headers,
    rfc3339,
    suggest_event,
    thinking_event,
    utc_now,
)
from .hermes import HandedToHermes, Hermes
from .language import USER_LANGUAGE_VARIABLE
from .llm import Llm
from .trigger import MESSAGE_RECEIVED_TYPE, InboundMessage, triggers_a_persona, type_of

logger = logging.getLogger("twalk_sdk")

#: How long one pull waits for an event before the loop checks whether it
#: was asked to stop. Short enough that SIGTERM is honoured promptly, long
#: enough that an idle persona is not a busy loop.
FETCH_TIMEOUT_SECONDS = 2.0

#: How long a failed event waits before JetStream redelivers it. A failure
#: here is usually the LLM endpoint being briefly unavailable, so the retry
#: is worth having — and bounded by ``MAX_DELIVER``, because a message that
#: fails deterministically must not be retried forever.
#:
#: Retried, though, only when a retry could answer differently. A model that
#: spent its budget reasoning will spend it again, and every attempt is
#: billed: that outcome is terminated on the first try rather than retried
#: (:attr:`twalk_sdk.completion.LlmError.transient`, issue #162).
RETRY_DELAY_SECONDS = 5
MAX_DELIVER = 3

#: How long the bus waits for a decision's replay before offering the decision
#: again. A replay is as long as the messages a grant reaches: one completion
#: each, sequentially, and a contact who wrote a dozen times in the hour before
#: the grant is a dozen completions. So the deadline is generous, and the loop
#: also tells the bus it is still working after each message
#: (``Msg.in_progress``) — the two together, because the first alone would be a
#: number somebody has to keep in step with the model's latency.
DECISION_ACK_WAIT_SECONDS = 300

#: How many messages one replay reads off the stream before it stops looking.
#: Not a limit on how many are *answered* — that is the reach, and the consent
#: screen states the count before the owner grants, so the number of drafts is
#: something they were told and agreed to. This bounds the *reading*: the
#: window is an hour of the whole deployment's inbound traffic, of which a
#: replay wants one contact's, and a loop with no bound is a loop that a busy
#: hour turns into a stall.
MOST_MESSAGES_READ_BACK = 5_000

#: How long a persona waits for the bus and its stream to exist before
#: giving up. A persona starts beside NATS in a compose deployment, so it
#: may well come up first.
STARTUP_ATTEMPTS = 60
STARTUP_DELAY_SECONDS = 1.0


@dataclass
class Context:
    """What the SDK lends a persona for the duration of one event."""

    config: Config
    llm: Llm
    logger: logging.Logger = logger
    #: The seam to Hermes (ADR 0032), or ``None`` when the deployment
    #: configured none. A persona that finds it ``None`` reasons with
    #: :attr:`llm` and nothing leaves the deployment — which is what every
    #: deployment before this ticket does, and the reason the seam is a
    #: capability the handler asks for rather than a step the loop takes.
    hermes: Optional[Hermes] = None


#: What a handler may answer with. Three outcomes, because there are three
#: facts: a draft this persona wrote, a wake it handed to Hermes (whose
#: answer arrives later through the Companion Gateway, ADR 0032), and
#: nothing to say.
Outcome = Union[Suggestion, HandedToHermes, None]
Handler = Callable[[InboundMessage, Context], Awaitable[Outcome]]


@dataclass(frozen=True)
class Verdict:
    """What waking a persona on one trigger decided about its delivery.

    Three answers, and the caller — not the waking — turns them into the
    bus's verbs, because there are two callers and they hold different
    deliveries. The live loop holds the trigger's own: done is an ack,
    hopeless a term, and a retry a nak with the delay. A replay holds the
    *decision* that reached back (:meth:`Persona._replay_for`): done and
    hopeless are both "carry on with the next message", and a retry is the
    decision's own nak, which runs the whole replay again — safely, because
    every event a replay publishes has a deterministic id and the bus absorbs
    the second copy.
    """

    hopeless: bool = False
    retry_in: Optional[float] = None


#: Nothing more to do with this trigger: it produced what it was going to.
DONE = Verdict()

#: An answer that will not change however often it is tried (issue #162).
HOPELESS = Verdict(hopeless=True)


class Persona:
    """A persona process, configured and ready to run."""

    def __init__(
        self,
        config: Config,
        llm: Optional[Llm] = None,
        hermes: Optional[Hermes] = None,
    ) -> None:
        self.config = config
        self.llm = llm or Llm(config.llm)
        # Built here and not in the handler: the seam's configuration is
        # validated once, at startup, and a persona author is handed a client
        # that can only send the narrow template (twalk_sdk.webhook).
        self.hermes = hermes or (Hermes(config.hermes) if config.hermes else None)
        self._handler: Optional[Handler] = None
        self._stop = asyncio.Event()

    @classmethod
    def from_env(cls) -> "Persona":
        return cls(Config.from_env())

    def on_inbound_message(self, handler: Handler) -> Handler:
        """Registers the persona's handler for inbound messages.

        Called with events whose consent is ``granted`` and nothing else.
        Returning a :class:`Suggestion` publishes it; returning ``None``
        means "nothing to suggest here" and is the right answer for a
        message this persona has no business replying to.
        """
        if self._handler is not None:
            raise RuntimeError("a persona registers one inbound-message handler")
        self._handler = handler
        return handler

    def run(self) -> None:
        """Runs the persona until it is asked to stop. The process entry
        point."""
        logging.basicConfig(
            level=self.config.log_level.upper(),
            format="%(asctime)s %(levelname)s %(name)s %(message)s",
        )
        asyncio.run(self.serve())

    async def serve(self) -> None:
        if self._handler is None:
            raise RuntimeError(
                "this persona registered no handler: decorate one with "
                "@persona.on_inbound_message"
            )
        # Re-created here: the event must belong to the loop that runs.
        self._stop = asyncio.Event()
        self._install_signal_handlers()

        logger.info(
            "persona starting persona_id=%s source=%s nats=%s stream=%s subject_prefix=%s "
            "consumer=%s model=%s user_language=%s",
            self.config.persona_id,
            self.config.source,
            self.config.nats_url,
            self.config.stream,
            self.config.subject_prefix,
            self.config.durable_name,
            self.config.llm.model,
            self.config.user_language or "unset",
        )
        self._say_what_the_language_fallback_will_do()
        await self._say_where_hermes_is()
        connection = await self._connect()
        jetstream = connection.jetstream()
        await self._await_stream(jetstream)
        subscription = await self._subscribe(jetstream)
        decisions = await self._subscribe_to_decisions(jetstream)
        logger.info(
            "persona ready subject=%s decisions=%s reach=%ss",
            self.config.subject(MESSAGE_RECEIVED_TYPE),
            self.config.subject(CONSENT_CHANGED_TYPE),
            self.config.reach.seconds,
        )
        try:
            # A task group, so that either loop failing takes the process down
            # rather than leaving a persona that reads messages and no longer
            # hears the owner's decisions, or the reverse. Both watch the same
            # stop event, so SIGTERM ends both.
            async with asyncio.TaskGroup() as running:
                running.create_task(self._consume(jetstream, subscription))
                running.create_task(self._consume_decisions(jetstream, decisions))
        finally:
            await self.llm.aclose()
            if self.hermes is not None:
                await self.hermes.aclose()
            await connection.drain()
            logger.info("persona stopped persona_id=%s", self.config.persona_id)

    def stop(self) -> None:
        """Asks the loop to finish the event in flight and return."""
        self._stop.set()

    def _say_what_the_language_fallback_will_do(self) -> None:
        """States, at startup, what happens on a message whose language
        cannot be told (ADR 0016, issue #164).

        A persona does not refuse to start over this — it answers every
        unambiguous message correctly without a preference — but it does not
        choose silently either. With the preference, the fallback is named;
        without it, so is its absence, in the log an operator reads, naming
        the variable and where it is set.
        """
        if self.config.user_language:
            logger.info(
                "an ambiguous message will be answered in the user's own "
                "language (%s=%s); one whose language the model can tell is "
                "answered in that language, which is the decision ADR 0016 "
                "makes",
                USER_LANGUAGE_VARIABLE,
                self.config.user_language,
            )
            return
        logger.warning(
            "no user language is configured (%s is unset), so ADR 0016's "
            "fallback has no value: a message too short to tell — a greeting, "
            "a single word, an emoji, a link — will be answered in whatever "
            "language the model picks, which on the reference deployment was "
            "English for a French speaker. The user sets it in the Companion's "
            "settings; the Hermes runtime injects it as HERMES_USER_LANGUAGE. "
            "Every message whose language is readable is unaffected.",
            USER_LANGUAGE_VARIABLE,
        )

    async def _say_where_hermes_is(self) -> None:
        """States the seam, and whether Hermes is there (ADR 0032).

        An unreachable Hermes does not stop this persona: the shape is the
        Sensor's own answer to the same question about the Gateway's consent
        snapshot — start anyway, ``ERROR`` naming the URL and what happens
        instead, retry in the background (:mod:`twalk_sdk.hermes`). Saying
        nothing when no seam is configured is deliberate too: a deployment
        that never asked for one is not in an error state, and the startup
        line above already names the model it reasons with.
        """
        if self.hermes is None:
            return
        self.hermes.say_what_it_is()
        if not await self.hermes.announce_reachability():
            self.hermes.retry_in_the_background()

    def _install_signal_handlers(self) -> None:
        """SIGTERM is how a container is asked to stop; an event in flight
        is finished and acked before the process exits, so nothing is
        processed twice."""
        loop = asyncio.get_running_loop()
        for received in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(received, self.stop)
            except (NotImplementedError, RuntimeError):  # pragma: no cover
                pass

    async def _connect(self) -> Any:
        last_error: Optional[Exception] = None
        for attempt in range(STARTUP_ATTEMPTS):
            try:
                return await nats.connect(
                    self.config.nats_url,
                    name=f"twalk-persona-{self.config.persona_id}",
                    max_reconnect_attempts=-1,
                    reconnect_time_wait=1,
                )
            except Exception as error:  # nats raises several unrelated types
                last_error = error
                if attempt == 0:
                    logger.info("waiting for the bus at %s", self.config.nats_url)
                await asyncio.sleep(STARTUP_DELAY_SECONDS)
        raise RuntimeError(
            f"the bus at {self.config.nats_url} never answered: {last_error}"
        )

    async def _await_stream(self, jetstream: JetStreamContext) -> None:
        """Waits for the stream to exist rather than creating it.

        A persona is a consumer, not the bus's operator: the stream belongs
        to the deployment (the Sensor ensures it, and the Hermes runtime
        will), so a persona that created one would risk creating it with
        the wrong subjects.
        """
        for attempt in range(STARTUP_ATTEMPTS):
            try:
                await jetstream.stream_info(self.config.stream)
                return
            except nats.js.errors.NotFoundError:
                if attempt == 0:
                    logger.info("waiting for stream %s", self.config.stream)
                await asyncio.sleep(STARTUP_DELAY_SECONDS)
        raise RuntimeError(f"stream {self.config.stream} does not exist")

    async def _subscribe(
        self, jetstream: JetStreamContext
    ) -> JetStreamContext.PullSubscription:
        subject = self.config.subject(MESSAGE_RECEIVED_TYPE)
        return await jetstream.pull_subscribe(
            subject,
            durable=self.config.durable_name,
            stream=self.config.stream,
            config=ConsumerConfig(
                durable_name=self.config.durable_name,
                filter_subject=subject,
                # Explicit acks: an event is acked once the persona is done
                # with it, so a crash mid-processing redelivers it.
                ack_policy=AckPolicy.EXPLICIT,
                # A fresh consumer starts at the beginning of the stream:
                # the events that arrived before this persona was ever
                # activated are still the user's messages.
                deliver_policy=DeliverPolicy.ALL,
                max_deliver=MAX_DELIVER,
            ),
        )

    async def _subscribe_to_decisions(
        self, jetstream: JetStreamContext
    ) -> JetStreamContext.PullSubscription:
        """The owner's consent decisions, for the one thing a persona does with
        them: a grant reaches the messages that were still waiting for it
        (issue #364).

        Durable, because a grant made while this persona was restarting is
        still a grant it has to act on. Created at the stream's **head** and
        not at its beginning, which is the opposite of the inbound consumer
        above and for a reason of the same kind: an inbound message that
        arrived before a persona existed is still the user's message, while a
        decision taken before it existed has already had its effect — the
        Sensor labelled everything that arrived afterwards. A persona
        installed today that replayed the whole decision history would draft
        answers to every conversation the owner ever granted.
        """
        subject = self.config.subject(CONSENT_CHANGED_TYPE)
        name = self.config.decisions_durable_name
        return await jetstream.pull_subscribe(
            subject,
            durable=name,
            stream=self.config.stream,
            config=ConsumerConfig(
                durable_name=name,
                filter_subject=subject,
                ack_policy=AckPolicy.EXPLICIT,
                deliver_policy=DeliverPolicy.NEW,
                # A replay is one completion per message it reaches, so the
                # deadline is the replay's and not a message's.
                ack_wait=DECISION_ACK_WAIT_SECONDS,
                max_deliver=MAX_DELIVER,
            ),
        )

    async def _consume_decisions(
        self,
        jetstream: JetStreamContext,
        subscription: JetStreamContext.PullSubscription,
    ) -> None:
        """The decision loop, beside the message loop and at its own pace."""
        while not self._stop.is_set():
            try:
                messages = await subscription.fetch(1, timeout=FETCH_TIMEOUT_SECONDS)
            except (nats.errors.TimeoutError, asyncio.TimeoutError):
                continue
            except nats.errors.Error as error:
                logger.warning("pull of a decision failed, retrying: %s", error)
                await asyncio.sleep(STARTUP_DELAY_SECONDS)
                continue
            for message in messages:
                await self._decided(jetstream, message)

    async def _decided(self, jetstream: JetStreamContext, message: Msg) -> None:
        """One consent decision: a grant this persona has to reach back with,
        or a decision it has no business interpreting."""
        try:
            event = json.loads(message.data)
        except (ValueError, UnicodeDecodeError):
            logger.error(
                "dropped a decision that is not JSON, sequence=%s", _sequence(message)
            )
            await message.term()
            return
        if not isinstance(event, dict):
            logger.error("dropped a decision that is not a CloudEvents envelope")
            await message.term()
            return
        grant = grant_in(event)
        if grant is None:
            # A revocation, a decision about a network or a persona, an
            # unreadable one: the stream carries every consent decision and
            # this loop is interested in exactly one kind. Debug, not info: a
            # deployment's decisions are mostly not grants about contacts, and
            # a line each would drown the ones that matter.
            logger.debug(
                "a decision this persona does nothing with event_id=%s",
                event.get("id"),
            )
            await message.ack()
            return
        if not self.config.reach.is_fresh(grant, utc_now()):
            logger.info(
                "a grant older than the reach answers nothing contact=%s "
                "granted_at=%s reach=%ss",
                grant.contact,
                rfc3339(grant.occurred_at),
                self.config.reach.seconds,
            )
            await message.ack()
            return
        await _settle(
            message,
            await self._replay_for(
                jetstream,
                grant,
                deliveries=_deliveries(message),
                still_working=message.in_progress,
            ),
        )

    async def _replay_for(
        self,
        jetstream: JetStreamContext,
        grant: Grant,
        deliveries: Optional[int],
        still_working: Callable[[], Awaitable[None]],
    ) -> Verdict:
        """Wakes the persona on the messages this grant reaches.

        The messages are read off the stream where they already are — nothing
        is re-published and nothing is re-labelled, so each keeps its own
        arrival time and its own id, and the journal shows one message answered
        late rather than a contact who wrote twice. They then go through
        :meth:`_process`, which is the same door a live message goes through.

        The read is a consumer over the window the reach describes, named for
        this replay — nats-py binds a pull subscription by name, so even a
        consumer meant to live for one call has one — and deleted when the call
        is done. It acks nothing and resumes nothing: the decision's own
        delivery is what makes the work durable. If any message asks to be retried the whole decision is
        naked and the replay runs again — which is safe rather than wasteful,
        since a message already answered recomputes the same thinking id and
        the same suggestion id, and the bus absorbs both.
        """
        reach = self.config.reach
        if reach.seconds == 0:
            # An operator who set zero has said a grant reaches nothing. Said
            # out loud, because a silent no-op here is the defect this ticket
            # is about.
            logger.info(
                "a grant reaches nothing: the reach is zero contact=%s",
                grant.contact,
            )
            return DONE
        subject = self.config.subject(MESSAGE_RECEIVED_TYPE)
        name = (
            f"{self.config.durable_name}-reach-{os.getpid()}-"
            f"{time.monotonic_ns()}"
        )
        since = rfc3339(grant.occurred_at - timedelta(seconds=reach.seconds))
        read = await jetstream.pull_subscribe(
            subject,
            durable=name,
            stream=self.config.stream,
            config=ConsumerConfig(
                durable_name=name,
                filter_subject=subject,
                deliver_policy=DeliverPolicy.BY_START_TIME,
                opt_start_time=since,
                ack_policy=AckPolicy.NONE,
                # A consumer this loop forgot to delete goes on its own.
                inactive_threshold=DECISION_ACK_WAIT_SECONDS,
            ),
        )
        reached = 0
        read_back = 0
        unanswered = 0
        retry_in: Optional[float] = None
        try:
            while read_back < MOST_MESSAGES_READ_BACK:
                try:
                    batch = await read.fetch(10, timeout=FETCH_TIMEOUT_SECONDS)
                except (nats.errors.TimeoutError, asyncio.TimeoutError):
                    break
                for message in batch:
                    read_back += 1
                    try:
                        event = json.loads(message.data)
                    except (ValueError, UnicodeDecodeError):
                        continue
                    if not isinstance(event, dict):
                        continue
                    if not triggers_a_persona(event):
                        continue
                    if not reach.reaches(event, grant):
                        continue
                    reached += 1
                    logger.info(
                        "a grant reaches a message that was waiting for it "
                        "event_id=%s contact=%s arrived=%s granted_at=%s",
                        event.get("id"),
                        grant.contact,
                        event.get("time"),
                        rfc3339(grant.occurred_at),
                    )
                    verdict = await self._process(
                        jetstream, event, deliveries=deliveries
                    )
                    if verdict.retry_in is not None:
                        retry_in = max(retry_in or 0.0, verdict.retry_in)
                    if verdict.hopeless:
                        # Already an ERROR line of its own, naming the event.
                        # Counted here as well, so that the line below can name
                        # the *grant*: an operator reading about a model that
                        # refused an answer should not have to join an event id
                        # to a decision to find out which contact went
                        # unanswered.
                        unanswered += 1
                    # A message that could not be answered must not stop the
                    # ones behind it.
                    await still_working()
            if read_back >= MOST_MESSAGES_READ_BACK:
                logger.error(
                    "a grant's replay stopped after reading %s messages, which "
                    "is its limit: contact=%s may have messages inside the "
                    "reach that were not answered",
                    read_back,
                    grant.contact,
                )
        finally:
            try:
                await jetstream.delete_consumer(self.config.stream, name)
            except Exception as error:  # noqa: BLE001 - tidiness, not correctness
                logger.warning("a replay's consumer outlived it: %s", error)
        logger.info(
            "a grant reached %s of the %s messages read back contact=%s reach=%ss",
            reached,
            read_back,
            grant.contact,
            reach.seconds,
        )
        if unanswered:
            # The grant did reach these and they produced nothing, for a reason
            # each has already logged. Said again as one line about the
            # decision, because this is the shape of the silence #364 is about:
            # the owner granted somebody and expects an answer.
            logger.error(
                "a grant reached %s messages that produced no suggestion "
                "contact=%s granted_at=%s: the owner will see nothing for them",
                unanswered,
                grant.contact,
                rfc3339(grant.occurred_at),
            )
        return DONE if retry_in is None else Verdict(retry_in=retry_in)

    async def _consume(
        self,
        jetstream: JetStreamContext,
        subscription: JetStreamContext.PullSubscription,
    ) -> None:
        while not self._stop.is_set():
            try:
                messages = await subscription.fetch(1, timeout=FETCH_TIMEOUT_SECONDS)
            except (nats.errors.TimeoutError, asyncio.TimeoutError):
                continue
            except nats.errors.Error as error:
                logger.warning("pull failed, retrying: %s", error)
                await asyncio.sleep(STARTUP_DELAY_SECONDS)
                continue
            for message in messages:
                await self._handle(jetstream, message)

    async def _handle(self, jetstream: JetStreamContext, message: Msg) -> None:
        try:
            event = json.loads(message.data)
        except (ValueError, UnicodeDecodeError):
            # Not a CloudEvent: redelivery would produce the same failure,
            # so it is terminated rather than retried.
            logger.error(
                "dropped a message that is not JSON, sequence=%s", _sequence(message)
            )
            await message.term()
            return
        if not isinstance(event, dict):
            logger.error("dropped a message that is not a CloudEvents envelope")
            await message.term()
            return

        # THE TRIGGER-TYPE GATE, and it runs *before* the consent gate
        # because the event it exists for has no consent to read. The user's
        # own message (`outbound.message.sent`, ADR 0018) carries no consent
        # extension at all, so the gate below would refuse it — but with the
        # wrong reason in the log, and only by the accident of a missing
        # attribute. This one refuses it on the type, which is what actually
        # says "this is the operator writing, not somebody writing to them".
        if not triggers_a_persona(event):
            logger.info(
                "dropped an event a persona is not triggered by event_id=%s type=%s",
                event.get("id"),
                type_of(event),
            )
            await message.ack()
            return

        # THE CONSENT GATE. Before the handler, before the LLM, before
        # anything reads the message: an event a persona may not process is
        # acked and forgotten. Nothing below this line runs for it.
        if not is_granted(event):
            logger.info(
                "dropped an event whose consent is not %s event_id=%s consent=%s",
                GRANTED,
                event.get("id"),
                consent_of(event),
            )
            await message.ack()
            return

        await _settle(
            message,
            await self._process(jetstream, event, deliveries=_deliveries(message)),
        )

    async def _process(
        self,
        jetstream: JetStreamContext,
        event: Dict[str, Any],
        deliveries: Optional[int],
    ) -> "Verdict":
        """Wakes the persona on one trigger and says what its delivery should
        now do.

        Everything from the thinking event to the published suggestion, for a
        trigger that has passed both gates — or that a grant reached, which is
        the same trigger arriving late (:meth:`_replay_for`). It returns a
        verdict instead of acking, because the two callers hold different
        things: the live loop holds a JetStream delivery with a retry count,
        and a replay holds a decision whose own delivery is the retry.

        ``deliveries`` is how many times the bus has offered the delivery this
        work arrived on, which bounds how often a failure that might pass is
        retried. For a live trigger that is the trigger's own count. For a
        replay it is the **decision's**, because a replay is read off the stream
        rather than delivered from it and the decision's delivery is what will
        bring it back: so every message of one replay shares one budget, and a
        model that is down takes the whole replay's three attempts rather than
        three each.
        """
        trigger = InboundMessage(event)
        handler = self._handler
        if handler is None:  # serve() refuses to start without one
            raise RuntimeError("this persona has no inbound-message handler")
        try:
            await self._publish(
                jetstream,
                thinking_event(
                    persona_id=self.config.persona_id,
                    source=self.config.source,
                    trigger=trigger,
                    model=self.llm.model,
                ),
            )
            outcome = await handler(
                trigger,
                Context(config=self.config, llm=self.llm, hermes=self.hermes),
            )
            if outcome is None:
                logger.info(
                    "no suggestion for event_id=%s network=%s",
                    trigger.event_id,
                    trigger.network,
                )
            elif isinstance(outcome, HandedToHermes):
                # The one outcome that produces no event here. Hermes is
                # asynchronous by construction — its webhook adapter answers
                # before the agent runs — so the suggestion arrives later,
                # through the Companion Gateway's endpoint and never through
                # this process (ADR 0032). The trigger is acked: it has been
                # dealt with, and a redelivery would only re-wake Hermes on a
                # delivery id it has already absorbed.
                logger.info(
                    "handed to hermes event_id=%s network=%s reference=%s "
                    "delivery=%s already_seen=%s ignored_by_route=%s",
                    trigger.event_id,
                    trigger.network,
                    outcome.reference,
                    outcome.delivery,
                    outcome.already_seen,
                    outcome.ignored_by_route,
                )
            else:
                suggestion = await self._disclosed(outcome, trigger)
                # One reading of the clock for both: `time` says when the
                # suggestion was produced and `expires_at` when it stops
                # being approvable, and the operator's window is the
                # difference between them.
                produced_at = utc_now()
                acknowledgement = await self._publish(
                    jetstream,
                    suggest_event(
                        persona_id=self.config.persona_id,
                        source=self.config.source,
                        trigger=trigger,
                        suggestion=suggestion,
                        # Not a delivery count: a redelivered trigger is the
                        # same suggestion, so it keeps the same attempt, the
                        # same id, and collapses on the bus instead of
                        # offering the user a second draft of one message
                        # (twalk_sdk.policy).
                        attempt=FIRST_ATTEMPT,
                        time=rfc3339(produced_at),
                        expires_at=self.config.suggestion.expires_at(produced_at),
                    ),
                )
                if getattr(acknowledgement, "duplicate", False):
                    logger.info(
                        "the bus already held this suggestion: the redelivery "
                        "was absorbed rather than becoming a second attempt "
                        "event_id=%s attempt=%s",
                        trigger.event_id,
                        FIRST_ATTEMPT,
                    )
        except Exception as error:
            if _will_not_change(error):
                # An answer that will not change. Retry is for a failure that
                # might pass; this one is the model behaving exactly as
                # configured, and every attempt is billed (issue #162). So the
                # delivery is *terminated* — the trigger is not left pending
                # and redelivered, and it is not left apparently unprocessed
                # either: this line is the whole account of it.
                logger.error(
                    "no suggestion for event_id=%s network=%s and no retry: %s",
                    trigger.event_id,
                    trigger.network,
                    error,
                )
                return HOPELESS
            # Otherwise the event is not acked: JetStream redelivers it after
            # a delay, because the usual cause is an endpoint that was briefly
            # away. The redeliveries are bounded by the consumer's limit, and
            # the last one says so rather than letting the trigger disappear.
            if deliveries is not None and deliveries >= MAX_DELIVER:
                logger.error(
                    "no suggestion for event_id=%s network=%s after %s "
                    "deliveries, which is this consumer's limit: the bus will "
                    "not offer it again. %s",
                    trigger.event_id,
                    trigger.network,
                    deliveries,
                    error,
                )
                return HOPELESS
            # The delay is the failure's own when it has one. A rate-limited
            # route says "not this minute" and retrying it in five seconds
            # spends a delivery on an answer that cannot have changed yet
            # (twalk_sdk.hermes.RATE_LIMIT_DELAY_SECONDS); everything else
            # takes the loop's ordinary retry.
            delay = float(getattr(error, "retry_after", 0) or RETRY_DELAY_SECONDS)
            logger.error(
                "failed to process event_id=%s, retrying in %ss: %s",
                trigger.event_id,
                delay,
                error,
            )
            return Verdict(retry_in=delay)
        return DONE

    async def _disclosed(self, suggestion: Suggestion, trigger: InboundMessage) -> Suggestion:
        """The suggestion with the sentence its language selects (ADR 0031).

        The language is the author's when they said, and the model's answer
        otherwise (:meth:`twalk_sdk.llm.Llm.language_of`, ADR 0016) — one
        more completion per suggestion, shaped for one token. The sentence
        is always set *here*, from that language, whatever the handler put
        in ``disclosure``: what a contact is told is the contract's own
        sentence and not a persona's wording.

        A language with no sentence raises :class:`DisclosureError`, which
        is not transient: the loop terminates the delivery with one ERROR
        line and no retry, the way it does for a model that spent its whole
        budget reasoning. No suggestion is published, which is the point —
        a reply that cannot be disclosed is one that should not exist.

        The ask itself can fail the four ways any completion can, and the
        failure is re-raised as :class:`LanguageAskFailed` with the cause's
        own ``transient``: the ERROR line then says it was the *ask* and
        not the reply that failed, and names the budget remedy — because on
        a reasoning model the ask's five tokens are spent thinking, every
        time, after a reply that was drafted fine (#162, one call later).
        """
        declared = suggestion.language is not None
        language = suggestion.language
        if language is None:
            try:
                language = await self.llm.language_of(suggestion.body)
            except LlmError as error:
                raise LanguageAskFailed(error) from error
        sentence = sentence_for(language)
        if sentence is None:
            raise DisclosureError(language, declared_by_persona=declared)
        logger.info(
            "disclosure language=%s declared_by=%s event_id=%s network=%s",
            language,
            "persona" if declared else "model",
            trigger.event_id,
            trigger.network,
        )
        return replace(suggestion, disclosure=sentence)

    async def _publish(self, jetstream: JetStreamContext, event: Dict[str, Any]) -> Any:
        """Publishes one event and returns the bus's acknowledgement.

        The acknowledgement is worth having back: it says whether
        ``Nats-Msg-Id`` matched something already stored, which is how a
        replay announces itself to the persona rather than only to the bus.
        """
        subject = self.config.subject(event["type"])
        acknowledgement = await jetstream.publish(
            subject,
            json.dumps(event, ensure_ascii=False).encode("utf-8"),
            headers=nats_headers(event),
            # Naming the stream makes a misrouted publish fail loudly here
            # instead of landing somewhere no consumer reads.
            stream=self.config.stream,
        )
        logger.info(
            "published %s id=%s subject=%s", event["type"], event["id"], subject
        )
        return acknowledgement


async def _settle(message: Msg, verdict: Verdict) -> None:
    """Turns a verdict into what the bus is told about this delivery.

    One function because there are two deliveries — a trigger's and a
    decision's — and they are settled identically: the difference between them
    is what produced the verdict, not what is done with it.
    """
    if verdict.hopeless:
        await message.term()
    elif verdict.retry_in is not None:
        await message.nak(delay=verdict.retry_in)
    else:
        await message.ack()


def _will_not_change(error: BaseException) -> bool:
    """Whether redelivering this trigger would reproduce the same failure.

    Read off the exception rather than off its class, because three
    different outside things now answer the question and none should have
    to know about the others: a model that spent its whole budget reasoning
    (:class:`twalk_sdk.completion.LlmError`, issue #162), a Hermes route
    that refused the signature or does not exist
    (:class:`twalk_sdk.hermes.HermesError`, ADR 0032), and a reply in a
    language the contract has no disclosure for
    (:class:`twalk_sdk.disclosure.DisclosureError`, ADR 0031). Anything
    that does not declare itself is retried, which is the safe default — a
    failure retried once too often costs a redelivery, and one terminated
    too early loses a message.
    """
    return getattr(error, "transient", True) is False


def _sequence(message: Msg) -> Optional[int]:
    try:
        return message.metadata.sequence.stream
    except Exception:  # pragma: no cover - metadata is absent off JetStream
        return None


def _deliveries(message: Msg) -> Optional[int]:
    """How many times the bus has handed this message over, this one
    included. ``None`` off JetStream, where there is no such count."""
    try:
        return message.metadata.num_delivered
    except Exception:  # pragma: no cover - metadata is absent off JetStream
        return None
