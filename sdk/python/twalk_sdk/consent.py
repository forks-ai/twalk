"""The consent gate.

This is the module the whole SDK exists for. Twalk's promise is that no
message is processed without the sender's consent, and the spec puts the
gate *here* rather than in each persona: JetStream cannot filter by message
header, so a consumer receives every inbound event and has to decide — and
a persona author who forgets to decide would breach the promise silently.
The SDK decides first, before any persona code runs (see
``twalk_sdk.persona``).

Two properties matter, and both are tested:

* The decision reads the envelope's own ``consent`` extension — the
  top-level CloudEvents attribute — and nothing else. It never looks inside
  ``data``, so it cannot come to depend on a field that may not be there: a
  revoked sender's message arrives with no body, no excerpt and no
  attachment reference at all (ADR 0012), and the gate drops it before that
  shape could ever matter.
* Anything that is not exactly ``granted`` is refused. Not a denylist of
  ``pending`` and ``revoked``: an event whose consent extension is missing,
  misspelled, or a value a future contract adds is refused too, because the
  safe default when consent cannot be read is to not process the message.

The second half of the module is the mirror of the first: a grant the owner
makes *after* a message arrived (issue #364). The gate's refusal stands — the
envelope's label is frozen at arrival and nothing re-labels it — and what
reaches the message is the decision event itself, read here and bounded by
:class:`GrantReach`. Everything in that half is pure: the persona process
(:mod:`twalk_sdk.persona`) does the reading and the waking, and asks the
questions below.

The first property above is about the *gate* and stays exactly as narrow as it
reads: the decision whether a message may be processed is taken on the
envelope's ``consent`` attribute and on nothing else. :func:`grant_in` does
read inside ``data`` — a decision event keeps its subject, its new state, its
scope and its instant there, and there is nowhere else to read them — and that
is a different document with a different author: the Companion Gateway's
record of what the owner chose, never a contact's message.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, FrozenSet, Mapping, Optional

#: The one consent state a persona may process events under (``CONTEXT.md``:
#: "Personas must not process events whose consent is not `granted`").
GRANTED = "granted"

#: The event the owner's own decisions arrive on. A persona follows it for one
#: reason only, and it is the second half of this module: a grant taken after a
#: message arrived (issue #364).
CONSENT_CHANGED_TYPE = "fr.linagora.twalk.consent.state.changed.v1"

#: The bus remembers an event's id for a day and absorbs a second publication
#: of it (ADR 0037). Not a number this SDK chooses — it is the Sensor's stream
#: policy — and it is here because a grant's reach has to stay within it for
#: the reason :data:`DEFAULT_GRANT_REACH_SECONDS` gives.
DUPLICATE_WINDOW_SECONDS = 86_400


def consent_of(event: Mapping[str, Any]) -> Optional[str]:
    """The event's ``consent`` extension, or ``None`` when it has none.

    A non-string value counts as absent: the contract's extension is a
    string, and a producer that sent something else has told us nothing we
    can act on.
    """
    value = event.get("consent")
    return value if isinstance(value, str) else None


def is_granted(event: Mapping[str, Any]) -> bool:
    """Whether a persona may process this event at all."""
    return consent_of(event) == GRANTED


# --- A grant in the past tense (issue #364) ---------------------------------
#
# The gate above reads the envelope's own label and refuses everything that is
# not `granted`, which is right at the moment a message arrives and wrong a
# minute later. A contact becomes interesting *because* they just wrote: the
# owner watches the message land, goes to the consent screen, grants — and the
# one message they granted for is the one message the label freezes out for
# ever. That was measured on the reference deployment on 2026-09-24, thirty-
# nine seconds between the two events, and nothing was ever going to happen.
#
# So a grant reaches backwards, a bounded distance, and the authority for
# reaching is the owner's own decision event rather than a re-labelling of the
# message: nothing is re-published, nothing is re-stamped, the trigger keeps
# its arrival time and its id, and the suggestion that comes out is an
# ordinary suggestion produced by the ordinary path. What the code below adds
# is one question — *does this grant reach this message?* — asked of an event
# the gate has already refused.

#: The state a message carries when nobody has decided about its sender yet:
#: the only state a grant reaches back to. A ``revoked`` sender's message was
#: published in the contract's reduced shape (ADR 0012) — no body, no excerpt,
#: nothing that resolves to media — so granting them later cannot make it
#: answerable: there is nothing in it to answer. Revocation still applies to
#: the future only; what it costs is that the past cannot be recovered, which
#: is the right way round for a withdrawal of consent.
PENDING = "pending"

#: How far back a grant reaches, by default: one hour, the same number the
#: suggestion policy uses for how long a draft stays approvable
#: (:mod:`twalk_sdk.policy`), and for the same judgement — long enough that
#: the owner gets to the screen after a meeting, short enough that granting a
#: contact today does not answer what they wrote yesterday.
#:
#: The reach must stay **at or under the bus's duplicate window** (a day, ADR
#: 0037), and that is what makes "revoke, grant again, and the same message is
#: not answered twice" a property of the design rather than a thing this SDK
#: has to remember: a second replay of the same trigger recomputes the same
#: suggestion id — ``sha256(persona:trigger:attempt)``, the contract's natural
#: key — and the bus absorbs it. Beyond the duplicate window the id would land
#: a second time; inside the reach it cannot, because the reach is at or under
#: that window and a decision older than the reach is not acted on at all.
DEFAULT_GRANT_REACH_SECONDS = 3600


@dataclass(frozen=True)
class Grant:
    """A grant the owner has just made, as a persona reads it off the bus.

    Only the three things a replay needs: who it is about, what perimeter it
    covers (connections since #270, networks for a decision older than it), and
    when it was taken. Not the old state, not the actor, not the
    subject's kind — a ``Grant`` exists only because :func:`grant_in` already
    checked those, and a type that carried them would invite a second check
    somewhere else.
    """

    contact: str
    connections: FrozenSet[str]
    networks: FrozenSet[str]
    occurred_at: datetime

    def covers(self, event: Mapping[str, Any]) -> bool:
        """Whether this grant's perimeter covers the connection an event
        arrived on.

        A decision is scoped (ADR 0033): the owner grants a contact *on the
        connections they named*, and a grant made on WhatsApp must not answer
        that person's mail. The connections are the perimeter since #270 and
        the networks are what a deployment older than that recorded, so both
        are read, connections first — on a deployment whose connections are
        named after their networks the two are the same strings anyway.
        """
        perimeter = self.connections or self.networks
        if not perimeter:
            # A decision naming no perimeter is one the Gateway does not
            # produce. Refusing it is the consent gate's own default: when the
            # scope cannot be read, nothing is processed.
            return False
        connection = event.get("connection")
        network = event.get("network")
        if isinstance(connection, str) and connection in self.connections:
            return True
        return isinstance(network, str) and network in self.networks


@dataclass(frozen=True)
class GrantReach:
    """How far into the past a grant reaches. Pure, so it is tested without a
    bus."""

    seconds: int = DEFAULT_GRANT_REACH_SECONDS

    def __post_init__(self) -> None:
        if isinstance(self.seconds, bool) or not isinstance(self.seconds, int):
            raise ValueError(
                "a grant's reach is a whole number of seconds, got "
                f"{self.seconds!r}"
            )
        if self.seconds < 0:
            raise ValueError(
                "a grant's reach cannot be negative; zero is how an operator "
                f"says a grant reaches nothing at all (got {self.seconds})"
            )
        if self.seconds > DUPLICATE_WINDOW_SECONDS:
            raise ValueError(
                "a grant's reach must stay within the bus's duplicate window "
                f"of {DUPLICATE_WINDOW_SECONDS} seconds (ADR 0037): beyond it "
                "the same message can be answered twice, because the "
                "suggestion's deterministic id is no longer deduplicated "
                f"(got {self.seconds})"
            )

    def reaches(self, event: Mapping[str, Any], grant: Grant) -> bool:
        """Whether ``grant`` reaches ``event``: the one question a replay asks.

        Five clauses, and only the first is the gate's own refusal restated;
        the rest are this question's, and each is narrower than it looks:

        * the event is still ``pending``. Not "is not granted": a message the
          gate refused because its sender was ``revoked`` has no content to
          answer, and one already ``granted`` was answered live.
        * the event's subject *is* the contact the decision names. The two are
          the same string by construction — a decision names its subject with
          the identifier the message arrived under — so this is an equality and
          not a resolution.
        * the grant's perimeter covers the connection the message arrived on.
        * the message arrived **before** the grant and no longer ago than the
          reach. Before, because a message that arrived after it was already
          labelled ``granted`` and needs no replay; and the distance is
          measured from the *grant*, not from now, so a decision that took a
          while to reach this persona still answers the messages it was made
          about.
        """
        if consent_of(event) != PENDING:
            return False
        if event.get("subject") != grant.contact:
            return False
        if not grant.covers(event):
            return False
        arrived_at = _instant(event.get("time"))
        if arrived_at is None:
            # An event whose own time cannot be read: the reach has no distance
            # to measure, so it does not reach. The gate's default again.
            return False
        distance = (grant.occurred_at - arrived_at).total_seconds()
        return 0 <= distance <= self.seconds

    def is_fresh(self, grant: Grant, now: datetime) -> bool:
        """Whether a grant is recent enough to be acted on at all.

        A persona that was down for a day comes back to decisions it has never
        seen, and replaying one of those would answer messages the owner
        granted for yesterday — which is exactly what the reach exists to
        refuse. The same number bounds both distances, because they are the
        same judgement about how long a message stays worth answering.
        """
        return 0 <= (now - grant.occurred_at).total_seconds() <= self.seconds


def grant_in(event: Mapping[str, Any]) -> Optional[Grant]:
    """The grant a ``consent.state.changed`` event carries, or ``None``.

    ``None`` for everything that is not one: another event type, a decision
    about a network or a persona rather than a contact, a revocation, a
    decision whose ``occurred_at`` cannot be read. A persona follows the
    decision stream to learn about grants and must be incurious about the
    rest — a reader that tried to interpret the others would be a second
    consent engine, and there is exactly one (ADR 0006).
    """
    if event.get("type") != CONSENT_CHANGED_TYPE:
        return None
    data = event.get("data")
    if not isinstance(data, Mapping):
        return None
    subject = data.get("subject")
    if not isinstance(subject, Mapping) or subject.get("type") != "contact":
        return None
    contact = subject.get("id")
    if not isinstance(contact, str) or not contact:
        return None
    if data.get("new_state") != GRANTED:
        return None
    occurred_at = _instant(data.get("occurred_at"))
    if occurred_at is None:
        return None
    scope = data.get("scope") if isinstance(data.get("scope"), Mapping) else {}
    return Grant(
        contact=contact,
        connections=_names(scope.get("connections")),
        networks=_names(scope.get("networks")),
        occurred_at=occurred_at,
    )


def _names(value: Any) -> FrozenSet[str]:
    """The strings in a scope's list, and nothing else that was in it."""
    if not isinstance(value, (list, tuple)):
        return frozenset()
    return frozenset(name for name in value if isinstance(name, str) and name)


def _instant(value: Any) -> Optional[datetime]:
    """A contract ``date-time`` as an instant, or ``None`` when it is not one.

    Read with :meth:`datetime.fromisoformat`, which accepts every RFC 3339
    spelling the contract allows (including the trailing ``Z``, since 3.11) and
    some ISO 8601 ones it does not — a laxity that costs nothing here, because
    the alternative to reading an odd spelling is refusing a decision the owner
    really took.

    Timezone-aware always: an instant without an offset cannot be compared with
    one that has it, and the contract's ``date-time`` always carries one.
    """
    if not isinstance(value, str):
        return None
    try:
        moment = datetime.fromisoformat(value)
    except ValueError:
        return None
    return moment if moment.tzinfo is not None else None
