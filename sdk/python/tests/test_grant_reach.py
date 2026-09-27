"""A grant in the past tense (issue #364).

The gate's mirror: the envelope's label is frozen at arrival and stays
refused, and what reaches a message the owner granted for afterwards is the
decision event itself. These tests pin the two pure questions that decide it
— *is this a grant about a contact?* and *does it reach this message?* — case
by case, including the ones a running system rarely produces.

The end-to-end proof is elsewhere, because it cannot be written here: the
persona process reads the decision stream, re-reads the messages the grant
reaches and publishes ordinary suggestions for them, which is
`hermes/tests/grant_reaches_back.rs` against a real bus and a real container.

The timeline in the ticket is the case that matters most, and it is a test
below verbatim: a mail at 17:12:10Z, a grant at 17:12:49Z, thirty-nine
seconds, nothing happened.
"""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from fixtures import fixture
from twalk_sdk.config import Config, ConfigError
from twalk_sdk.consent import (
    DEFAULT_GRANT_REACH_SECONDS,
    DUPLICATE_WINDOW_SECONDS,
    Grant,
    GrantReach,
    grant_in,
)

CONTACT = "mailto:michel.perso@example.org"
CONNECTION = "mail-linagora"


def decision(**changes: object) -> dict:
    """The contract's own consent fixture, made to be about a contact.

    The fixture is a decision about a persona — the SDK's other reader cares
    about those — so the subject is rewritten the way
    `clerk/tests/harness/events.rs` rewrites it, and nothing else is, so that
    what is under test is this module and not a hand-written envelope.
    """
    event = fixture("consent.state.changed")
    event["subject"] = CONTACT
    event["data"]["subject"] = {"type": "contact", "id": CONTACT}
    event["data"]["scope"] = {"connections": [CONNECTION], "networks": ["email"]}
    event["data"]["occurred_at"] = "2026-09-24T17:12:49Z"
    for key, value in changes.items():
        event["data"][key] = value
    return event


def message(**changes: object) -> dict:
    """One inbound message, pending, from that contact, on that connection."""
    event = fixture("inbound.message.received")
    event["consent"] = "pending"
    event["subject"] = CONTACT
    event["connection"] = CONNECTION
    event["network"] = "email"
    event["time"] = "2026-09-24T17:12:10Z"
    event.update(changes)
    return event


class GrantInTest(unittest.TestCase):
    def test_a_grant_about_a_contact_is_read_whole(self) -> None:
        grant = grant_in(decision())
        self.assertIsNotNone(grant)
        assert grant is not None
        self.assertEqual(grant.contact, CONTACT)
        self.assertEqual(grant.connections, frozenset({CONNECTION}))
        self.assertEqual(grant.networks, frozenset({"email"}))
        self.assertEqual(
            grant.occurred_at,
            datetime(2026, 9, 24, 17, 12, 49, tzinfo=timezone.utc),
        )

    def test_a_decision_about_a_persona_is_not_a_grant_this_reads(self) -> None:
        # The contract's fixture as it ships: activation, which the runtime
        # reads and a replay has no business interpreting.
        self.assertIsNone(grant_in(fixture("consent.state.changed")))

    def test_a_decision_about_a_network_is_not_one_either(self) -> None:
        event = decision()
        event["data"]["subject"] = {"type": "network", "id": "email"}
        self.assertIsNone(grant_in(event))

    def test_a_revocation_reaches_nothing(self) -> None:
        self.assertIsNone(grant_in(decision(new_state="revoked")))

    def test_a_decision_back_to_unset_reaches_nothing(self) -> None:
        self.assertIsNone(grant_in(decision(new_state="unset")))

    def test_an_event_of_another_type_is_not_read_at_all(self) -> None:
        self.assertIsNone(grant_in(message()))

    def test_a_decision_whose_instant_cannot_be_read_is_refused(self) -> None:
        self.assertIsNone(grant_in(decision(occurred_at="last Tuesday")))

    def test_a_decision_whose_instant_carries_no_offset_is_refused(self) -> None:
        # Comparing a naive instant with an aware one raises; refusing it is
        # the gate's own default, and the contract always carries the offset.
        self.assertIsNone(grant_in(decision(occurred_at="2026-09-24T17:12:49")))

    def test_a_scope_of_things_that_are_not_names_keeps_the_names(self) -> None:
        grant = grant_in(decision(scope={"connections": [CONNECTION, 7, "", None]}))
        assert grant is not None
        self.assertEqual(grant.connections, frozenset({CONNECTION}))


class ReachesTest(unittest.TestCase):
    def setUp(self) -> None:
        self.reach = GrantReach()
        read = grant_in(decision())
        assert read is not None
        self.grant = read

    def test_the_timeline_that_opened_the_ticket(self) -> None:
        # 17:12:10Z the mail, 17:12:49Z the grant. Thirty-nine seconds.
        self.assertTrue(self.reach.reaches(message(), self.grant))

    def test_a_message_that_was_already_granted_needs_no_replay(self) -> None:
        self.assertFalse(self.reach.reaches(message(consent="granted"), self.grant))

    def test_a_revoked_senders_message_has_nothing_to_answer(self) -> None:
        # ADR 0012 published it without a body. Granting them later cannot
        # make it answerable, and revocation applies to the future only.
        self.assertFalse(self.reach.reaches(message(consent="revoked"), self.grant))

    def test_a_message_from_somebody_else_is_not_reached(self) -> None:
        other = message(subject="mailto:someone.else@example.org")
        self.assertFalse(self.reach.reaches(other, self.grant))

    def test_a_message_on_a_connection_outside_the_grant_is_not_reached(self) -> None:
        # The grant was made on the mail connection; the same person writing
        # on WhatsApp is a decision the owner has not taken (ADR 0033).
        elsewhere = message(connection="whatsapp", network="whatsapp")
        self.assertFalse(self.reach.reaches(elsewhere, self.grant))

    def test_a_grant_from_before_connections_is_honoured_by_network(self) -> None:
        # A decision recorded before #270 named networks and no connections.
        older = grant_in(decision(scope={"networks": ["email"]}))
        assert older is not None
        self.assertTrue(self.reach.reaches(message(), older))

    def test_a_grant_naming_no_perimeter_reaches_nothing(self) -> None:
        unscoped = grant_in(decision(scope={}))
        assert unscoped is not None
        self.assertFalse(self.reach.reaches(message(), unscoped))

    def test_a_message_that_arrived_after_the_grant_needs_no_replay(self) -> None:
        # It was labelled `granted` on arrival, or it was not and that is a
        # different defect. Either way the reach does not look forwards.
        later = message(time="2026-09-24T17:13:00Z")
        self.assertFalse(self.reach.reaches(later, self.grant))

    def test_a_message_older_than_the_reach_is_left_alone(self) -> None:
        old = message(time="2026-09-24T16:00:00Z")
        self.assertFalse(self.reach.reaches(old, self.grant))

    def test_the_edge_of_the_reach_is_inside_it(self) -> None:
        edge = message(
            time=(
                self.grant.occurred_at - timedelta(seconds=DEFAULT_GRANT_REACH_SECONDS)
            ).strftime("%Y-%m-%dT%H:%M:%SZ")
        )
        self.assertTrue(self.reach.reaches(edge, self.grant))

    def test_a_message_whose_own_time_cannot_be_read_is_not_reached(self) -> None:
        self.assertFalse(self.reach.reaches(message(time="soon"), self.grant))

    def test_a_message_with_no_consent_extension_at_all_is_not_reached(self) -> None:
        # The user's own messages carry none (ADR 0018) and are not triggers.
        event = message()
        del event["consent"]
        self.assertFalse(self.reach.reaches(event, self.grant))


class FreshnessTest(unittest.TestCase):
    def setUp(self) -> None:
        self.reach = GrantReach()
        self.grant = Grant(
            contact=CONTACT,
            connections=frozenset({CONNECTION}),
            networks=frozenset({"email"}),
            occurred_at=datetime(2026, 9, 24, 17, 12, 49, tzinfo=timezone.utc),
        )

    def test_a_grant_just_taken_is_acted_on(self) -> None:
        self.assertTrue(
            self.reach.is_fresh(self.grant, self.grant.occurred_at + timedelta(seconds=5))
        )

    def test_a_grant_older_than_the_reach_answers_nothing(self) -> None:
        # A persona that was down for a day comes back to decisions it has
        # never seen; replaying one would answer what was granted yesterday.
        self.assertFalse(
            self.reach.is_fresh(self.grant, self.grant.occurred_at + timedelta(days=1))
        )

    def test_a_grant_from_the_future_is_not_acted_on(self) -> None:
        self.assertFalse(
            self.reach.is_fresh(self.grant, self.grant.occurred_at - timedelta(seconds=1))
        )


class ReachConfigurationTest(unittest.TestCase):
    def test_the_default_is_the_suggestion_windows_own_hour(self) -> None:
        self.assertEqual(GrantReach().seconds, 3600)
        self.assertEqual(DEFAULT_GRANT_REACH_SECONDS, 3600)

    def test_zero_is_how_an_operator_says_a_grant_reaches_nothing(self) -> None:
        self.assertEqual(GrantReach(seconds=0).seconds, 0)

    def test_a_negative_reach_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            GrantReach(seconds=-1)

    def test_a_reach_past_the_buses_duplicate_window_is_refused(self) -> None:
        # Past it the same message can be answered twice: the suggestion's
        # deterministic id is no longer deduplicated (ADR 0037).
        with self.assertRaises(ValueError) as refused:
            GrantReach(seconds=DUPLICATE_WINDOW_SECONDS + 1)
        self.assertIn("duplicate window", str(refused.exception))

    def test_the_whole_duplicate_window_is_allowed(self) -> None:
        self.assertEqual(
            GrantReach(seconds=DUPLICATE_WINDOW_SECONDS).seconds,
            DUPLICATE_WINDOW_SECONDS,
        )

    def test_a_reach_that_is_not_a_whole_number_of_seconds_is_refused(self) -> None:
        for value in (3600.0, "3600", True, None):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    GrantReach(seconds=value)  # type: ignore[arg-type]


def environment(**overrides: str) -> dict:
    """The four variables a persona needs, plus whatever a test says."""
    env = {
        "TWALK_PERSONA_ID": "assistant",
        "TWALK_HERMES_DOMAIN": "twalk.example.com",
        "TWALK_LLM_BASE_URL": "http://llm:8080/v1",
        "TWALK_LLM_MODEL": "qwen2.5-32b-instruct",
    }
    env.update(overrides)
    return env


class ConfiguredReachTest(unittest.TestCase):
    def test_the_reach_defaults_to_an_hour(self) -> None:
        self.assertEqual(
            Config.from_env(environment()).reach.seconds,
            DEFAULT_GRANT_REACH_SECONDS,
        )

    def test_the_operator_sets_the_reach(self) -> None:
        config = Config.from_env(environment(TWALK_GRANT_REACH_SECONDS="900"))
        self.assertEqual(config.reach.seconds, 900)

    def test_the_operator_can_turn_it_off(self) -> None:
        # Zero is a supported answer and not a refusal: a deployment that
        # wants a grant to mean nothing in the past tense says so.
        config = Config.from_env(environment(TWALK_GRANT_REACH_SECONDS="0"))
        self.assertEqual(config.reach.seconds, 0)

    def test_an_empty_value_is_the_default_rather_than_a_refusal(self) -> None:
        # Compose passes an unset variable through as an empty string.
        config = Config.from_env(environment(TWALK_GRANT_REACH_SECONDS="  "))
        self.assertEqual(config.reach.seconds, DEFAULT_GRANT_REACH_SECONDS)

    def test_a_reach_that_is_not_one_refuses_to_start_the_persona(self) -> None:
        for refused in ("an hour", "-60", "3600.5", str(DUPLICATE_WINDOW_SECONDS + 1)):
            with self.subTest(value=refused):
                with self.assertRaises(ConfigError) as refusal:
                    Config.from_env(environment(TWALK_GRANT_REACH_SECONDS=refused))
                self.assertIn("TWALK_GRANT_REACH_SECONDS", str(refusal.exception))

    def test_the_decisions_consumer_is_named_after_the_persona(self) -> None:
        # A second consumer, so that a decision that fails to replay is
        # retried without spending a message's deliveries.
        config = Config.from_env(environment())
        self.assertEqual(config.decisions_durable_name, "persona-assistant-decisions")
        self.assertNotEqual(config.decisions_durable_name, config.durable_name)


if __name__ == "__main__":
    unittest.main()
