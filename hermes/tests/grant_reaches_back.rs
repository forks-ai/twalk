//! A grant in the past tense (issue #364), at the persona's process boundary:
//! the real `assistant` container, the real bus, and the two events the owner
//! produced on the reference deployment on 2026-09-24 — a message that
//! arrived while its sender was undecided, and a grant thirty-nine seconds
//! later. Nothing happened then, and nothing was going to.
//!
//! What is asserted here is the whole of it, from outside the process: that
//! the pending message produces nothing at the time, that the grant makes the
//! persona wake on *that* message, that what comes out is an ordinary
//! suggestion keyed on the trigger the owner watched arrive, and that
//! granting twice does not draft twice.
//!
//! The arithmetic — which message a grant reaches, how far back, whose — is
//! unit-tested in `sdk/python/tests/test_grant_reach.py`, because a reach
//! that is "the operator's to set" has to be both.

mod harness;

use anyhow::{Context, Result};
use harness::{
    sha256_hex, traceparent_for, validate_against_contract, PersonaRun, CONSENT_CHANGED_TYPE,
    INBOUND_TYPE, SUGGEST_TYPE,
};
use serde_json::{json, Value};

/// A contact nobody has decided about, spelled the way a bridged sender is.
const SENDER: &str = "@whatsapp_33698765432:example.com";

/// Another one, so that a grant's reach can be shown to stop at the person it
/// is about.
const SOMEBODY_ELSE: &str = "@whatsapp_33611112222:example.com";

/// This instant, in seconds since the epoch. Read **once per test** and every
/// fixture's instant derived from it: read twice, two instants meant to differ
/// by a second can land on the same one — which is how the first version of
/// this suite published its second grant with the first grant's id and asserted
/// nothing at all.
fn now_epoch() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("the clock is after 1970")
        .as_secs() as i64
}

/// An instant as the contract's `date-time`. Hand-rolled because this crate's
/// tests have no date library: the Gateway's suites have `time` as a
/// dev-dependency and this one does not, and one fixture's calendar arithmetic
/// is not a reason to add it.
fn rfc3339(at: i64) -> String {
    let days = at.div_euclid(86_400);
    let seconds = at.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        seconds / 3600,
        (seconds % 3600) / 60,
        seconds % 60
    )
}

/// Howard Hinnant's `civil_from_days`, the standard algorithm: days since the
/// epoch to a calendar date, so a test can date a fixture without a crate.
///
/// Its inverse, `days_from_civil`, is in `suggestion.rs` and was written there
/// for the same reason — this crate's tests read and write the one shape the
/// contract's producers use and take no date dependency to do it. The pair
/// belongs in one place; whoever needs a third should move both into
/// `harness/`.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// One `inbound.message.received` whose sender nobody has decided about: the
/// full shape a `pending` message has (ADR 0012 reduces a *revoked* sender's
/// publication and leaves this one alone), dated `arrived_seconds_ago`.
fn pending_message(
    run: &PersonaRun,
    sender: &str,
    marker: &str,
    body: &str,
    arrived_at: i64,
) -> Result<Value> {
    let id = sha256_hex(&format!("{}:{marker}", run.prefix));
    let event = json!({
        "specversion": "1.0",
        "id": id,
        "source": format!("matrix://matrix.example.com/!{}:example.com", &id[..18]),
        "type": INBOUND_TYPE,
        "time": rfc3339(arrived_at),
        "subject": sender,
        "datacontenttype": "application/json",
        "dataschema": "https://schemas.twalk.dev/cloudevents/v1/inbound.message.received.schema.json",
        "traceparent": traceparent_for(&id),
        "network": "whatsapp",
        "connection": "whatsapp",
        "consent": "pending",
        "data": {
            "body": format!("{body} [{marker}]"),
            "format": "text/plain",
            "reply_to": null,
            "attachments": [],
            "contact": { "display_name": "Aicha Benali" }
        }
    });
    validate_against_contract(&event, "inbound.message.received")?;
    Ok(event)
}

/// The `consent.state.changed` the Companion Gateway publishes when the owner
/// grants a contact, with the contract's own deterministic id: the sha256 of
/// `subject.type:subject.id:new_state:<connections>:occurred_at`. Computed
/// rather than invented, because that id is the `Nats-Msg-Id` and two
/// decisions that differ only in the instant must not collide.
fn grant(contact: &str, taken_at: i64) -> Result<Value> {
    let occurred_at = rfc3339(taken_at);
    let id = sha256_hex(&format!("contact:{contact}:granted:whatsapp:{occurred_at}"));
    let event = json!({
        "specversion": "1.0",
        "id": id,
        "source": "gateway://example.com/consent",
        "type": CONSENT_CHANGED_TYPE,
        "time": occurred_at,
        "subject": contact,
        "datacontenttype": "application/json",
        "dataschema": "https://schemas.twalk.dev/cloudevents/v1/consent.state.changed.schema.json",
        "network": "whatsapp",
        "data": {
            "subject": { "type": "contact", "id": contact },
            "old_state": "unset",
            "new_state": "granted",
            "scope": { "connections": ["whatsapp"], "networks": ["whatsapp"] },
            "occurred_at": occurred_at,
            "actor": "@michel:example.com"
        }
    });
    validate_against_contract(&event, "consent.state.changed")?;
    Ok(event)
}

/// The same shape, revoking. A persona does nothing with it — a revocation
/// reaches no message, and a revoked sender's message was published without
/// content — and it is here because the criterion is about the *cycle*: revoke,
/// grant again, and the message is still answered once.
fn revoke(contact: &str, taken_at: i64) -> Result<Value> {
    let occurred_at = rfc3339(taken_at);
    let id = sha256_hex(&format!("contact:{contact}:revoked:whatsapp:{occurred_at}"));
    let mut event = grant(contact, taken_at)?;
    event["id"] = json!(id);
    event["data"]["old_state"] = json!("granted");
    event["data"]["new_state"] = json!("revoked");
    validate_against_contract(&event, "consent.state.changed")?;
    Ok(event)
}

fn event_id(event: &Value) -> String {
    event["id"].as_str().expect("a string id").to_owned()
}

#[tokio::test]
async fn the_message_that_prompted_a_grant_is_answered_once_and_keeps_its_own_arrival() -> Result<()>
{
    const REPLY: &str = "Oui, 20h me va.";
    let run = PersonaRun::start("reach", REPLY).await?;
    let marker = format!("reach-{}", run.prefix);
    // The deployment's own timeline, from one reading of the clock: the message
    // at T, the grant thirty-nine seconds later, and — for step 6 — a
    // revocation and a second grant at instants that cannot collide with it.
    let now = now_epoch();

    // 1. The message arrives while its sender is undecided. The persona is
    //    delivered it and refuses it, which is ADR 0012's rule and is not
    //    what this ticket changes.
    let trigger = pending_message(&run, SENDER, &marker, "On décale à 20h ?", now - 39)?;
    let trigger_id = event_id(&trigger);
    run.publish_inbound(&trigger).await?;
    run.wait_logged("dropped an event whose consent is not granted", 1)
        .await?;
    assert!(
        run.published(SUGGEST_TYPE).await?.is_empty(),
        "a pending message must produce no suggestion at the time it arrives"
    );
    assert!(
        run.llm_requests_mentioning(&marker).is_empty(),
        "and no completion: the gate runs before the model is touched"
    );

    // 2. The owner grants the sender. Thirty-nine seconds, the deployment's
    //    own timeline.
    let decision = grant(SENDER, now)?;
    run.bus
        .publish_event(&run.subject(CONSENT_CHANGED_TYPE), &decision)
        .await?;

    // 3. The persona wakes on the message that was waiting, and what comes
    //    out is an ordinary suggestion: the contract's deterministic id on
    //    the first attempt, keyed on the trigger the owner watched arrive.
    let suggest = run.wait_for(SUGGEST_TYPE, &trigger_id).await?;
    validate_against_contract(&suggest.payload, "persona.suggest.produced")?;
    let event = &suggest.payload;
    assert_eq!(
        event["id"].as_str(),
        Some(sha256_hex(&format!("assistant:{trigger_id}:1")).as_str()),
        "a replayed message is the same message answered late: same trigger, \
         first attempt, the id the live path would have produced"
    );
    assert_eq!(event["data"]["attempt"], json!(1));
    assert_eq!(
        event["data"]["trigger"]["event_id"].as_str(),
        Some(trigger_id.as_str())
    );

    // 4. It is the same message, not a new one: nothing was re-published, so
    //    the trigger on the stream still carries its own arrival time and its
    //    own id. The journal shows one message, answered late.
    let inbound = run.published(INBOUND_TYPE).await?;
    assert_eq!(
        inbound.len(),
        1,
        "the replay must not put a second copy of the message on the bus"
    );
    assert_eq!(
        inbound[0].payload["time"], trigger["time"],
        "the message keeps the instant it arrived at"
    );
    assert_eq!(inbound[0].payload["id"], trigger["id"]);
    assert_eq!(
        inbound[0].payload["consent"],
        json!("pending"),
        "and its label: the grant reaches the message, it does not re-stamp it"
    );

    // 5. The persona did read the words: the reply is a draft of this
    //    message and not of an empty one.
    assert_eq!(
        run.llm_requests_mentioning(&marker).len(),
        1,
        "exactly one completion, for the message the grant reached"
    );

    // 6. Revoke, and grant again: still one draft. The second grant is a
    //    second event — a different instant, so a different id under the
    //    contract's own recipe, so the bus delivers it rather than absorbing
    //    it — and its replay reaches the same message again, recomputes the
    //    same suggestion id, and *that* is what the bus absorbs. Nothing has to
    //    remember which messages have been answered.
    //
    //    The instants are made to differ on purpose: keyed on a second, two
    //    decisions taken inside one would share an id, and this assertion would
    //    pass by never having happened.
    let withdrawn = revoke(SENDER, now - 2)?;
    let again = grant(SENDER, now - 1)?;
    assert_ne!(
        event_id(&again),
        event_id(&decision),
        "the second grant has to be a second event, or nothing is under test"
    );
    for event in [&withdrawn, &again] {
        run.bus
            .publish_event(&run.subject(CONSENT_CHANGED_TYPE), event)
            .await?;
    }
    // The second replay ran: the line is one per message a grant reaches, so
    // it is there twice once the second one has been through.
    run.wait_logged("a grant reaches a message that was waiting for it", 2)
        .await?;
    let suggestions = run.published(SUGGEST_TYPE).await?;
    assert_eq!(
        suggestions.len(),
        1,
        "one message, one draft, however often the owner grants: got {:#?}",
        suggestions
            .iter()
            .map(|message| &message.payload)
            .collect::<Vec<_>>()
    );

    run.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn a_grant_reaches_neither_an_older_message_nor_somebody_elses() -> Result<()> {
    const REPLY: &str = "Bien reçu.";
    let run = PersonaRun::start("reach-bounds", REPLY).await?;
    let marker = format!("bounds-{}", run.prefix);
    let now = now_epoch();

    // Two messages the grant below must not answer, and one it must.
    let old = pending_message(
        &run,
        SENDER,
        &format!("{marker}-old"),
        "Et pour mardi ?",
        7_200,
    )?;
    let other = pending_message(
        &run,
        SOMEBODY_ELSE,
        &format!("{marker}-other"),
        "Tu es là ?",
        now - 60,
    )?;
    let reached =
        pending_message(&run, SENDER, &format!("{marker}-now"), "On décale ?", now - 60)?;
    for event in [&old, &other, &reached] {
        run.publish_inbound(event).await?;
    }
    run.wait_logged("dropped an event whose consent is not granted", 3)
        .await?;

    let decision = grant(SENDER, now)?;
    run.bus
        .publish_event(&run.subject(CONSENT_CHANGED_TYPE), &decision)
        .await?;
    let suggest = run.wait_for(SUGGEST_TYPE, &event_id(&reached)).await?;
    validate_against_contract(&suggest.payload, "persona.suggest.produced")?;

    // The replay says what it did, in one line, and the line is the count:
    // one message reached of the three it read back.
    run.wait_logged("a grant reached 1 of the 3 messages read back", 1)
        .await?;
    let suggestions = run.published(SUGGEST_TYPE).await?;
    assert_eq!(
        suggestions.len(),
        1,
        "a message two hours old is outside the hour a grant reaches, and \
         another contact's message is outside the grant altogether: got {:#?}",
        suggestions
            .iter()
            .map(|message| &message.payload)
            .collect::<Vec<_>>()
    );
    assert_eq!(
        suggestions[0].payload["subject"].as_str(),
        Some(event_id(&reached).as_str())
    );
    assert!(
        run.llm_requests_mentioning(&format!("{marker}-old"))
            .is_empty(),
        "a message outside the reach costs no completion"
    );
    assert!(
        run.llm_requests_mentioning(&format!("{marker}-other"))
            .is_empty(),
        "and neither does somebody else's"
    );

    run.shutdown().await?;
    Ok(())
}
