// matrix-sdk crypto futures overflow the default trait-solver depth when
// spawned (harness::CryptoBot); matrix-sdk itself sets the same limit.
#![recursion_limit = "256"]

//! Issue #123 / ADR 0025 / ADR 0034: the outbound path has an identity, and it
//! is the user's own.
//!
//! A mautrix bridge relays to its network only what the **logged-in user's own
//! Matrix account** sends. The Sensor had nothing that could be that account,
//! so an approved reply went out as `@sensor:`, Synapse returned an event id,
//! and the bridge logged nothing at all — not a refusal, not a warning. The
//! outbound half of this product had never worked on a live deployment while
//! every component reported itself healthy. And the one identity a bridge would
//! have relayed was not even in the room: on the reference deployment the
//! owner's account showed `invite: 33, join: 0`, because the whole premise of
//! Twalk is that the user does not run a Matrix client.
//!
//! So the Sensor gains a **second, write-only Matrix client**: a device of the
//! owner's own account, beside its own `@sensor:` client. One identity
//! observes, one identity acts.
//!
//! What this file asserts, from the homeserver and the bus and never from
//! inside the Sensor:
//!
//! - the owner's device **joins** a portal room a configured bridge bot invited
//!   it to, so the invitation stops being the dead end #123 found;
//! - and joins **nothing else** — a room a stranger built, wrote a WhatsApp
//!   `m.bridge` marker into and invited the owner to is left at `invite`,
//!   because everything in an invitation except the inviter is chosen by
//!   whoever sent it, and this device posts messages;
//! - an approved reply is posted **by the owner's account**, not by `@sensor:`,
//!   and the Sensor says on the bus that it reached the contact (#216);
//! - in an **encrypted** portal — which every real portal is — the reply is
//!   Megolm-encrypted by a device that runs no message sync, and another device
//!   entirely (the Sensor's own) decrypts it, which is the only way to prove the
//!   room key was really shared;
//! - with **no** owner device the behaviour is unchanged — `@sensor:` posts —
//!   and the Sensor now says the reply reached nobody instead of calling it
//!   sent, which is #216's whole complaint;
//! - and a token for **another account** is refused at startup, rather than
//!   being found later by a contact receiving a reply from a stranger.
//!
//! Isolation is the suite's: `TWALK_TEST_STACK`, `TWALK_TEST_SYNAPSE_PORT` and
//! `TWALK_TEST_NATS_PORT` move the whole stack aside for a parallel worktree
//! (`sensor/tests/harness/mod.rs`).

mod harness;

use std::time::Duration;

use anyhow::{Context, Result};
use harness::crypto::{make_encrypted_whatsapp_portal, CryptoBot};
use harness::{
    contract_fixture, ensure_stack, fresh_state_dir, make_whatsapp_portal, poll_until,
    sensor_env_with, validate_against_contract, wait_up_to, Bot, Bus, SensorProc, StoredMessage,
    SENSOR_USER_ID,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const STREAM: &str = "twalk";
const REPLY_APPROVED_SUBJECT: &str = "twalk.persona.reply.approved.v1";
const POSTED_SUBJECT: &str = "twalk.persona.reply.approved.v1.posted";
const OUTBOUND_SUBJECT: &str = "twalk.outbound.message.sent.v1";

/// The owner: unlike every other suite, a **real account** on the test stack.
/// The identity Twalk acts through has to log in, hold a device, and join
/// rooms, so it cannot be the never-resolved `@michel:test.twalk` the
/// publication suites use.
const OWNER: &str = "@owner:test.twalk";

/// The bridge, playing mautrix's own bot: the `sender_localpart` that creates
/// portals and invites the user into them. It is the **only** authenticated
/// fact in an invitation, so it is the only thing the join policy reads.
const BRIDGE_BOT: &str = "@whatsappbot:test.twalk";

/// A perfectly ordinary account that is not a bridge: the attacker in the
/// second half of the first test, and a reminder that a Matrix ID in an
/// invitation costs nothing to obtain.
const STRANGER: &str = "@bot_beta:test.twalk";

/// A fresh CloudEvents id per published event: the bus persists across runs, so
/// reusing the fixture id would make a second run's approval a duplicate the
/// stream silently drops.
fn unique_event_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let mut hasher = Sha256::new();
    hasher.update(nanos.to_string().as_bytes());
    hasher.update(
        COUNTER
            .fetch_add(1, Ordering::Relaxed)
            .to_string()
            .as_bytes(),
    );
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The contract fixture with its placeholders patched to real test values,
/// re-validated so what is published stays a contract event.
fn approved_reply(room_id: &str, body: &str) -> Result<Value> {
    let mut event = contract_fixture("persona.reply.approved")?;
    event["id"] = json!(unique_event_id());
    event["data"]["target"]["room_id"] = json!(room_id);
    event["data"]["target"]
        .as_object_mut()
        .unwrap()
        .remove("reply_to_event_id");
    event["data"]["final"]["body"] = json!(body);
    event["data"]["approved_by"] = json!(OWNER);
    validate_against_contract(&event, "persona.reply.approved")?;
    Ok(event)
}

/// The environment of a Sensor that knows who its operator is, which accounts
/// are the bridges' bots, and — unless `owner_device` is `None` — holds a
/// device of the operator's own account.
fn owner_device_env(test_name: &str, owner_device: Option<(&str, &str)>) -> Vec<(String, String)> {
    let state_dir = fresh_state_dir(test_name);
    let mut overrides = vec![
        ("SENSOR_OWNER", OWNER.to_owned()),
        ("SENSOR_ALLOWED_INVITERS", BRIDGE_BOT.to_owned()),
        ("SENSOR_BRIDGE_BOTS", BRIDGE_BOT.to_owned()),
        ("SENSOR_STATE_DIR", state_dir.to_string_lossy().into_owned()),
        ("SENSOR_SEND_RETRY_BASE_MS", "100".to_owned()),
        ("SENSOR_SEND_RETRY_MAX_ATTEMPTS", "3".to_owned()),
    ];
    if let Some((access_token, device_id)) = owner_device {
        overrides.push(("SENSOR_OWNER_DEVICE_ACCESS_TOKEN", access_token.to_owned()));
        overrides.push(("SENSOR_OWNER_DEVICE_ID", device_id.to_owned()));
    }
    let overrides: Vec<(&str, &str)> = overrides
        .iter()
        .map(|(key, value)| (*key, value.as_str()))
        .collect();
    sensor_env_with(&overrides)
}

/// Waits for the Sensor's report of what one posted reply reached.
async fn posted_report(bus: &Bus, approval_id: &str) -> Result<StoredMessage> {
    poll_until(
        || async {
            bus.fetch_all_with_headers(STREAM, POSTED_SUBJECT)
                .await
                .ok()?
                .into_iter()
                .find(|m| m.payload["id"].as_str() == Some(approval_id))
        },
        "the Sensor's report of what the posted reply reached",
    )
    .await
}

/// The first `m.room.message` (or `m.room.encrypted` event) a given account sent
/// in a room.
async fn event_from(bot: &Bot, room_id: &str, sender: &str, description: &str) -> Result<Value> {
    bot.wait_for_event(
        room_id,
        |event| {
            event.get("sender").and_then(Value::as_str) == Some(sender)
                && matches!(
                    event.get("type").and_then(Value::as_str),
                    Some("m.room.message") | Some("m.room.encrypted")
                )
        },
        description,
    )
    .await
}

/// The owner's device joins the portals of configured bridges, and refuses
/// every other invitation.
///
/// The two halves are one test on purpose. What makes the refusal assertable is
/// that the *other* invitation, sent at the same moment by a stranger, was
/// still sitting at `invite` after the loop had demonstrably run by joining the
/// legitimate one — without that ordering, "has not joined yet" and "will never
/// join" are the same observation.
#[tokio::test]
async fn the_owners_device_joins_portals_and_nothing_else() -> Result<()> {
    ensure_stack().await?;
    let _guard = harness::SENSOR_LOCK.lock().await;
    let owner = Bot::login("owner").await?;
    let bridge = Bot::login("whatsappbot").await?;
    let stranger = Bot::login("bot_beta").await?;
    assert_eq!(owner.user_id(), OWNER);
    assert_eq!(bridge.user_id(), BRIDGE_BOT);
    assert_eq!(stranger.user_id(), STRANGER);

    // A portal, as mautrix builds one: the bridge's own bot creates it, marks
    // it, and invites the user.
    let portal = make_whatsapp_portal(&bridge, "owner-device-portal").await?;
    bridge.invite(&portal, SENSOR_USER_ID).await?;
    bridge.invite(&portal, OWNER).await?;

    // And a room that *claims* to be a portal. Everything in this invitation
    // except its sender is the stranger's to choose, including the `m.bridge`
    // marker — which is exactly why the marker is not what the Sensor reads.
    let impostor = stranger.create_room("owner-device-impostor", false).await?;
    let (state_key, content) = harness::whatsapp_bridge_state(BRIDGE_BOT, "impostor");
    stranger
        .send_state_event(&impostor, "m.bridge", &state_key, content)
        .await?;
    stranger.invite(&impostor, OWNER).await?;

    let sensor = SensorProc::start(&owner_device_env(
        "joins-portals",
        Some((owner.access_token(), owner.device_id())),
    ))?;

    bridge.wait_for_membership(&portal, OWNER, "join").await?;
    // The observing identity is unchanged (ADR 0024) and joins on its own
    // schedule: the two clients are independent, so this is waited for rather
    // than read once.
    bridge
        .wait_for_membership(&portal, SENSOR_USER_ID, "join")
        .await?;

    // The loop has run — it joined the portal above — so the impostor's
    // invitation is not one it has yet to reach.
    assert_eq!(
        stranger.get_membership(&impostor, OWNER).await?,
        "invite",
        "a device of the user's own account must not be placed in a room by anybody who can send \
         an invitation"
    );

    // Both lines, waited for rather than snapshotted: the membership the
    // homeserver already reports and the line the Sensor has written are two
    // different moments, and the whole suite running at once is enough to put
    // them in that order.
    let logs = wait_up_to(Duration::from_secs(30), || async {
        let logs = sensor.logs().await;
        let joined = logs
            .iter()
            .any(|line| line.contains("joined a portal of a configured bridge"));
        let refused = logs.iter().any(|line| {
            line.contains("not joining the owner's device to this room")
                && line.contains("inviter_is_not_a_bridge_bot")
        });
        (joined && refused).then_some(logs)
    })
    .await;
    assert!(
        logs.is_ok(),
        "the join and the refusal are both announced with their reason, not silent: {:?}",
        sensor.logs().await
    );

    sensor.stop().await;
    Ok(())
}

/// Issue #237: a portal the owner's device can never join is given up on
/// **once**, from what the homeserver answered, and the loop goes on joining
/// the portals it can.
///
/// The shape is the one measured live: a portal every member has left. The
/// homeserver has no server to join through and says so with a 404 — and that
/// answer will never change, so the seventy-eight retries in five minutes it
/// produced were noise that buried the next real failure. What is asserted,
/// from outside the Sensor:
///
/// - a *later* invitation, arriving after the first failure, is joined — so the
///   loop has run at least once more since, and would have retried the orphan
///   had it not remembered it;
/// - the orphan is announced exactly once, as unjoinable, and never as "retrying";
/// - and the fact is readable off `/metrics`, not only out of the log: the
///   `unjoinable` outcome is 1 and the gauge of such portals is 1.
#[tokio::test]
async fn a_portal_that_can_never_be_joined_is_given_up_on_once() -> Result<()> {
    const METRICS_LISTEN: &str = "127.0.0.1:19011";
    const METRICS_URL: &str = "http://127.0.0.1:19011/metrics";

    ensure_stack().await?;
    let _guard = harness::SENSOR_LOCK.lock().await;
    let owner = Bot::login("owner").await?;
    let bridge = Bot::login("whatsappbot").await?;

    // The orphan: built and marked like any portal, the owner invited — then
    // the only member leaves. Synapse now has no server that is in the room.
    let orphan = make_whatsapp_portal(&bridge, "owner-device-orphan").await?;
    bridge.invite(&orphan, OWNER).await?;
    bridge.leave_room(&orphan).await?;

    let mut env = owner_device_env(
        "unjoinable-portal",
        Some((owner.access_token(), owner.device_id())),
    );
    env.push((
        "SENSOR_METRICS_LISTEN".to_owned(),
        METRICS_LISTEN.to_owned(),
    ));
    let sensor = SensorProc::start(&env)?;

    // The first pass over the orphan has happened once its refusal is logged.
    poll_until(
        || async {
            sensor
                .logs()
                .await
                .iter()
                .any(|line| line.contains("can never be joined"))
                .then_some(())
        },
        "waiting for the orphan portal to be given up on",
    )
    .await?;

    // A portal that arrives *after* that: joining it proves the loop ran again.
    let portal = make_whatsapp_portal(&bridge, "owner-device-after-orphan").await?;
    bridge.invite(&portal, OWNER).await?;
    bridge.wait_for_membership(&portal, OWNER, "join").await?;

    let logs = sensor.logs().await;
    let given_up = logs
        .iter()
        .filter(|line| line.contains(&orphan) && line.contains("can never be joined"))
        .count();
    assert_eq!(given_up, 1, "one refusal, not a stream: {logs:?}");
    assert!(
        !logs
            .iter()
            .any(|line| line.contains(&orphan) && line.contains("failed to join a portal")),
        "a permanent answer is never retried: {logs:?}"
    );
    assert_eq!(
        bridge.get_membership(&orphan, OWNER).await.ok().as_deref(),
        Some("invite"),
        "the orphan invitation is left where it was"
    );

    // The stack persists across runs, so the owner may hold orphans from
    // earlier runs too: what is asserted is that this one is counted, and
    // that the gauge and the once-per-room counter agree with each other.
    let metrics = reqwest::get(METRICS_URL).await?.text().await?;
    let sample = |name: &str| -> u64 {
        metrics
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .and_then(|rest| rest.trim().parse().ok())
            .unwrap_or_else(|| panic!("no sample {name} in {metrics}"))
    };
    let unjoinable = sample("twalk_sensor_owner_device_invites_total{outcome=\"unjoinable\"} ");
    let portals = sample("twalk_sensor_owner_device_unjoinable_portals ");
    assert!(unjoinable >= 1, "the orphan is counted: {metrics}");
    assert_eq!(
        portals, unjoinable,
        "readable without grepping logs, and consistent: {metrics}"
    );

    sensor.stop().await;
    Ok(())
}

/// An approved reply is posted by the **owner's own account**, and the Sensor
/// says on the bus that it reached the contact.
#[tokio::test]
async fn an_approved_reply_is_posted_by_the_owners_own_account() -> Result<()> {
    ensure_stack().await?;
    let _guard = harness::SENSOR_LOCK.lock().await;
    let bus = Bus::connect().await?;
    let owner = Bot::login("owner").await?;
    let bridge = Bot::login("whatsappbot").await?;

    let portal = make_whatsapp_portal(&bridge, "owner-device-reply").await?;
    bridge.invite(&portal, SENSOR_USER_ID).await?;
    bridge.invite(&portal, OWNER).await?;

    let sensor = SensorProc::start(&owner_device_env(
        "posts-as-the-owner",
        Some((owner.access_token(), owner.device_id())),
    ))?;
    bridge.wait_for_membership(&portal, OWNER, "join").await?;

    let body = "Oui, 20h c'est parfait.";
    let approved = approved_reply(&portal, body)?;
    let approval_id = approved["id"].as_str().unwrap().to_owned();
    bus.publish_event(REPLY_APPROVED_SUBJECT, &approved).await?;

    let posted = event_from(&bridge, &portal, OWNER, "the reply posted by the owner").await?;
    assert_eq!(
        posted.pointer("/content/body").and_then(Value::as_str),
        Some(body),
        "the posted content is the final, approved content"
    );

    // And `@sensor:` posted nothing at all: the two identities are not
    // interchangeable, and one of them is the one a bridge ignores.
    let events = bridge.room_events(&portal, 50).await?;
    assert!(
        events.iter().all(|event| {
            event.get("sender").and_then(Value::as_str) != Some(SENSOR_USER_ID)
                || event.get("type").and_then(Value::as_str) != Some("m.room.message")
        }),
        "the observing identity must never be the one that speaks"
    );

    // #216: the answer is on the bus, not only in a log line.
    let report = posted_report(&bus, &approval_id).await?;
    assert_eq!(report.header("reach"), Some("contact"));
    assert_eq!(report.header("posted-as"), Some(OWNER));
    assert_eq!(report.header("event-id"), Some(approval_id.as_str()));
    assert_eq!(
        report.header("Nats-Msg-Id"),
        Some(format!("{approval_id}:posted").as_str()),
        "the report needs a message id of its own: it shares the stream with the approval, which \
         was published under the event id"
    );
    assert_eq!(
        report.payload, approved,
        "the report carries the approval unchanged, so no schema moves to make room for it"
    );
    validate_against_contract(&report.payload, "persona.reply.approved")?;

    sensor.stop().await;
    Ok(())
}

/// The reply into an **encrypted** portal — which every real portal is.
///
/// The owner's device runs no message sync: its `/sync` asks for zero timeline
/// events and nothing is registered to receive them. The claim being tested is
/// that this is still enough for Megolm, and the only honest way to test it is
/// to have a **different device** decrypt what it wrote. The Sensor's own
/// client is that device: it is in the room, it holds its own crypto store, and
/// when it decrypts a message from the owner it publishes
/// `outbound.message.sent` (ADR 0018) — so that event appearing with the
/// approved body is proof the room key was really shared with a device the
/// owner's client only learned about through the send path itself.
#[tokio::test]
async fn an_encrypted_portal_reply_is_readable_by_another_device() -> Result<()> {
    ensure_stack().await?;
    let _guard = harness::SENSOR_LOCK.lock().await;
    let bus = Bus::connect().await?;
    let owner = Bot::login("owner").await?;
    // The bridge needs the real SDK here: raw HTTP cannot create a room that
    // negotiates Megolm the way a mautrix portal does.
    let bridge = CryptoBot::login("whatsappbot").await?;
    let reader = Bot::login("whatsappbot").await?;

    let portal = make_encrypted_whatsapp_portal(&bridge, "owner-device-encrypted").await?;
    bridge.invite(&portal, SENSOR_USER_ID).await?;
    bridge.invite(&portal, OWNER).await?;

    let sensor = SensorProc::start(&owner_device_env(
        "encrypted-portal",
        Some((owner.access_token(), owner.device_id())),
    ))?;
    reader.wait_for_membership(&portal, OWNER, "join").await?;
    reader
        .wait_for_membership(&portal, SENSOR_USER_ID, "join")
        .await?;

    let body = "Chiffré, et envoyé par le compte du propriétaire.";
    let approved = approved_reply(&portal, body)?;
    let approval_id = approved["id"].as_str().unwrap().to_owned();
    bus.publish_event(REPLY_APPROVED_SUBJECT, &approved).await?;

    let posted = event_from(&reader, &portal, OWNER, "the encrypted reply").await?;
    assert_eq!(
        posted.get("type").and_then(Value::as_str),
        Some("m.room.encrypted"),
        "a write-only device still encrypts: the ciphertext is what reaches the room"
    );

    // Another device read it. Nothing else in this suite proves the room key
    // went anywhere.
    let decrypted = poll_until(
        || async {
            bus.fetch_room_messages(STREAM, OUTBOUND_SUBJECT, &portal)
                .await
                .ok()?
                .into_iter()
                .find(|m| m.payload.pointer("/data/body").and_then(Value::as_str) == Some(body))
        },
        "the Sensor's own device decrypting the owner-device's reply",
    )
    .await?;
    assert_eq!(
        decrypted.payload["subject"].as_str(),
        Some(OWNER),
        "the reply really is the user's own message, which is the whole point (ADR 0018)"
    );
    validate_against_contract(&decrypted.payload, "outbound.message.sent")?;

    let report = posted_report(&bus, &approval_id).await?;
    assert_eq!(report.header("reach"), Some("contact"));
    assert_eq!(report.header("posted-as"), Some(OWNER));

    sensor.stop().await;
    Ok(())
}

/// With no device of the owner's account, nothing about the send changes — and
/// everything about what is *claimed* of it does.
#[tokio::test]
async fn without_the_owners_device_the_reply_reaches_nobody_and_says_so() -> Result<()> {
    ensure_stack().await?;
    let _guard = harness::SENSOR_LOCK.lock().await;
    let bus = Bus::connect().await?;
    let bridge = Bot::login("whatsappbot").await?;

    let portal = make_whatsapp_portal(&bridge, "owner-device-absent").await?;
    bridge.invite(&portal, SENSOR_USER_ID).await?;

    let sensor = SensorProc::start(&owner_device_env("no-owner-device", None))?;
    bridge
        .wait_for_membership(&portal, SENSOR_USER_ID, "join")
        .await?;

    let body = "Postée par le Sensor, et lue par personne.";
    let approved = approved_reply(&portal, body)?;
    let approval_id = approved["id"].as_str().unwrap().to_owned();
    bus.publish_event(REPLY_APPROVED_SUBJECT, &approved).await?;

    // Unchanged: the Sensor posts, exactly as it did before any of this.
    let posted = event_from(
        &bridge,
        &portal,
        SENSOR_USER_ID,
        "the reply posted by the Sensor",
    )
    .await?;
    assert_eq!(
        posted.pointer("/content/body").and_then(Value::as_str),
        Some(body)
    );

    // Changed: it is no longer reported as sent. This is the sentence #216 is
    // about — "published on your bus" and "delivered to the contact" are two
    // different facts, and only one of them happened.
    let report = posted_report(&bus, &approval_id).await?;
    assert_eq!(
        report.header("reach"),
        Some("nobody"),
        "a mautrix bridge relays only the logged-in user's own account"
    );
    assert_eq!(report.header("posted-as"), Some(SENSOR_USER_ID));

    let logs = sensor.logs().await;
    assert!(
        logs.iter().any(|line| {
            line.contains("no device of the owner's account configured") && line.contains("#123")
        }),
        "the degradation is stated once at startup and named after the issue: {logs:?}"
    );

    sensor.stop().await;
    Ok(())
}

/// A token for the wrong account is a configuration error, and the Sensor
/// refuses to start on it.
///
/// The alternative is that it starts, joins portal rooms as somebody else's
/// device and writes into other people's conversations under a Matrix ID nobody
/// chose — a defect whose first symptom is a contact receiving a reply from a
/// stranger, which is not a thing a deployment can take back.
#[tokio::test]
async fn a_token_for_another_account_is_refused_at_startup() -> Result<()> {
    ensure_stack().await?;
    let _guard = harness::SENSOR_LOCK.lock().await;
    let somebody_else = Bot::login("bot_beta").await?;

    let mut sensor = SensorProc::start(&owner_device_env(
        "wrong-account",
        Some((somebody_else.access_token(), somebody_else.device_id())),
    ))?;

    poll_until(
        || async {
            let logs = sensor.logs().await;
            logs.iter()
                .any(|line| {
                    line.contains("SENSOR_OWNER_DEVICE_ACCESS_TOKEN belongs to")
                        && line.contains(STRANGER)
                        && line.contains(OWNER)
                })
                .then_some(())
        },
        "the Sensor naming both accounts and refusing to start",
    )
    .await?;
    // `is_running` takes the process mutably, so this is a bounded loop rather
    // than `poll_until`. The refusal is a startup one: it happens before the
    // sync loop, so a second is generous.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while sensor.is_running() && std::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(
        !sensor.is_running(),
        "the Sensor must exit rather than run as a device of somebody else's account"
    );

    sensor.stop().await;
    Ok(())
}

/// Revoking the acting device is noticed and named, not a silent stop
/// (issue #229).
///
/// ADR 0025 accepted a long-lived token for the owner's own account at rest, and
/// the mitigation it named was neither encryption nor scope: the token is a
/// device among the owner's devices, revocable from any Matrix client without
/// Twalk's involvement. A mitigation nobody can observe is not one, and until
/// this ticket nothing observed it — the sync loop warned every thirty seconds
/// for ever, approvals went on being accepted, and nothing arrived.
///
/// The revocation here is a `POST /logout` with the device's own token, which is
/// what the owner's phone does to a device it deletes: the homeserver forgets
/// both, and every later request with that token answers `M_UNKNOWN_TOKEN`.
#[tokio::test]
async fn a_revoked_acting_device_is_noticed_and_named_and_no_reply_goes_out_as_the_owner(
) -> Result<()> {
    ensure_stack().await?;
    let _guard = harness::SENSOR_LOCK.lock().await;
    let bus = Bus::connect().await?;
    let owner = Bot::login("owner").await?;
    let bridge = Bot::login("whatsappbot").await?;

    let portal = make_whatsapp_portal(&bridge, "owner-device-revoked").await?;
    bridge.invite(&portal, SENSOR_USER_ID).await?;
    bridge.invite(&portal, OWNER).await?;

    let sensor = SensorProc::start(&owner_device_env(
        "revoked-device",
        Some((owner.access_token(), owner.device_id())),
    ))?;
    bridge.wait_for_membership(&portal, OWNER, "join").await?;

    // The owner revokes it from somewhere else entirely. Nothing tells the
    // Sensor; it finds out because its next sync is refused.
    owner.revoke_this_device().await?;

    // 1. It is noticed **without a restart**, and named: which credential is
    //    gone, what puts it back, and that this is not a homeserver that is
    //    merely away — those are two situations and must not share one signal.
    //
    //    Waited for longer than the harness's twenty seconds, and the reason is
    //    the thing under test: the device holds a sync long-poll open for
    //    `OWNER_DEVICE_SYNC_TIMEOUT` (thirty seconds), so a revocation is
    //    noticed when that poll comes back and not when it happens. Twenty
    //    seconds is shorter than that by construction, which is how the first
    //    version of this test failed.
    let said = wait_up_to(Duration::from_secs(90), || async {
        let logs = sensor.logs().await;
        logs.iter()
            .any(|line| {
                line.contains("SENSOR_OWNER_DEVICE_ACCESS_TOKEN")
                    && line.contains("no longer knows")
            })
            .then_some(())
    })
    .await;
    if said.is_err() {
        let logs = sensor.logs().await;
        anyhow::bail!("the revocation was never named; the Sensor's log was:\n{logs:#?}");
    }
    let logs = sensor.logs().await;
    assert!(
        logs.iter()
            .any(|line| line.contains("not a homeserver that is unreachable")),
        "the message tells the two situations apart: {logs:#?}"
    );

    // 2. And no reply is accepted for sending under the identity the deployment
    //    no longer holds. Not posted as the Sensor either: that would put a
    //    message in the contact's room that the contact cannot see, which is
    //    #123's worst answer wearing a success's clothes.
    let body = "Cette réponse ne doit pas sortir.";
    let approved = approved_reply(&portal, body)?;
    let approval_id = approved["id"].as_str().unwrap().to_owned();
    bus.publish_event(REPLY_APPROVED_SUBJECT, &approved).await?;

    // The retries are exhausted in under a second here
    // (`SENSOR_SEND_RETRY_BASE_MS`, `SENSOR_SEND_RETRY_MAX_ATTEMPTS`), and what
    // the owner sees is the dead letter: the approval screen reads its `reason`
    // (#311), so the credential and the remedy are what they are told.
    let dead = wait_up_to(Duration::from_secs(60), || async {
        bus.fetch_all_with_headers(STREAM, "twalk.persona.reply.approved.v1.dead")
            .await
            .ok()?
            .into_iter()
            .find(|message| message.header("event-id") == Some(approval_id.as_str()))
    })
    .await
    .context("the approval was never dead-lettered")?;
    // A dead letter is a copy of the approval it gave up on, so it is still an
    // event the contract allows — asserted, because a suite that checked only
    // the headers would not notice a copy that had stopped being one.
    validate_against_contract(&dead.payload, "persona.reply.approved")?;
    let reason = dead
        .header("reason")
        .expect("a dead letter says why the Sensor gave up");
    assert!(
        reason.contains("SENSOR_OWNER_DEVICE_ACCESS_TOKEN"),
        "the reason names the credential the owner has to replace: {reason}"
    );
    assert!(
        !reason.contains(body),
        "the reason names the failure and never quotes the reply: {reason}"
    );

    // Nothing in the room, under either identity: read once and asked of both.
    let events = bridge.room_events(&portal, 50).await?;
    for sender in [OWNER, SENSOR_USER_ID] {
        assert!(
            !events.iter().any(|event| {
                event["sender"].as_str() == Some(sender)
                    && event.pointer("/content/body").and_then(Value::as_str) == Some(body)
            }),
            "no reply may be posted as {sender} once the acting credential is gone"
        );
    }

    sensor.stop().await;

    // 3. Re-provisioning restores delivery, with no other step: a new device of
    //    the same account, the token and the id set, and the reply the owner
    //    approved goes out as them. The restart is the provisioning — today the
    //    credential is an environment variable an operator sets (#228 is the
    //    handover that removes that step) — and nothing else is asked for: no
    //    invitation to re-accept, no state to clear.
    let replacement = Bot::login("owner").await?;
    let mut env = owner_device_env(
        "revoked-device-replaced",
        Some((replacement.access_token(), replacement.device_id())),
    );
    // A longer send schedule than the other tests use, and for a reason that is
    // part of what is under test. The owner's *account* is already joined to the
    // portal — the revoked device joined it, and a membership belongs to the
    // account and not to the device — so there is no join to wait for here. What
    // there is to wait for is the new device's first sync, after which it knows
    // the room at all; until then a reply to a portal is a transient failure by
    // design ("the owner's device has not joined this portal room"), and with
    // the suite's default schedule of three attempts a hundred milliseconds
    // apart the retries are spent before the first sync returns. Lengthening it
    // makes this test wait for the design instead of racing it.
    for (name, value) in &mut env {
        if name == "SENSOR_SEND_RETRY_BASE_MS" {
            *value = "500".to_owned();
        }
        if name == "SENSOR_SEND_RETRY_MAX_ATTEMPTS" {
            *value = "8".to_owned();
        }
    }
    let sensor = SensorProc::start(&env)?;
    let again = "Cette réponse-là sort.";
    let approved = approved_reply(&portal, again)?;
    bus.publish_event(REPLY_APPROVED_SUBJECT, &approved).await?;
    let posted = wait_up_to(Duration::from_secs(120), || async {
        bridge
            .room_events(&portal, 50)
            .await
            .ok()?
            .into_iter()
            .find(|event| {
                event["sender"].as_str() == Some(OWNER)
                    && event.pointer("/content/body").and_then(Value::as_str) == Some(again)
            })
    })
    .await
    .context("the re-provisioned device never posted the reply as the owner")?;
    assert_eq!(
        posted["sender"].as_str(),
        Some(OWNER),
        "a re-provisioned device sends as the owner again"
    );

    sensor.stop().await;
    Ok(())
}

/// The credential arrives over a channel anybody can write to, and the two ways
/// it arrives that this Sensor takes nothing from (#228, ADR 0034).
///
/// A to-device event is addressable by **any account on any homeserver**: there is
/// no invitation to accept and no room to be in. So the property under test is not
/// that a handover works — the browser's journey proves that, with a real Olm
/// session — but that the two deliveries which are *not* a handover are refused,
/// counted, and leave the deployment exactly as it was.
///
/// The two are one test for the reason the join/refuse pair above is one test: the
/// refusals are asserted against a room and a state directory that the Sensor
/// **could** have written to, and that is what tells "it refused" from "it could
/// not have done it anyway". The room is created the way the Companion creates it,
/// power-level exception included, and the offer the owner writes in it names a
/// real device of theirs — so everything about this handover is right except the
/// one thing each half gets wrong.
#[tokio::test]
async fn a_handover_in_the_clear_or_one_that_cannot_be_read_is_refused_and_counted() -> Result<()> {
    ensure_stack().await?;
    let _guard = harness::SENSOR_LOCK.lock().await;

    let owner = Bot::login("owner").await?;
    let state_dir = fresh_state_dir("handover-refused");
    let metrics_addr = harness::free_loopback_addr()?;
    let metrics_url = format!("http://{metrics_addr}/metrics");
    let mut env = sensor_env_with(&[
        ("SENSOR_OWNER", OWNER),
        ("SENSOR_BRIDGE_BOTS", BRIDGE_BOT),
        ("SENSOR_STATE_DIR", &state_dir.to_string_lossy()),
        ("SENSOR_METRICS_LISTEN", &metrics_addr),
    ]);
    // The Sensor has to accept the owner's invitation to the handover room, which
    // is the only room this test is about.
    for (name, value) in env.iter_mut() {
        if name == "SENSOR_ALLOWED_INVITERS" {
            *value = format!("{OWNER},{BRIDGE_BOT}");
        }
    }
    let sensor = SensorProc::start(&env)?;

    // The room, as `companion/src/lib/matrix/handover.ts` creates it, and the
    // offer that says which device the credential will come from.
    let room = owner
        .create_handover_room("h228 the handover room", SENSOR_USER_ID)
        .await?;
    owner
        .wait_for_membership(&room, SENSOR_USER_ID, "join")
        .await?;
    owner
        .send_state_event(
            &room,
            "fr.linagora.twalk.owner_device.handover.from",
            "",
            json!({ "device_id": owner.device_id() }),
        )
        .await?;

    // Half one: the credential in the clear, from the very device the owner
    // offered. Everything a real handover carries, and no encryption — which is
    // either an attacker's or a bug, and the two get the same answer because
    // nothing about a plaintext event says which.
    owner
        .send_to_device(
            "fr.linagora.twalk.owner_device.handover",
            SENSOR_USER_ID,
            json!({
                "user_id": OWNER,
                "device_id": owner.device_id(),
                "access_token": owner.access_token(),
            }),
        )
        .await?;

    // Half two: an Olm-shaped event this Sensor cannot read, sent while the offer
    // stands. The type is inside what cannot be read, so the only reason this
    // counts as a refused handover at all is the offer — which is the state ADR
    // 0034 says hardening the trust requirement would turn this channel into.
    //
    // The ciphertext is deliberately not a real Olm message: what a test can
    // produce over plain HTTP is an event nobody can read, and the Sensor answers
    // the same way for that as for one it has no session for.
    owner
        .send_to_device(
            "m.room.encrypted",
            SENSOR_USER_ID,
            json!({
                "algorithm": "m.olm.v1.curve25519-aes-sha2",
                "sender_key": "3C5BFWi2Y8MaVvjM8M22DBmh24PmgR0nPvJOIArzgyI",
                "ciphertext": {
                    "7qZcfnBmbEGzxxaWfBjElJuvn7BZx+lSz+SXVoUaqlY": {
                        "type": 0,
                        "body": "AwogGJJzMhf/S3GQFXAOrCZ3iKyGU5ZScVtjI0KypTYrW1kQ",
                    },
                },
            }),
        )
        .await?;

    // Both refusals, from the Sensor's own words. Two lines, because a Sensor
    // that said this once for two deliveries would be one that stopped reading
    // the channel after the first.
    let refusals = wait_up_to(Duration::from_secs(60), || async {
        let lines = sensor.logs().await;
        let refused = lines
            .iter()
            .filter(|line| line.contains("refused a to-device event claiming to hand over"))
            .count();
        let unreadable = lines
            .iter()
            .filter(|line| line.contains("could not be read while a handover was offered"))
            .count();
        (refused >= 1 && unreadable >= 1).then_some((refused, unreadable))
    })
    .await;
    let refusals = match refusals {
        Ok(counts) => counts,
        Err(error) => {
            // The Sensor's own first lines say why it refused or never saw
            // anything, and a timeout on its own would send somebody to read this
            // file instead of that log.
            let log = sensor.logs().await.join("\n");
            sensor.stop().await;
            anyhow::bail!(
                "the Sensor never refused both deliveries ({error}); its log was:\n{log}"
            );
        }
    };
    assert!(refusals.0 >= 1 && refusals.1 >= 1);

    // And on /metrics, which is the only place an operator would ever see that
    // somebody is trying: two refusals, both `not_encrypted`, and nothing held.
    let body = wait_up_to(Duration::from_secs(30), || async {
        let body = reqwest::get(&metrics_url).await.ok()?.text().await.ok()?;
        body.contains("twalk_sensor_handovers_refused_total{why=\"not_encrypted\"} 2")
            .then_some(body)
    })
    .await
    .context("the two refusals are counted by why")?;
    assert!(
        body.contains("twalk_sensor_handovers_held_total 0"),
        "nothing was held: {body}"
    );
    assert!(
        body.contains("twalk_sensor_handovers_refused_total{why=\"unexpected_sender\"} 0"),
        "and neither refusal was about the device: {body}"
    );

    // Nothing was written down, so nothing is acted through after a restart
    // either.
    assert!(
        !state_dir.join("owner-device.json").exists(),
        "no credential is on the volume in {}",
        state_dir.display()
    );

    // And nothing was acknowledged in the room — in a room whose power levels
    // grant the Sensor that one state event, so the absence is a decision and not
    // a permission.
    let acknowledgement = owner
        .get_state_event(&room, "fr.linagora.twalk.owner_device.handover.held", "")
        .await;
    assert!(
        acknowledgement.is_err(),
        "the Sensor acknowledged a handover it refused: {acknowledgement:?}"
    );

    sensor.stop().await;
    Ok(())
}

/// The whole of ADR 0034, closed: a credential handed over in the browser makes
/// this deployment reply **as the owner** — with no restart, and with nothing
/// configured (#228).
///
/// This is the acceptance the ticket asks for and the one nothing else can give.
/// The refusal test above drives the deliveries a test can drive over plain HTTP;
/// the Companion's own suite drives the browser's half against a recorded
/// homeserver. Neither answers the question that has sunk this product's outbound
/// path before: do the two halves actually fit — the event type, the content, the
/// device the `EncryptionInfo` reports against the device the offer named, the
/// power-level exception the acknowledgement needs — on a real homeserver, with a
/// real Olm session.
///
/// So the browser is played by a `CryptoBot` with a real crypto stack, and every
/// assertion is made from outside the Sensor: the acknowledgement in the room, the
/// credential on the volume, `/metrics`, and — the one that matters — a portal
/// message whose `sender` is the owner's own account, posted by a device this
/// process was not started with.
#[tokio::test]
async fn a_handover_makes_the_deployment_reply_as_the_owner_with_no_restart() -> Result<()> {
    ensure_stack().await?;
    let _guard = harness::SENSOR_LOCK.lock().await;
    let bus = Bus::connect().await?;

    // The browser: the owner's own session, with the crypto stack that will
    // encrypt the credential.
    let browser = CryptoBot::login("owner").await?;
    let bridge = Bot::login("whatsappbot").await?;

    // A Sensor that has been given **nothing**: no SENSOR_OWNER_DEVICE_ACCESS_TOKEN
    // and no credential on its volume. This is every deployment before onboarding,
    // and it is the state #123 describes — replies go out as `@sensor:` and reach
    // nobody.
    let state_dir = fresh_state_dir("handover-held");
    let metrics_addr = harness::free_loopback_addr()?;
    let metrics_url = format!("http://{metrics_addr}/metrics");
    let mut env = sensor_env_with(&[
        ("SENSOR_OWNER", OWNER),
        ("SENSOR_BRIDGE_BOTS", BRIDGE_BOT),
        ("SENSOR_STATE_DIR", &state_dir.to_string_lossy()),
        ("SENSOR_METRICS_LISTEN", &metrics_addr),
        ("SENSOR_SEND_RETRY_BASE_MS", "100"),
        ("SENSOR_SEND_RETRY_MAX_ATTEMPTS", "8"),
    ]);
    for (name, value) in env.iter_mut() {
        if name == "SENSOR_ALLOWED_INVITERS" {
            *value = format!("{OWNER},{BRIDGE_BOT}");
        }
    }
    let sensor = SensorProc::start(&env)?;
    harness::wait_up_to(Duration::from_secs(30), || async {
        sensor
            .logs()
            .await
            .iter()
            .any(|line| line.contains("and none handed over"))
            .then_some(())
    })
    .await
    .context("the Sensor says it holds no acting device before the handover")?;

    // The room the two share, created as the Companion creates it, and the two
    // waits that make an encrypted send to the Sensor possible at all (#226).
    let room = browser
        .create_handover_room("h228 handover, accepted", SENSOR_USER_ID)
        .await?;
    browser
        .wait_for_joined_member(&room, SENSOR_USER_ID)
        .await?;
    harness::crypto::wait_for_user_devices(browser.client(), SENSOR_USER_ID).await?;

    // The offer: the owner says which of their devices will hand a credential
    // over. Only their account can write it here.
    browser
        .send_state_event(
            &room,
            "fr.linagora.twalk.owner_device.handover.from",
            "",
            json!({ "device_id": browser.device_id() }),
        )
        .await?;

    // The device the browser creates for Twalk to act through: an ordinary login
    // on the owner's own account, which is what `initial_device_display_name:
    // twalk` is in the Companion.
    let acting = Bot::login("owner").await?;
    assert_ne!(
        acting.device_id(),
        browser.device_id(),
        "the device handed over is not the browser's own"
    );
    let encrypted_to = browser
        .hand_over_encrypted(
            SENSOR_USER_ID,
            "fr.linagora.twalk.owner_device.handover",
            json!({
                "user_id": OWNER,
                "device_id": acting.device_id(),
                "access_token": acting.access_token(),
            }),
        )
        .await?;
    assert!(
        encrypted_to >= 1,
        "the credential went to a device of the Sensor's"
    );

    // The acknowledgement, which is the only thing the Companion reads as
    // success — and it names the device, so a browser waiting for its own
    // handover is not satisfied by an earlier one.
    let acknowledgement = wait_up_to(Duration::from_secs(90), || async {
        let answer = acting
            .get_state_event(&room, "fr.linagora.twalk.owner_device.handover.held", "")
            .await
            .ok()?;
        answer["device_id"]
            .as_str()
            .is_some_and(|device| device == acting.device_id())
            .then_some(answer)
    })
    .await
    .with_context(|| format!("the Sensor never acknowledged the handover in {room}"))?;
    assert_eq!(acknowledgement["user_id"].as_str(), Some(OWNER));
    assert_eq!(
        acknowledgement["offered_by"].as_str(),
        Some(browser.device_id().as_str()),
        "the acknowledgement names the device that offered it"
    );
    assert!(
        !acknowledgement.to_string().contains(acting.access_token()),
        "the acknowledgement is unencrypted state in a room and must not carry the credential"
    );

    // It is on the volume, readable by nobody else, so the next restart still has
    // it — an acknowledgement for a credential held only in memory would be a
    // deployment that stops replying as the owner when it is next restarted.
    let credential_file = state_dir.join("owner-device.json");
    let held: Value = serde_json::from_str(&std::fs::read_to_string(&credential_file)?)?;
    assert_eq!(held["device_id"].as_str(), Some(acting.device_id()));
    assert_eq!(held["user_id"].as_str(), Some(OWNER));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&credential_file)?.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the credential is readable by its owner alone");
    }

    // And on /metrics, where a revoked deployment's own gauge now says it can act
    // again (#229 could not put that back without a restart).
    let body = wait_up_to(Duration::from_secs(30), || async {
        let body = reqwest::get(&metrics_url).await.ok()?.text().await.ok()?;
        body.contains("twalk_sensor_handovers_held_total 1")
            .then_some(body)
    })
    .await
    .context("the handover is counted")?;
    assert!(
        body.contains("twalk_sensor_owner_device_credential_gone 0"),
        "the deployment holds a usable device: {body}"
    );
    assert!(
        body.contains("twalk_sensor_handovers_refused_total{why=\"unexpected_sender\"} 0"),
        "and nothing about this handover was refused: {body}"
    );

    // The proof. A portal, an approved reply on the bus, and the sender of the
    // message that lands in the room: the owner's own account, through a device
    // this process was not started with and nobody restarted it to use.
    let portal = make_whatsapp_portal(&bridge, "handover-reply").await?;
    bridge.invite(&portal, SENSOR_USER_ID).await?;
    bridge.invite(&portal, OWNER).await?;
    bridge.wait_for_membership(&portal, OWNER, "join").await?;

    let body = "Oui, je confirme pour 20h.";
    let approved = approved_reply(&portal, body)?;
    let approval_id = approved["id"].as_str().unwrap().to_owned();
    bus.publish_event(REPLY_APPROVED_SUBJECT, &approved).await?;

    let posted = wait_up_to(Duration::from_secs(120), || async {
        bridge
            .room_events(&portal, 50)
            .await
            .ok()?
            .into_iter()
            .find(|event| {
                event["sender"].as_str() == Some(OWNER)
                    && event.pointer("/content/body").and_then(Value::as_str) == Some(body)
            })
    })
    .await
    .context("the handed-over device never posted the reply as the owner")?;
    assert_eq!(posted["sender"].as_str(), Some(OWNER));

    // And the Sensor says on the bus what that reached, which is the fact #216
    // exists for: a reply posted by the owner's account is one the bridge relays.
    let report = posted_report(&bus, &approval_id).await?;
    assert_eq!(report.header("reach"), Some("contact"));
    assert_eq!(report.header("posted-as"), Some(OWNER));

    sensor.stop().await;
    Ok(())
}

/// A handed-over credential the homeserver no longer knows does not stop the
/// Sensor from starting — and the deadlock that would be if it did (#228, #229).
///
/// The owner revokes the device from their phone, which is ADR 0025's whole
/// mitigation, and the deployment is restarted. The credential is still on the
/// volume and the homeserver refuses it. A Sensor that treated that the way it
/// treats a **configured** credential it cannot use — refusing to start — could
/// never be re-onboarded, because the remedy needs a running Sensor to accept the
/// new handover: the deployment would be down until somebody with shell access
/// deleted a file.
///
/// So it starts, says what is true, and shows it on `/metrics` as the state #229
/// named: a device was given and nothing can act through it.
#[tokio::test]
async fn a_handed_over_credential_the_homeserver_refuses_does_not_stop_the_sensor() -> Result<()> {
    ensure_stack().await?;
    let _guard = harness::SENSOR_LOCK.lock().await;

    // A real device of the owner's, revoked the way the owner revokes one.
    let revoked = Bot::login("owner").await?;
    let device_id = revoked.device_id().to_owned();
    let credential = json!({
        "user_id": OWNER,
        "device_id": device_id,
        "access_token": revoked.access_token(),
    });
    revoked.revoke_this_device().await?;

    let state_dir = fresh_state_dir("handover-revoked");
    std::fs::create_dir_all(&state_dir)?;
    std::fs::write(
        state_dir.join("owner-device.json"),
        serde_json::to_vec(&credential)?,
    )?;
    let metrics_addr = harness::free_loopback_addr()?;
    let mut sensor = SensorProc::start(&sensor_env_with(&[
        ("SENSOR_OWNER", OWNER),
        ("SENSOR_BRIDGE_BOTS", BRIDGE_BOT),
        ("SENSOR_STATE_DIR", &state_dir.to_string_lossy()),
        ("SENSOR_METRICS_LISTEN", &metrics_addr),
    ]))?;

    poll_until(
        || async {
            let logs = sensor.logs().await;
            (logs
                .iter()
                .any(|line| line.contains("cannot be used") && line.contains("onboard again"))
                && logs.iter().any(|line| line.contains("sensor running")))
            .then_some(())
        },
        "the Sensor naming the dead credential, the remedy, and running anyway",
    )
    .await?;
    assert!(
        sensor.is_running(),
        "a revoked handover must not take the whole deployment down: it observes and publishes as \
         before"
    );

    // And the gauge says which of the two situations this is: a device was given
    // and cannot act, not a deployment that was never given one.
    let body = wait_up_to(Duration::from_secs(30), || async {
        let body = reqwest::get(format!("http://{metrics_addr}/metrics"))
            .await
            .ok()?
            .text()
            .await
            .ok()?;
        body.contains("twalk_sensor_owner_device_credential_gone 1")
            .then_some(body)
    })
    .await
    .context("the credential-gone gauge is 1")?;
    assert!(
        body.contains("twalk_sensor_handovers_held_total 0"),
        "{body}"
    );

    // The credential is kept: the homeserver may have been merely away, and
    // deleting the owner's credential over one failed request is not this
    // process's decision to make.
    assert!(state_dir.join("owner-device.json").exists());

    sensor.stop().await;
    Ok(())
}
