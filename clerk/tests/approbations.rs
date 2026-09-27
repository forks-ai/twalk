//! `approbations`: one suggestion is one post, and nothing of the contact
//! reaches the relay (ticket #265, ADR 0035).
//!
//! Three tests at the clerk's process boundary — the bus on one side, a
//! real Buzz relay read as its owner on the other, the clerk's own
//! `/metrics` beside them — and each one is a promise the clerk makes
//! that no unit test of its modules can keep.
//!
//! **One post and it stays one.** A suggestion redelivered by the bus, and
//! a clerk restarted on the same stream, must not produce a second post:
//! the clerk holds no store and recognises its own posts by their
//! reference line. "No second post" is proven by **ordering**, never by a
//! timer: a later suggestion is published and its post waited for, which
//! shows the consumer went past the redelivery; only then is the first
//! suggestion's count read.
//!
//! **Nothing of the contact.** The post carries the suggestion's body and
//! the clerk's own lines; what it must not carry is anything from the
//! message the suggestion answers — the contact's Matrix ID, display name,
//! network identifier, their message, a quoted excerpt, the room — nor the
//! persona's rationale, which quotes that message in its own words. The
//! test publishes the inbound message on the run's own stream with every
//! one of those as a marker, waits for the post, then searches **every
//! byte** the clerk could have written on all three channels: every
//! event's content and every tag value.
//!
//! **Expired is skipped, and counted.** A suggestion already past its
//! `expires_at` is not posted — and because a silence is the failure this
//! project ships most, it is a counted skip on `/metrics`.

mod harness;

use std::time::Duration;

use anyhow::Result;
use harness::{inbound_message, suggestion, Run, CONTACT_MATRIX_ID};
use serde_json::json;
use twalk_clerk::refusals::{delivery_unread_line, Unread};
use twalk_clerk::text::Lang;

#[tokio::test]
async fn a_suggestion_becomes_one_post_and_stays_one() -> Result<()> {
    let mut run = Run::start("approbations-one").await?;

    // One suggestion, an hour to live: one post, whose content is the
    // body between the clerk's own lines and the reference line last.
    let first = suggestion(&run.id, 1, 3600)?;
    let first_id = first["id"].as_str().unwrap().to_owned();
    let body = first["data"]["suggestion"]["body"].as_str().unwrap();
    let expires_at = first["data"]["expires_at"].as_str().unwrap();
    run.publish("persona.suggest.produced", &first).await?;

    let post = run.wait_for_post(&first_id).await?;
    assert!(
        post.content.contains(body),
        "the post carries the suggestion's body verbatim:\n{}",
        post.content
    );
    let reference = format!("twalk:suggestion:{first_id} expires {expires_at}");
    assert_eq!(
        post.content.lines().last(),
        Some(reference.as_str()),
        "the reference line is the post's last line:\n{}",
        post.content
    );
    // No write half on this run, so no device to read the delivery with:
    // the post says so, in the Companion's words (#300), rather than
    // guessing whether the reply could reach the contact.
    let no_device = delivery_unread_line(Lang::Fr, Unread::NoDevice);
    assert!(
        post.content.lines().any(|line| line == no_device),
        "a read-half post carries the no-device delivery line:\n{}",
        post.content
    );
    assert_eq!(
        post.pubkey.to_hex(),
        run.clerk_pubkey,
        "signed by the clerk's own key"
    );
    run.assert_metric("twalk_clerk_posts_total{channel=\"approbations\"} 1")
        .await?;

    // The same event again — the bus deduplicates on `Nats-Msg-Id` for
    // the bus's duplicate window (24 h since #174), so this is the same
    // CloudEvent id under a new message id, which is what a redelivery is
    // to the clerk. Then a second suggestion: its post proves the consumer
    // went past the redelivery.
    run.publish_again("persona.suggest.produced", &first)
        .await?;
    let second = suggestion(&run.id, 2, 3600)?;
    run.publish("persona.suggest.produced", &second).await?;
    run.wait_for_post(second["id"].as_str().unwrap()).await?;

    let posts = run.posts_about(&first_id).await?;
    assert_eq!(
        posts.len(),
        1,
        "a redelivered suggestion is still one post: {posts:?}"
    );
    run.assert_metric("twalk_clerk_skipped_total{why=\"duplicate\"} 1")
        .await?;
    run.assert_metric("twalk_clerk_posts_total{channel=\"approbations\"} 2")
        .await?;

    // A warm restart on the same key, channels and stream: the durable
    // consumer resumes at its ack floor, so the first two suggestions are
    // not read again — a third one's post is the proof the new process is
    // consuming, and the duplicate counter of the new process staying at
    // zero is the proof it resumed rather than re-read the stream.
    run.restart_clerk().await?;
    let third = suggestion(&run.id, 3, 3600)?;
    run.publish("persona.suggest.produced", &third).await?;
    run.wait_for_post(third["id"].as_str().unwrap()).await?;

    let posts = run.posts_about(&first_id).await?;
    assert_eq!(
        posts.len(),
        1,
        "a restarted clerk does not post the first suggestion again: {posts:?}"
    );
    run.assert_metric_now("twalk_clerk_skipped_total{why=\"duplicate\"} 0")
        .await?;
    run.assert_metric("twalk_clerk_posts_total{channel=\"approbations\"} 1")
        .await?;

    run.shutdown().await
}

#[tokio::test]
async fn nothing_of_the_contact_reaches_the_relay() -> Result<()> {
    let run = Run::start("approbations-nothing").await?;

    // The message the suggestion answers, on this run's own stream, with
    // a marker in every field that is the contact's: their words, their
    // name, their number, the excerpt they quoted.
    let mut inbound = inbound_message(&run.id, 1)?;
    inbound["data"]["body"] = json!("MARKER-INBOUND");
    inbound["data"]["contact"]["display_name"] = json!("MARKER-NAME");
    inbound["data"]["contact"]["network_identifier"] = json!("MARKER-NUMBER");
    inbound["data"]["reply_to"] = json!({
        "matrix_event_id": "$MARKER-quoted-event",
        "excerpt": "MARKER-EXCERPT",
    });
    let contact = inbound["subject"].as_str().unwrap().to_owned();
    assert_eq!(contact, CONTACT_MATRIX_ID);
    let room = inbound["source"]
        .as_str()
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap()
        .to_owned();
    assert!(
        room.starts_with('!'),
        "the source ends with the room id: {room}"
    );
    run.publish("inbound.message.received", &inbound).await?;

    // The suggestion that answers it: a marker in the body (which the post
    // must carry, once) and one in the rationale (which it must not).
    let body_marker = format!("MARKER-BODY-{}", run.id);
    let rationale_marker = format!("MARKER-RATIONALE-{}", run.id);
    let mut event = suggestion(&run.id, 2, 3600)?;
    event["data"]["trigger"]["event_id"] = inbound["id"].clone();
    event["data"]["suggestion"]["body"] = json!(format!("D'accord pour 20h ! {body_marker}"));
    event["data"]["rationale"] = json!(rationale_marker);
    let id = event["id"].as_str().unwrap().to_owned();
    run.publish("persona.suggest.produced", &event).await?;
    run.wait_for_post(&id).await?;
    // The activity line that follows the post is written after it; wait
    // for it too, so the search below reads everything the suggestion
    // caused and not only the first thing.
    run.wait_for_line(&run.channels.activity, "approbations")
        .await?;

    // Every byte the clerk could have written, on all three channels:
    // every event's content and every value of every tag.
    let mut written = String::new();
    for channel in [
        &run.channels.approvals,
        &run.channels.activity,
        &run.channels.journal,
    ] {
        for event in run.stack.all_events_in(channel).await? {
            written.push_str(&event.content);
            written.push('\n');
            for tag in event.tags.iter() {
                for value in tag.as_slice() {
                    written.push_str(value);
                    written.push('\n');
                }
            }
        }
    }

    assert_eq!(
        written.matches(&body_marker).count(),
        1,
        "the suggestion's body is on the relay exactly once, in the post:\n{written}"
    );
    for absent in [
        rationale_marker.as_str(),
        "MARKER-RATIONALE",
        "MARKER-INBOUND",
        "MARKER-NAME",
        "MARKER-NUMBER",
        "MARKER-EXCERPT",
        contact.as_str(),
        room.as_str(),
    ] {
        assert!(
            !written.contains(absent),
            "{absent:?} reached the relay; everything written was:\n{written}"
        );
    }

    run.shutdown().await
}

#[tokio::test]
async fn an_expired_suggestion_is_not_posted_and_is_counted() -> Result<()> {
    let run = Run::start("approbations-expired").await?;

    // Expired a second ago; then a live one, whose post proves the
    // consumer read past the expired one.
    let expired = suggestion(&run.id, 1, -1)?;
    let expired_id = expired["id"].as_str().unwrap().to_owned();
    run.publish("persona.suggest.produced", &expired).await?;
    let live = suggestion(&run.id, 2, 3600)?;
    run.publish("persona.suggest.produced", &live).await?;
    run.wait_for_post(live["id"].as_str().unwrap()).await?;

    let posts = run.posts_about(&expired_id).await?;
    assert!(
        posts.is_empty(),
        "an expired suggestion is not posted: {posts:?}"
    );
    run.assert_metric("twalk_clerk_skipped_total{why=\"expired\"} 1")
        .await?;
    run.assert_metric("twalk_clerk_posts_total{channel=\"approbations\"} 1")
        .await?;

    run.shutdown().await
}

#[tokio::test]
async fn a_post_a_relay_refused_while_its_database_was_down_lands_when_it_is_back() -> Result<()> {
    let mut run = Run::start("approbations-outage").await?;

    // First, that this run is healthy: one suggestion, one post. Without it a
    // failure below could be the stack rather than the outage under test.
    let warm = suggestion(&run.id, 1, 3600)?;
    run.publish("persona.suggest.produced", &warm).await?;
    run.wait_for_post(warm["id"].as_str().unwrap()).await?;

    // The relay's storage goes, and the relay stays up and answering: the shape
    // this stack took in an earlier run, and the shape that cost #308 a post —
    // a relay that is *down* is unreachable, which was always retried, and a
    // relay that answers a client error for its own outage was not.
    //
    // What it actually answers, measured here: `404 relay: no community is
    // configured for this host`. Its tenant lookup fails closed and names the
    // tenant rather than the lookup, so the refusal that reads most like "wrong
    // relay" is what a relay says when its database is gone. The clerk's rule
    // is written against that (`relay::SERVER_FAULT_REASONS`), and this test is
    // where the spelling came from — which is why it asserts the *property*,
    // that the post lands once, and not the status.
    let stopped = run.stack.stop_database().await?;
    let during = suggestion(&run.id, 2, 3600)?;
    let during_id = during["id"].as_str().unwrap().to_owned();
    let body = during["data"]["suggestion"]["body"]
        .as_str()
        .unwrap()
        .to_owned();
    run.publish("persona.suggest.produced", &during).await?;

    // The clerk tried, could not, and said so by counting it. The number is not
    // asserted exactly: it is the backoff's arithmetic against however long
    // Postgres takes to come back.
    let failures = run
        .wait_until_counter("twalk_clerk_relay_failures_total", 1)
        .await?;
    assert!(failures >= 1);

    // And it was a **refusal** that was retried, which is the rule under test
    // (#308) and not something the older behaviour would have passed: a relay
    // answering nothing would take the `Unreachable` path, transient long
    // before this ticket. So the clerk's own log is read for the refusal it
    // retried, with the relay's reason in it.
    run.clerk
        .wait_for_log("the relay could not be written to")
        .await?;
    let logs = run.clerk.logs().await;
    assert!(
        logs.contains("no community is configured for this host")
            || logs.contains("database error"),
        "the retried failure must be the relay's own refusal, with its reason; the log was:\n{logs}"
    );
    // Nothing given up on, either: a post acked as though the relay had judged
    // the request is the suggestion the owner never learns existed, and it
    // would show here.
    run.assert_metric_now("twalk_clerk_skipped_total{why=\"refused\"} 0")
        .await?;

    // Nothing was posted. Read from the clerk's own counter and not from the
    // relay: a relay with no storage cannot answer a query either, so a test
    // that asked it here would fail on the outage it had just created — which
    // is how this assertion was written the first time.
    run.assert_metric_now("twalk_clerk_posts_total{channel=\"approbations\"} 1")
        .await?;

    stopped.start().await?;

    // It lands, once, with the suggestion's own words in it — on a delivery the
    // bus made because the clerk refused to treat the outage as a verdict.
    let post = run
        .wait_for_post_within(&during_id, Duration::from_secs(90))
        .await?;
    assert!(
        post.content.contains(&body),
        "the post that landed carries the suggestion's body:\n{}",
        post.content
    );
    let posts = run.posts_about(&during_id).await?;
    assert_eq!(
        posts.len(),
        1,
        "the retries produce one post and not one per attempt: {posts:?}"
    );

    // Two posts in all, and nothing skipped: a post acked as though the relay
    // had judged the request is a suggestion the owner never learns existed,
    // and it would show up here as a count that stayed at one.
    run.assert_metric("twalk_clerk_posts_total{channel=\"approbations\"} 2")
        .await?;
    run.assert_metric_now("twalk_clerk_skipped_total{why=\"refused\"} 0")
        .await?;
    run.assert_metric_now("twalk_clerk_skipped_total{why=\"duplicate\"} 0")
        .await?;

    run.shutdown().await
}
