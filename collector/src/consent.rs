//! The collector's consent state (issue #280): the shared cache
//! (`twalk-consent-cache`, #273) fed the Sensor's way — the Companion
//! Companion Gateway's snapshot first, then the `consent.state.changed` stream from
//! the sequence the snapshot hands over (ADR 0010). What the collector reads
//! it for is one question: is this `mailto:` revoked on the mail connection?
//! — the participant rule of `definitions/calendar-event.schema.json`.
//!
//! The consumer is not durable: the snapshot is the record, and a restart
//! re-reads it and starts the stream again from where it says. A deployment
//! with no Companion Gateway has no snapshot and no decisions, and the cache stays
//! empty: nobody is withheld, because nobody was ever decided about.

use anyhow::{Context, Result};
use futures::StreamExt;
use serde_json::Value;
use tracing::{info, warn};
use twalk_consent_cache::{ConsentCache, ConsentChange, Snapshot, CONSENT_CHANGED_TYPE};

/// The cache this collector reads, knowing the owner by **every address they
/// hold** (#322).
///
/// The owner has no consent state (ADR 0021): a decision about one of their own
/// addresses — from the snapshot or from the stream — never enters the cache, and
/// the cache is what enforces that, from the identities it is given. Given one
/// address, a decision about the owner's alias was recorded like a contact's, and
/// the participant rule would then have withheld the owner from their own meeting.
///
/// Their identities here are `mailto:` subjects, because that is how every mail and
/// every calendar event spells them and the collector has no Matrix ID to name them
/// by.
pub fn cache_for(owner: &crate::owner::Owner) -> ConsentCache {
    let mut theirs = owner.mailtos();
    let primary = theirs
        .next()
        .expect("an owner always has the address they are named by");
    ConsentCache::for_people_only(
        Some(twalk_consent_cache::owner::Owner::new(primary, theirs)),
        twalk_consent_cache::bridge_bot::BridgeBots::default(),
    )
}

/// The cache, filled from the Companion Gateway's snapshot document (the same one the
/// registry is read off), and a task that keeps it current off the bus.
pub async fn follow(
    jetstream: async_nats::jetstream::Context,
    snapshot_document: Option<&Value>,
    owner: &crate::owner::Owner,
) -> Result<ConsentCache> {
    let cache = cache_for(owner);
    let Some(document) = snapshot_document else {
        info!("no Companion Gateway: no consent decisions, nobody withheld");
        return Ok(cache);
    };
    let snapshot = Snapshot::parse(document).context("the consent snapshot cannot be read")?;
    for why in &snapshot.unusable {
        warn!(reason = ?why, "a consent entry was not applied: {}", why.explained());
    }
    cache.apply_snapshot(&snapshot);
    info!(
        entries = snapshot.entries.len(),
        from_sequence = snapshot.next_stream_sequence,
        "consent snapshot applied; following the stream"
    );
    let stream_cache = cache.clone();
    let start = snapshot.next_stream_sequence;
    tokio::spawn(async move {
        loop {
            match consume(&jetstream, &stream_cache, start).await {
                Ok(()) => warn!("the consent stream ended; reopening it"),
                Err(error) => warn!(%error, "the consent consumer failed; reopening it"),
            }
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
    });
    Ok(cache)
}

async fn consume(
    jetstream: &async_nats::jetstream::Context,
    cache: &ConsentCache,
    start_sequence: u64,
) -> Result<()> {
    let stream = jetstream
        .get_stream("twalk")
        .await
        .context("failed to get the twalk stream")?;
    let consumer = stream
        .create_consumer(async_nats::jetstream::consumer::pull::Config {
            filter_subject: crate::status::bus_subject(CONSENT_CHANGED_TYPE),
            ack_policy: async_nats::jetstream::consumer::AckPolicy::None,
            deliver_policy: async_nats::jetstream::consumer::DeliverPolicy::ByStartSequence {
                start_sequence,
            },
            ..Default::default()
        })
        .await
        .context("failed to create the consent consumer")?;
    let mut messages = consumer
        .messages()
        .await
        .context("failed to open the consent stream")?;
    while let Some(message) = messages.next().await {
        let message = match message {
            Ok(message) => message,
            Err(error) => {
                warn!(%error, "consent stream error, continuing");
                continue;
            }
        };
        let Ok(event) = serde_json::from_slice::<Value>(&message.payload) else {
            warn!("a consent.state.changed payload is not JSON; skipped");
            continue;
        };
        match ConsentChange::parse(&event) {
            Ok(change) => {
                cache.apply(&change);
                info!(
                    subject = change.subject_label(),
                    state = change.new_state.as_str(),
                    connections = ?change.connections,
                    "applied a consent change"
                );
            }
            Err(why) => {
                warn!(reason = ?why, "a consent change was not applied: {}", why.explained())
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRIMARY: &str = "mmaudet@linagora.com";
    const ALIAS: &str = "michel.maudet@linagora.com";
    const CONNECTION: &str = "mail-linagora";

    /// A decision about an address of the owner's is refused the way a decision
    /// about the owner is — for every address they hold (#322).
    #[test]
    fn no_decision_about_the_owner_enters_the_cache_whichever_address_it_names() {
        let revoking = |subject: &str| {
            serde_json::json!({
                "specversion": "1.0",
                "type": CONSENT_CHANGED_TYPE,
                "source": "https://gateway.example/",
                "id": "decision-1",
                "subject": subject,
                "time": "2026-09-27T20:00:00Z",
                "data": {
                    "subject": { "type": "contact", "id": subject },
                    "new_state": "revoked",
                    "scope": { "connections": [CONNECTION] },
                },
            })
        };
        let cache = cache_for(&crate::owner::Owner::new(PRIMARY, [ALIAS]));

        for address in [PRIMARY, ALIAS] {
            let subject = format!("mailto:{address}");
            let change = ConsentChange::parse(&revoking(&subject))
                .expect("the fixture is a consent decision");
            cache.apply(&change);
            assert_eq!(
                cache.state(&subject, CONNECTION),
                twalk_consent_cache::Consent::Pending,
                "a decision about {address} is the owner's own and is refused: with it recorded, \
                 the participant rule would withhold the owner from their own meeting"
            );
        }

        // And a contact is decided about exactly as before.
        let subject = "mailto:alice@example.org";
        let change = ConsentChange::parse(&revoking(subject)).expect("a decision");
        cache.apply(&change);
        assert_eq!(
            cache.state(subject, CONNECTION),
            twalk_consent_cache::Consent::Revoked
        );
    }
}
