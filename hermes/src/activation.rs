//! Persona activation: the user's decision that a persona may read a given
//! network, recorded as a consent decision on that persona and nothing else
//! (ADR 0013).
//!
//! Two things follow from that ADR, and they are the whole of this module.
//!
//! **The runtime learns activation from the Companion Gateway's snapshot, then
//! follows the bus.** It reads `GET /api/consent/snapshot` with its service
//! token, applies the `persona` entries it carries, and follows
//! `consent.state.changed` from the sequence that document names — the shape the
//! Sensor has used for the same question since ADR 0010. Nothing is activated by
//! default: a persona nobody decided about is paused, because activation never
//! spreads on its own.
//!
//! It used to replay the stream from the beginning and read no snapshot, on the
//! argument that persona decisions are a handful over a deployment's life. That
//! argument was about *volume* and the defect was about *time* (#312): ADR 0037
//! gave the stream a ninety-day retention, so an activation decided before that
//! window is gone from the stream, and a runtime restarted afterwards saw no
//! activation at all — every persona paused, and nothing saying why. A silence
//! that looks like a working deployment is this project's signature failure, and
//! here it was manufactured by a retention policy that is otherwise right. The
//! replay is kept as the **fallback** for a Gateway that does not answer, which
//! is the Sensor's shape too: a deployment with no Gateway configured has no
//! snapshot to read and the stream is all there is.
//!
//! **A paused persona still runs, and receives nothing.** So the thing
//! activation moves cannot be the process. It is the persona's durable
//! consumer, which the runtime owns: an active persona's consumer is
//! filtered to `inbound.message.received`, and a paused one's is filtered
//! to [`paused_subject`] — a subject inside the stream that no producer in
//! Twalk ever publishes on. The persona process stays up, stays connected,
//! keeps pulling, and is handed nothing. That is ADR 0013 rendered as a
//! consumer configuration rather than as a kill.
//!
//! One consequence is deliberate and worth stating: messages that arrive
//! while a persona is paused are not replayed to it when it is activated
//! again. The user paused it; the messages of the pause are not its
//! business afterwards either.

use std::collections::HashMap;

use serde_json::Value;

pub const CONSENT_CHANGED_TYPE: &str = "fr.linagora.twalk.consent.state.changed.v1";
pub const MESSAGE_RECEIVED_TYPE: &str = "fr.linagora.twalk.inbound.message.received.v1";

/// The contract's consent states, as they appear in `data.new_state`.
pub const GRANTED: &str = "granted";

/// The subject a paused persona's consumer is filtered to.
///
/// It is inside the deployment's namespace, so JetStream accepts it as a
/// filter on the stream, and it is not a contract event type, so nothing
/// publishes there — ever. A consumer filtered to it is a consumer that
/// receives nothing, which is exactly what ADR 0013 asks for, without
/// stopping the process and without the runtime standing between the
/// persona and the bus.
pub fn paused_subject(subject_prefix: &str, persona_id: &str) -> String {
    format!("{subject_prefix}.hermes.paused.{persona_id}")
}

/// One recorded decision about one persona.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersonaDecision {
    pub persona_id: String,
    /// The networks the decision applies to (the contract's
    /// `data.scope.networks`).
    pub networks: Vec<String>,
    /// `data.new_state`, verbatim: an unknown label is not `granted`, and
    /// that is all this module needs to know.
    pub new_state: String,
}

impl PersonaDecision {
    /// Reads a `consent.state.changed` event, if it is one and if it is
    /// about a persona.
    ///
    /// `None` for a contact's or a network's decision — the same stream
    /// carries all three — and for anything malformed, because a runtime
    /// that guessed at a decision it could not read would be guessing about
    /// consent.
    pub fn parse(event: &Value) -> Option<Self> {
        if event.get("type").and_then(Value::as_str)? != CONSENT_CHANGED_TYPE {
            return None;
        }
        let data = event.get("data")?;
        let subject = data.get("subject")?;
        if subject.get("type").and_then(Value::as_str)? != "persona" {
            return None;
        }
        let networks = data
            .get("scope")?
            .get("networks")?
            .as_array()?
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect::<Vec<_>>();
        if networks.is_empty() {
            return None;
        }
        Some(Self {
            persona_id: subject.get("id").and_then(Value::as_str)?.to_owned(),
            networks,
            new_state: data.get("new_state").and_then(Value::as_str)?.to_owned(),
        })
    }
}

/// The persona decisions one Companion Gateway snapshot carries, and the stream
/// position they reflect (#312).
///
/// The document's shape is `companion-gateway/openapi.yaml`'s `ConsentSnapshot`:
/// one entry per (subject, **connection**), each carrying the connection's
/// `network`, the state in force and the journal position it was decided at. A
/// persona granted on two networks is therefore two entries.
///
/// The entries are applied **in the order they were decided** (`decision_sequence`)
/// and not in the order the document lists them, which is by connection id. That is
/// not a nicety: a deployment can hold two connections of one network (ADR 0033
/// says so in as many words), so two entries can carry the same `network` with
/// different states, and [`Activation`] keeps the last one applied per network. Left
/// in document order, whether a persona booted active would depend on the alphabet
/// — `alpha-wa` revoked last week beating `zulu-wa` granted today — and the runtime
/// would disagree with what replaying the stream gives, which is the one thing these
/// two paths must never do.
///
/// Read here rather than through `twalk-consent-cache`, which parses the same
/// document for the Sensor: that crate **refuses** a `persona` entry on purpose
/// (`Unusable::NotAboutASender`), because its job is to label senders. Reading the
/// entries it refuses through it would be reading against its grain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    pub decisions: Vec<PersonaDecision>,
    /// Where to start the stream consumer after applying `decisions`: the
    /// document's own `next_stream_sequence`, **never** computed here.
    ///
    /// The contract spells that number out and says why — "left to the client to
    /// compute, because that off-by-one would silently skip or re-apply one
    /// decision" — and `twalk-consent-cache` refuses a document without it for the
    /// same reason. It happens to be `stream_sequence + 1` today; adding one here
    /// would be this runtime deciding that, which is exactly what the field exists
    /// to stop.
    pub follow_from: u64,
}

impl Snapshot {
    /// Reads a snapshot document, or `None` when it does not say where to follow
    /// the stream from.
    ///
    /// A document with no `next_stream_sequence` is **not** read as "from the
    /// beginning": that would apply every decision the stream still holds on top of
    /// entries that already reflect them, which is the double-apply the field
    /// exists to prevent. The caller treats it as a Gateway that did not answer —
    /// replay, and say so — because that is honest about what is known.
    ///
    /// An `entries` member this runtime cannot read is a different matter: it is
    /// left out and the rest applied, because a document that lost one row is not a
    /// reason to pause every persona, which is the defect this whole path closes.
    pub fn read(document: &Value) -> Option<Self> {
        let follow_from = document
            .get("next_stream_sequence")
            .and_then(Value::as_u64)
            .filter(|sequence| *sequence >= 1)?;
        let mut decided: Vec<(u64, PersonaDecision)> = document
            .get("entries")
            .and_then(Value::as_array)
            .map(|entries| entries.iter().filter_map(Self::decision).collect())
            .unwrap_or_default();
        // Stable, so entries decided at the same position keep the document's own
        // order; by position, so the most recent decision is the last applied.
        decided.sort_by_key(|(sequence, _)| *sequence);
        Some(Self {
            decisions: decided.into_iter().map(|(_, decision)| decision).collect(),
            follow_from,
        })
    }

    /// One `ConsentStateEntry` as a decision about one persona on one network, with
    /// the journal position it was decided at — or `None` when it is about anything
    /// else.
    ///
    /// A missing `decision_sequence` sorts as `0`, which puts such an entry before
    /// every entry that names one: an entry whose position is unknown must not be
    /// allowed to overwrite one whose position is known.
    fn decision(entry: &Value) -> Option<(u64, PersonaDecision)> {
        let subject = entry.get("subject")?;
        if subject.get("type").and_then(Value::as_str)? != "persona" {
            return None;
        }
        let network = entry
            .get("network")
            .and_then(Value::as_str)
            .filter(|network| !network.is_empty())?;
        let decided_at = entry
            .get("decision_sequence")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        Some((
            decided_at,
            PersonaDecision {
                persona_id: subject.get("id").and_then(Value::as_str)?.to_owned(),
                networks: vec![network.to_owned()],
                new_state: entry.get("state").and_then(Value::as_str)?.to_owned(),
            },
        ))
    }
}

/// Where the activation a runtime starts with came from, and where the stream is
/// followed from afterwards (#312).
///
/// Here rather than in the binary because both are decisions: which position to
/// follow from, and what to tell an operator it was read from. The binary turns the
/// first into a JetStream `DeliverPolicy` and does no arithmetic on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadFrom {
    /// The Companion Gateway's consent snapshot: how many persona decisions it
    /// carried, and the position **it** named to follow from.
    Snapshot { decisions: usize, follow_from: u64 },
    /// Nothing but the stream — no Gateway configured, or one that did not answer,
    /// or a document that named no position. What the runtime did before #312, and
    /// what it can still only do for a decision the stream still holds.
    TheStreamAlone,
}

impl ReadFrom {
    /// The sequence to follow the consent subject from, or `None` for the whole
    /// stream.
    ///
    /// Never `follow_from + 1`: the document's `next_stream_sequence` **is** where to
    /// start, spelled out by the Gateway so that no consumer computes that
    /// off-by-one and silently skips or re-applies one decision.
    pub fn follow_from(self) -> Option<u64> {
        match self {
            Self::Snapshot { follow_from, .. } => Some(follow_from),
            Self::TheStreamAlone => None,
        }
    }

    /// How many decisions the snapshot carried.
    pub fn decisions(self) -> usize {
        match self {
            Self::Snapshot { decisions, .. } => decisions,
            Self::TheStreamAlone => 0,
        }
    }

    /// What an operator is told the activation was read from.
    pub fn source(self) -> &'static str {
        match self {
            Self::Snapshot { .. } => "the Companion Gateway's consent snapshot",
            Self::TheStreamAlone => "the stream alone",
        }
    }

    /// Where the stream is followed from, in the words a log line can use.
    ///
    /// Not a number in the fallback: `DeliverPolicy::All` starts at whatever the
    /// stream's oldest surviving sequence happens to be, which on a stream with a
    /// ninety-day retention is not `1` — and inventing `1` in the one path this
    /// whole ticket is about would be a log line stating a falsehood.
    pub fn following_from(self) -> String {
        match self {
            Self::Snapshot { follow_from, .. } => format!("sequence {follow_from}"),
            Self::TheStreamAlone => "the beginning of the stream".to_owned(),
        }
    }
}

/// What the runtime has learned from the consent stream so far: the last
/// decision per (persona, network).
#[derive(Debug, Default, Clone)]
pub struct Activation {
    states: HashMap<String, HashMap<String, String>>,
}

impl Activation {
    pub fn new() -> Self {
        Self::default()
    }

    /// Applies one decision. Last writer wins per network, which is what
    /// stream order means: the events arrive in the order the user took the
    /// decisions.
    pub fn apply(&mut self, decision: &PersonaDecision) {
        let per_network = self.states.entry(decision.persona_id.clone()).or_default();
        for network in &decision.networks {
            per_network.insert(network.clone(), decision.new_state.clone());
        }
    }

    /// Whether this persona may be handed events at all.
    ///
    /// Active means "granted on at least one network". The runtime's
    /// enforcement is necessarily this coarse: a bus subject carries no
    /// network, so a consumer cannot be filtered to one. Per-network
    /// scoping is a consumer-side decision like the SDK's consent gate, and
    /// it is not enforced here — see `hermes/README.md`.
    pub fn is_active(&self, persona_id: &str) -> bool {
        self.networks_granted(persona_id).next().is_some()
    }

    /// Whether any decision about this persona has been applied at all.
    ///
    /// The distinction ADR 0010 protects — "an absent subject means 'no decision',
    /// never 'revoked'" — and the reason a paused persona's log line can say which of
    /// the two it is instead of telling an owner who paused it to go and activate it.
    pub fn decided_about(&self, persona_id: &str) -> bool {
        self.states
            .get(persona_id)
            .is_some_and(|per_network| !per_network.is_empty())
    }

    /// The networks this persona is activated on, sorted: what an operator
    /// reads in the runtime's logs.
    pub fn granted_networks(&self, persona_id: &str) -> Vec<String> {
        let mut networks = self
            .networks_granted(persona_id)
            .map(str::to_owned)
            .collect::<Vec<_>>();
        networks.sort();
        networks
    }

    fn networks_granted<'a>(&'a self, persona_id: &str) -> impl Iterator<Item = &'a str> {
        self.states
            .get(persona_id)
            .into_iter()
            .flat_map(|per_network| {
                per_network
                    .iter()
                    .filter(|(_, state)| state.as_str() == GRANTED)
                    .map(|(network, _)| network.as_str())
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn decision(subject_type: &str, id: &str, state: &str, networks: &[&str]) -> Value {
        json!({
            "specversion": "1.0",
            "id": "0".repeat(64),
            "source": "gateway://example.com/consent",
            "type": CONSENT_CHANGED_TYPE,
            "time": "2026-09-17T10:05:00Z",
            "subject": id,
            "datacontenttype": "application/json",
            "data": {
                "subject": { "type": subject_type, "id": id },
                "old_state": "unset",
                "new_state": state,
                "scope": { "networks": networks },
                "occurred_at": "2026-09-17T10:05:00Z",
            }
        })
    }

    /// The snapshot document the runtime now starts from (#312).
    #[test]
    fn a_snapshot_is_read_as_one_decision_per_network_and_the_rest_is_left_out() {
        let document = json!({
            // The two the contract carries, and the one this runtime reads: the
            // position is `next_stream_sequence`, spelled out by the Gateway so no
            // consumer computes the off-by-one itself.
            "stream_sequence": 4_812,
            "next_stream_sequence": 4_813,
            "owner_identities": ["@michel:example.com"],
            "entries": [
                // A persona granted on two networks: two entries, because the
                // document is keyed by (subject, connection).
                {
                    "subject": { "type": "persona", "id": "assistant" },
                    "connection": "whatsapp",
                    "network": "whatsapp",
                    "state": "granted",
                    "decided_at": "2026-06-01T09:00:00Z",
                    "decision_sequence": 12
                },
                {
                    "subject": { "type": "persona", "id": "assistant" },
                    "connection": "signal",
                    "network": "signal",
                    "state": "revoked",
                    "decided_at": "2026-06-02T09:00:00Z",
                    "decision_sequence": 13
                },
                // Everything else in the same document: a contact's decision and
                // a network default, which are the Sensor's business and not this
                // runtime's.
                {
                    "subject": { "type": "contact", "id": "@alice:example.org" },
                    "connection": "whatsapp",
                    "network": "whatsapp",
                    "state": "granted",
                    "decided_at": "2026-06-03T09:00:00Z",
                    "decision_sequence": 14
                },
                {
                    "subject": { "type": "network", "id": "signal" },
                    "connection": "signal",
                    "network": "signal",
                    "state": "revoked",
                    "decided_at": "2026-06-04T09:00:00Z",
                    "decision_sequence": 15
                },
            ]
        });

        let snapshot = Snapshot::read(&document).expect("the document names a position");

        assert_eq!(
            snapshot.follow_from, 4_813,
            "the document's own next_stream_sequence, not stream_sequence + 1 computed here"
        );
        assert_eq!(
            snapshot.decisions,
            vec![
                PersonaDecision {
                    persona_id: "assistant".to_owned(),
                    networks: vec!["whatsapp".to_owned()],
                    new_state: "granted".to_owned(),
                },
                PersonaDecision {
                    persona_id: "assistant".to_owned(),
                    networks: vec!["signal".to_owned()],
                    new_state: "revoked".to_owned(),
                },
            ]
        );

        // And applied, they say what an activation decided months ago says: this
        // persona reads WhatsApp and does not read Signal — which is the whole
        // point, since the decisions themselves are long gone from the stream.
        let mut activation = Activation::new();
        for decision in &snapshot.decisions {
            activation.apply(decision);
        }
        assert!(activation.is_active("assistant"));
        assert_eq!(activation.granted_networks("assistant"), ["whatsapp"]);
    }

    /// Where the stream is followed from, and what an operator is told (#312).
    #[test]
    fn the_position_followed_from_is_the_documents_own_and_never_computed() {
        let from_snapshot = ReadFrom::Snapshot {
            decisions: 2,
            follow_from: 4_813,
        };
        assert_eq!(
            from_snapshot.follow_from(),
            Some(4_813),
            "the document's next_stream_sequence, not one more than its stream_sequence"
        );
        assert_eq!(from_snapshot.decisions(), 2);
        assert_eq!(from_snapshot.following_from(), "sequence 4813");
        assert!(from_snapshot.source().contains("consent snapshot"));

        // The fallback names no number: `DeliverPolicy::All` starts at whatever the
        // stream's oldest surviving sequence is, which on a stream with a ninety-day
        // retention is not 1 — and this is the one path the ticket is about.
        let fallback = ReadFrom::TheStreamAlone;
        assert_eq!(fallback.follow_from(), None);
        assert_eq!(fallback.decisions(), 0);
        assert_eq!(fallback.following_from(), "the beginning of the stream");
        assert_eq!(fallback.source(), "the stream alone");
    }

    /// A paused persona's reason is one of two, and they are not the same fact
    /// (#312, ADR 0010).
    #[test]
    fn a_revoked_persona_is_not_a_persona_nobody_decided_about() {
        let mut activation = Activation::new();
        assert!(
            !activation.decided_about("assistant"),
            "nobody has decided: activation never spreads on its own"
        );

        activation.apply(&PersonaDecision {
            persona_id: "assistant".to_owned(),
            networks: vec!["whatsapp".to_owned()],
            new_state: "revoked".to_owned(),
        });
        assert!(!activation.is_active("assistant"));
        assert!(
            activation.decided_about("assistant"),
            "the owner paused it, which is a decision and not an absence — telling them to \
             activate it would be telling them to undo what they just did"
        );
    }

    /// Two connections of one network are two decisions, and the most recent one is
    /// the one that holds (#312).
    ///
    /// The scenario is a deployment's, not a fixture's: ADR 0033 allows two
    /// connections of the same kind, the document lists entries by connection id, and
    /// nothing says the alphabet agrees with the calendar.
    #[test]
    fn the_most_recently_decided_entry_wins_and_not_the_one_listed_last() {
        let entry = |connection: &str, state: &str, decided_at: u64| {
            json!({
                "subject": { "type": "persona", "id": "assistant" },
                "connection": connection,
                "network": "whatsapp",
                "state": state,
                "decided_at": "2026-06-01T09:00:00Z",
                "decision_sequence": decided_at
            })
        };
        // As the snapshot lists them: by connection id. The revocation is older and
        // comes first; the grant is this week's and comes second.
        let in_document_order = Snapshot::read(&json!({
            "next_stream_sequence": 40,
            "entries": [entry("alpha-wa", "revoked", 10), entry("zulu-wa", "granted", 30)]
        }))
        .expect("a position");
        // And the same deployment with the ids the other way round, which is the
        // only difference: the grant is now listed first and is still the newer.
        let reversed = Snapshot::read(&json!({
            "next_stream_sequence": 40,
            "entries": [entry("alpha-wa", "granted", 30), entry("zulu-wa", "revoked", 10)]
        }))
        .expect("a position");

        for snapshot in [in_document_order, reversed] {
            let mut activation = Activation::new();
            for decision in &snapshot.decisions {
                activation.apply(decision);
            }
            assert!(
                activation.is_active("assistant"),
                "the newer decision holds whichever order the document listed it in: {:?}",
                snapshot.decisions
            );
        }
    }

    /// A document that lost a member pauses nothing (#312).
    #[test]
    fn an_unreadable_entry_is_left_out_and_the_rest_is_applied() {
        let snapshot = Snapshot::read(&json!({
            "next_stream_sequence": 9,
            "entries": [
                { "subject": { "type": "persona" }, "network": "whatsapp", "state": "granted" },
                { "subject": { "type": "persona", "id": "assistant" }, "state": "granted" },
                { "subject": { "type": "persona", "id": "assistant" }, "network": "", "state": "granted" },
                { "subject": { "type": "persona", "id": "scribe" }, "network": "signal", "state": "granted" },
            ]
        }))
        .expect("the document names a position");

        assert_eq!(
            snapshot.decisions,
            vec![PersonaDecision {
                persona_id: "scribe".to_owned(),
                networks: vec!["signal".to_owned()],
                new_state: "granted".to_owned(),
            }],
            "the readable entry is applied and the rest left out: pausing every \
             persona over one missing member is the defect this path closes"
        );
        assert_eq!(snapshot.follow_from, 9);

        // A document that names **no** position is not read at all. Reading it as
        // "from the beginning" would apply every decision the stream still holds on
        // top of entries that already reflect them — the double-apply the contract
        // spells the field out to prevent — so the caller treats it as a Gateway
        // that did not answer, replays, and says so.
        assert_eq!(Snapshot::read(&json!({})), None);
        assert_eq!(
            Snapshot::read(&json!({ "stream_sequence": 12, "entries": [] })),
            None,
            "stream_sequence alone is not the position to follow from"
        );
        assert_eq!(Snapshot::read(&json!({ "next_stream_sequence": 0 })), None);
    }

    #[test]
    fn a_persona_decision_is_read_and_a_contacts_is_not() {
        let parsed = PersonaDecision::parse(&decision(
            "persona",
            "assistant",
            "granted",
            &["whatsapp", "signal"],
        ))
        .expect("a persona decision parses");
        assert_eq!(
            parsed,
            PersonaDecision {
                persona_id: "assistant".to_owned(),
                networks: vec!["whatsapp".to_owned(), "signal".to_owned()],
                new_state: "granted".to_owned(),
            }
        );
        assert_eq!(
            PersonaDecision::parse(&decision(
                "contact",
                "@whatsapp_33612345678:example.com",
                "granted",
                &["whatsapp"]
            )),
            None,
            "a contact's decision is on the same stream and is not activation"
        );
        assert_eq!(
            PersonaDecision::parse(&decision("network", "whatsapp", "granted", &["whatsapp"])),
            None
        );
    }

    #[test]
    fn an_event_that_is_not_a_consent_decision_is_not_one() {
        let mut other = decision("persona", "assistant", "granted", &["whatsapp"]);
        other["type"] = json!(MESSAGE_RECEIVED_TYPE);
        assert_eq!(PersonaDecision::parse(&other), None);
        assert_eq!(PersonaDecision::parse(&json!({})), None);
        assert_eq!(PersonaDecision::parse(&json!("not an object")), None);
    }

    #[test]
    fn a_persona_nobody_decided_about_is_paused() {
        let activation = Activation::new();
        assert!(
            !activation.is_active("assistant"),
            "activation never spreads on its own (ADR 0013)"
        );
        assert!(activation.granted_networks("assistant").is_empty());
    }

    #[test]
    fn the_last_decision_per_network_wins() {
        let mut activation = Activation::new();
        for event in [
            decision("persona", "assistant", "granted", &["whatsapp", "signal"]),
            decision("persona", "assistant", "revoked", &["signal"]),
        ] {
            activation.apply(&PersonaDecision::parse(&event).expect("a persona decision"));
        }
        assert!(activation.is_active("assistant"));
        assert_eq!(
            activation.granted_networks("assistant"),
            vec!["whatsapp".to_owned()]
        );

        activation.apply(
            &PersonaDecision::parse(&decision("persona", "assistant", "revoked", &["whatsapp"]))
                .expect("a persona decision"),
        );
        assert!(
            !activation.is_active("assistant"),
            "a persona revoked on every network it had is paused"
        );
    }

    #[test]
    fn one_personas_decision_says_nothing_about_another() {
        let mut activation = Activation::new();
        activation.apply(
            &PersonaDecision::parse(&decision("persona", "assistant", "granted", &["whatsapp"]))
                .expect("a persona decision"),
        );
        assert!(activation.is_active("assistant"));
        assert!(!activation.is_active("watch"));
    }

    #[test]
    fn a_paused_personas_subject_is_inside_the_stream_and_is_no_contract_type() {
        let subject = paused_subject("twalk", "assistant");
        assert_eq!(subject, "twalk.hermes.paused.assistant");
        assert!(
            subject.starts_with("twalk."),
            "the filter has to overlap the stream's subjects"
        );
        assert!(
            !subject.contains(".inbound.")
                && !subject.contains(".outbound.")
                && !subject.contains(".persona.")
                && !subject.contains(".consent.")
                && !subject.contains(".bridge."),
            "nothing may ever publish there: {subject}"
        );
    }
}
