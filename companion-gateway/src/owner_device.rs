//! Whether this deployment can still act as the owner — read off the bus,
//! stored nowhere (issue #404, ADR 0041).
//!
//! # The fact, and why it had to cross
//!
//! The Sensor acts through a device of the owner's own account (#123, ADR
//! 0025), and that is what makes a reply to a bridged conversation reach the
//! contact: a mautrix bridge relays only what the logged-in user's own account
//! sends. #229 made a **revoked** device visible where it had been silent —
//! the Sensor reads `M_UNKNOWN_TOKEN` for what it is, refuses every reply to a
//! bridged conversation rather than posting one nobody receives, and the
//! refusal dead-letters with that sentence as its reason so the approval
//! screen reads it (#311). All of that is *after* the owner pressed the
//! button. What #229's own words asked for and its criteria did not is that
//! *"the Companion stops offering a delivery it can no longer perform"*, and
//! for that the fact has to cross from the Sensor, which is the only process
//! that knows, to this Gateway, which draws the screen.
//!
//! ADR 0041 argues the shape: a contract type on the bus,
//! `owner.device.state.changed.v1`, published by the Sensor at every
//! transition and at the start of every run, rather than this Gateway
//! scraping the Sensor's `/metrics` — an optional endpoint, an operator
//! surface rather than a contract, and the first dependency between these two
//! components that would not go through the bus.
//!
//! # What is kept, and what is deliberately not
//!
//! The last state and nothing else, **in memory**. There is no migration and
//! no row: the bus holds the last event on the subject, the consumer asks for
//! it at startup ([`async_nats::jetstream::consumer::DeliverPolicy::Last`]
//! on that one subject) and then follows live, and the Sensor republishes at
//! every start. A Gateway that has heard nothing answers [`None`] — *unknown*
//! — and the screen offers the button exactly as it did before #404, because
//! an absence must not read as a revocation. A durable consumer would buy
//! nothing here and cost a name to collide on: there is no transition to miss,
//! only a current state to hold.
//!
//! The consumer acts on `credential_gone` **alone**. `not_configured` is
//! carried by the contract and applied here so that "the Sensor said there is
//! no device" and "nothing has been heard" are two different answers rather
//! than one silence — but it does not change a portal's delivery. Every
//! deployment before #123 is in that state, and refusing every portal's reply
//! there is #123's own decision and not this ticket's.

use std::sync::{Arc, RwLock};

use anyhow::{Context, Result};
use futures::StreamExt;
use serde_json::Value;
use tracing::{debug, info, warn};

pub const OWNER_DEVICE_STATE_CHANGED_TYPE: &str = "fr.linagora.twalk.owner.device.state.changed.v1";

/// The three states the contract names (`data.to_state`), copied here and held
/// to the schema by the tests below.
pub const STATES: [&str; 3] = ["present", "credential_gone", "not_configured"];

/// How long the follower waits before reopening a consumer that failed, as the
/// collector's own consent follower waits.
const REOPEN_AFTER: std::time::Duration = std::time::Duration::from_secs(5);

/// What the Sensor says it holds. The contract's three words, and the third is
/// not a fault — see the module's own note on why only the second acts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceState {
    /// A usable device of the owner's account: a reply to a bridged
    /// conversation goes out as them.
    Present,
    /// The homeserver no longer knows its token — the owner revoked the
    /// device, or an admin did (#229).
    CredentialGone,
    /// None was ever given (#123): replies are posted by the Sensor's own
    /// account, which a mautrix bridge does not relay.
    NotConfigured,
}

impl DeviceState {
    /// The contract's own word for it.
    pub fn as_str(self) -> &'static str {
        match self {
            DeviceState::Present => "present",
            DeviceState::CredentialGone => "credential_gone",
            DeviceState::NotConfigured => "not_configured",
        }
    }

    /// `None` for a word this build does not know — which is refused as
    /// unreadable rather than folded into the nearest state it resembles.
    pub fn of(word: &str) -> Option<Self> {
        match word {
            "present" => Some(DeviceState::Present),
            "credential_gone" => Some(DeviceState::CredentialGone),
            "not_configured" => Some(DeviceState::NotConfigured),
            _ => None,
        }
    }
}

/// One transition, as the contract's `data` has it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    pub event_id: String,
    /// The account the device belongs to. Checked against the account this
    /// Gateway was configured with: the bus is one deployment's, but a
    /// misconfigured pair of components pointed at one bus would otherwise
    /// have this Gateway draw a screen from the other's credential.
    pub owner: String,
    pub device_id: Option<String>,
    pub to_state: DeviceState,
    pub occurred_at: String,
    // Deliberately no `from_state`: the contract's is the *Sensor's* previous
    // state, which is `unknown` on the first event of every run, and what a
    // transition is from here is what **this** Gateway last held.
    /// What puts it back, in the Sensor's own words, so that the screen and
    /// the log tell one situation one way. Bounded on the way in.
    pub remedy: Option<String>,
}

impl Change {
    /// Reads an `owner.device.state.changed.v1`. What the contract requires is
    /// required here; a state this build does not know is an error, so the
    /// follower skips the event rather than holding a word it cannot act on.
    pub fn parse(event: &Value) -> Result<Self> {
        anyhow::ensure!(
            event.get("type").and_then(Value::as_str) == Some(OWNER_DEVICE_STATE_CHANGED_TYPE),
            "not an owner.device.state.changed event"
        );
        let string = |pointer: &str| -> Result<String> {
            event
                .pointer(pointer)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .with_context(|| format!("the event has no string at {pointer}"))
        };
        let to_state = string("/data/to_state")?;
        let to_state = DeviceState::of(&to_state)
            .with_context(|| format!("the event names the unknown state {to_state:?}"))?;
        Ok(Self {
            event_id: string("/id")?,
            owner: string("/data/owner")?,
            device_id: event
                .pointer("/data/device_id")
                .and_then(Value::as_str)
                .map(str::to_owned),
            to_state,
            occurred_at: string("/data/occurred_at")?,
            remedy: event
                .pointer("/data/remedy")
                .and_then(Value::as_str)
                .map(|remedy| remedy.chars().take(1024).collect()),
        })
    }
}

/// The state itself, and what the deployment last heard about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Known {
    pub state: DeviceState,
    pub device_id: Option<String>,
    pub occurred_at: String,
    pub remedy: Option<String>,
}

/// The Gateway's one copy of the owner device's state: the account it belongs
/// to, configured, and the last thing the Sensor said about it, or nothing.
pub struct OwnerDeviceState {
    /// `GATEWAY_OWNER`, when the deployment names one. Without it nothing is
    /// applied at all — there is no account to check an event against, and the
    /// register already answers `no_owner_configured` for every room.
    owner: Option<String>,
    known: RwLock<Option<Known>>,
}

impl OwnerDeviceState {
    pub fn new(owner: Option<&str>) -> Self {
        Self {
            owner: owner
                .map(str::trim)
                .filter(|owner| !owner.is_empty())
                .map(str::to_owned),
            known: RwLock::new(None),
        }
    }

    /// The account this deployment acts as, as configuration names it
    /// (`GATEWAY_OWNER`). Read by the portal register rather than configured
    /// twice: the owner and their device are one setting, and a value read in
    /// two places is a value that drifts in one of them.
    pub fn owner(&self) -> Option<&str> {
        self.owner.as_deref()
    }

    /// What was last heard, or `None` for *unknown*.
    pub fn known(&self) -> Option<Known> {
        self.known.read().ok().and_then(|known| known.clone())
    }

    /// Whether this deployment is known to hold no usable device of the
    /// owner's account. `false` while nothing has been heard: the honest
    /// default, because an absence is not a revocation.
    pub fn credential_is_gone(&self) -> bool {
        self.known()
            .is_some_and(|known| known.state == DeviceState::CredentialGone)
    }

    /// Records a transition, or refuses it. `false` means the event was about
    /// another account, or this deployment names none.
    pub fn apply(&self, change: &Change) -> bool {
        let Some(owner) = &self.owner else {
            warn!(
                event = %change.event_id,
                "the owner device said something and GATEWAY_OWNER names nobody to check it \
                 against; ignored"
            );
            return false;
        };
        if &change.owner != owner {
            warn!(
                event = %change.event_id,
                said_about = %change.owner,
                configured = %owner,
                "an owner device event is about another account; ignored — two deployments \
                 sharing one bus is a misconfiguration, not a state to draw"
            );
            return false;
        }
        let was = self.known().map(|known| known.state);
        if let Ok(mut known) = self.known.write() {
            *known = Some(Known {
                state: change.to_state,
                device_id: change.device_id.clone(),
                occurred_at: change.occurred_at.clone(),
                remedy: change.remedy.clone(),
            });
        }
        let from = was.map_or("unknown", DeviceState::as_str);
        let device_id = change.device_id.as_deref().unwrap_or("none");
        if was == Some(change.to_state) {
            // The Sensor republishes its state at the start of every run, so a
            // Sensor restart says `present` again. Said once, quietly: it is
            // not a transition and a log that called it one would have an
            // operator looking for something that did not happen.
            debug!(
                state = change.to_state.as_str(),
                %device_id, "the owner device said its state again"
            );
        } else if change.to_state == DeviceState::CredentialGone {
            // The one state that changes an answer, so the one the Gateway's
            // own log names in full — with the Sensor's own remedy rather than
            // a second sentence about the same situation.
            warn!(
                %from,
                %device_id,
                occurred_at = %change.occurred_at,
                remedy = change.remedy.as_deref().unwrap_or("(none given)"),
                "this deployment no longer holds a device of the owner's account: no reply to a \
                 bridged conversation can be posted as them, and the approval screen says so \
                 before the button rather than after"
            );
        } else {
            info!(
                %from,
                to = change.to_state.as_str(),
                %device_id,
                "the owner device this deployment acts through changed state"
            );
        }
        true
    }
}

/// Never returns: asks the bus for the last thing said about the owner device
/// and then follows the subject for as long as the Gateway runs.
pub async fn follow_until_shutdown(state: Arc<OwnerDeviceState>, nats_url: String) {
    let subject = crate::consent::bus_subject(OWNER_DEVICE_STATE_CHANGED_TYPE);
    let client = match async_nats::ConnectOptions::new()
        .retry_on_initial_connect()
        .connect(&nats_url)
        .await
    {
        Ok(client) => client,
        Err(error) => {
            warn!(
                %error,
                "the owner device's state is not followed: the approval screen will keep \
                 offering a reply to a bridged conversation after the device it acts through \
                 has been revoked, as it did before #404"
            );
            return;
        }
    };
    let jetstream = async_nats::jetstream::new(client);
    info!(%subject, "following the owner device's state");
    loop {
        if let Err(error) = follow(&state, &jetstream, &subject).await {
            warn!(%error, "the owner device's state could not be followed; reopening");
        }
        tokio::time::sleep(REOPEN_AFTER).await;
    }
}

/// One consumer's life: the last event on the subject, then every next one.
///
/// Ephemeral, unacked and filtered to the one subject — `Last` with a filter
/// is the last message *matching it* — so a Gateway that has been down reads
/// the state and not the transitions it missed, which is all this holds.
async fn follow(
    state: &OwnerDeviceState,
    jetstream: &async_nats::jetstream::Context,
    subject: &str,
) -> Result<()> {
    let stream = jetstream
        .get_stream(crate::consent::STREAM_NAME)
        .await
        .context("failed to reach the bus stream")?;
    let consumer = stream
        .create_consumer(async_nats::jetstream::consumer::pull::Config {
            filter_subject: subject.to_owned(),
            ack_policy: async_nats::jetstream::consumer::AckPolicy::None,
            deliver_policy: async_nats::jetstream::consumer::DeliverPolicy::Last,
            ..Default::default()
        })
        .await
        .context("failed to create the owner device consumer")?;
    let mut messages = consumer
        .messages()
        .await
        .context("failed to open the owner device subject")?;
    while let Some(message) = messages.next().await {
        let message = match message {
            Ok(message) => message,
            Err(error) => {
                warn!(%error, "the owner device subject errored; continuing");
                continue;
            }
        };
        match serde_json::from_slice::<Value>(&message.payload)
            .context("not JSON")
            .and_then(|event| Change::parse(&event))
        {
            Ok(change) => {
                state.apply(&change);
            }
            Err(error) => {
                warn!(%error, "an owner device event could not be read; skipping it")
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const OWNER: &str = "@mmaudet:twalk.example.com";

    fn fixture() -> Value {
        serde_json::from_str(include_str!(
            "../../contracts/cloudevents/v1/fixtures/owner.device.state.changed.json"
        ))
        .unwrap()
    }

    #[test]
    fn the_contracts_fixture_is_read_and_an_unknown_state_is_refused() {
        let change = Change::parse(&fixture()).unwrap();
        assert_eq!(change.to_state, DeviceState::CredentialGone);
        assert_eq!(change.device_id.as_deref(), Some("EXAMPLEDEV1"));
        assert!(change.owner.starts_with('@'));
        assert!(change.remedy.unwrap().contains("onboarding again"));
        let mut odd = fixture();
        odd["data"]["to_state"] = json!("asleep");
        assert!(Change::parse(&odd).is_err());
        let mut other = fixture();
        other["type"] = json!("fr.linagora.twalk.bridge.status.changed.v1");
        assert!(Change::parse(&other).is_err());
    }

    /// Nothing heard is *unknown*, and unknown offers the button: the default
    /// is the behaviour before #404 and not a refusal.
    #[test]
    fn a_gateway_that_has_heard_nothing_says_the_credential_is_not_gone() {
        let state = OwnerDeviceState::new(Some(OWNER));
        assert!(state.known().is_none());
        assert!(!state.credential_is_gone());
    }

    #[test]
    fn a_revocation_is_held_and_a_handover_clears_it() {
        let state = OwnerDeviceState::new(Some(OWNER));
        let mut gone = fixture();
        gone["data"]["owner"] = json!(OWNER);
        assert!(state.apply(&Change::parse(&gone).unwrap()));
        assert!(state.credential_is_gone());
        assert_eq!(
            state.known().unwrap().device_id.as_deref(),
            Some("EXAMPLEDEV1")
        );
        // Re-provisioning, or a handover (#228): the Sensor says `present`
        // and the register stops refusing, with nothing reloaded.
        let mut back = fixture();
        back["data"]["owner"] = json!(OWNER);
        back["data"]["from_state"] = json!("credential_gone");
        back["data"]["to_state"] = json!("present");
        back["data"]["device_id"] = json!("NEWDEVICE1");
        back["data"].as_object_mut().unwrap().remove("remedy");
        assert!(state.apply(&Change::parse(&back).unwrap()));
        assert!(!state.credential_is_gone());
        let known = state.known().unwrap();
        assert_eq!(known.state, DeviceState::Present);
        assert_eq!(known.device_id.as_deref(), Some("NEWDEVICE1"));
        assert!(known.remedy.is_none());
    }

    /// `not_configured` is held and does not make the credential gone: the
    /// module's note on why is the argument, and this is the assertion.
    #[test]
    fn no_device_configured_is_heard_and_is_not_a_revocation() {
        let state = OwnerDeviceState::new(Some(OWNER));
        let mut none = fixture();
        none["data"]["owner"] = json!(OWNER);
        none["data"]["to_state"] = json!("not_configured");
        none["data"].as_object_mut().unwrap().remove("device_id");
        assert!(state.apply(&Change::parse(&none).unwrap()));
        assert_eq!(state.known().unwrap().state, DeviceState::NotConfigured);
        assert!(!state.credential_is_gone());
    }

    #[test]
    fn a_state_about_another_account_is_refused() {
        let state = OwnerDeviceState::new(Some(OWNER));
        let mut theirs = fixture();
        theirs["data"]["owner"] = json!("@someone:elsewhere.example.com");
        assert!(!state.apply(&Change::parse(&theirs).unwrap()));
        assert!(state.known().is_none());
        // And a deployment naming no owner applies nothing at all.
        let nobody = OwnerDeviceState::new(None);
        let mut mine = fixture();
        mine["data"]["owner"] = json!(OWNER);
        assert!(!nobody.apply(&Change::parse(&mine).unwrap()));
    }

    #[test]
    fn the_three_states_are_the_contracts() {
        let schema: Value = serde_json::from_str(include_str!(
            "../../contracts/cloudevents/v1/owner.device.state.changed.schema.json"
        ))
        .unwrap();
        let contract: Vec<&str> = schema["properties"]["data"]["properties"]["to_state"]["enum"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert_eq!(contract, STATES.to_vec());
        assert_eq!(
            schema["properties"]["type"]["const"].as_str(),
            Some(OWNER_DEVICE_STATE_CHANGED_TYPE)
        );
        // Every word this build knows is one the contract names, and the
        // other way round.
        for state in STATES {
            assert_eq!(DeviceState::of(state).unwrap().as_str(), state);
        }
    }
}
