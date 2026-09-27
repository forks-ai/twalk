//! The owner's own device: the identity Twalk **acts** as, beside the identity
//! it observes with (ADR 0025, ADR 0034, issue #123).
//!
//! A mautrix bridge relays to its network only what the **logged-in user's own
//! Matrix account** sends. A message from `@sensor:` is not a message from the
//! user, so the bridge ignores it — without a log line, which is how the
//! outbound half of this product reported itself healthy while nothing left
//! the deployment. The answer ADR 0025 decided is a second Matrix client: a
//! device of the owner's own account, held beside the Sensor's own session.
//!
//! One identity observes and one identity acts, and **they are never
//! confused**. Everything the register, the consent model and ADR 0024 rest on
//! is the observing identity's: the owner's device joins portal rooms and posts
//! approved replies, it publishes nothing, it reads no history, and it is never
//! what makes a conversation `observing`.
//!
//! This module holds the two decisions that are policy rather than plumbing —
//! which invitations the owner's device may accept, and what a posted reply
//! reached — and nothing that does I/O; `main.rs` wires them to matrix-sdk.

use crate::bridge_bot::BridgeBots;

/// Subdirectory of `SENSOR_STATE_DIR` the owner-device's own stores live in.
///
/// Never shared with the Sensor's own stores, and not because of tidiness: the
/// crypto store is bound to **one device** (matrix-sdk refuses to open one
/// belonging to another, `CryptoStoreError::MismatchedAccount`), and these are
/// two devices of two different accounts. The state store is separate for the
/// same reason it is per-session everywhere else — its rooms, its sync token.
pub const STORE_SUBDIR: &str = "owner-device";

/// The to-device event the browser hands the credential over in (ADR 0034,
/// issue #228), and what the Sensor must refuse.
///
/// # The channel, and why it is this one
///
/// ADR 0025 needs a device of the owner's own account; ADR 0034 decided it is
/// created **in the browser** during onboarding and reaches the Sensor as an
/// Olm-encrypted to-device message addressed to the Sensor's own device — so the
/// Companion Gateway is not in the path at all, and ADR 0011's sentence about
/// the Gateway storing no Matrix token stays literally true rather than being
/// amended. A long-lived credential of the user's account relayed through a
/// Gateway would sit in request bodies and logs for the life of the deployment;
/// what transits there today is a token the browser already had and the Gateway
/// drops within one call, which is a different thing.
///
/// # Three refusals, and they are one answer
///
/// A handover is accepted **only** when it arrived decrypted and the device that
/// sent it is the one this deployment expects. Everything else is discarded and
/// counted:
///
/// - **in the clear**: either an attacker's or a bug, and the two deserve the
///   same answer. Nothing about a plaintext to-device event says which, so
///   neither is trusted;
/// - **undecryptable**: the same, from the other side. It is also what a future
///   hardening of the Sensor's trust requirement would turn this channel into
///   (ADR 0034 records that), so it must read as a refusal and not as an error
///   nobody recognises;
/// - **from a device nobody expected**: any account on any homeserver can send
///   a to-device event to the Sensor. The sender being the owner is necessary
///   and not sufficient — the owner's *browser* is one of their devices, and the
///   credential must come from the one the handover room is with.
///
/// Refusing is not the same as failing: the Sensor goes on doing everything else
/// it does. A deployment whose onboarding was interrupted is one with no acting
/// device, which is the state it was already in.
pub const HANDOVER_EVENT_TYPE: &str = "fr.linagora.twalk.owner_device.handover";

/// What the browser puts in it: the credential, and nothing that is not needed
/// to use it.
///
/// The `device_id` travels beside the token because the crypto store is bound to
/// one device (matrix-sdk refuses to open one belonging to another), so a token
/// without its device id is a credential the Sensor cannot act under. The
/// `user_id` travels because the Sensor refuses a credential for an account that
/// is not the owner's, at startup today and here too: a device of somebody
/// else's account would join portal rooms as a stranger and write into other
/// people's conversations under a Matrix ID nobody chose.
#[derive(Clone, PartialEq, Eq)]
pub struct Handover {
    pub user_id: String,
    pub device_id: String,
    pub access_token: String,
}

/// Prints the credential without printing the credential.
///
/// Written by hand rather than derived because everything else in this file is
/// derived and one `{handover:?}` in a log line, a test failure or an
/// `anyhow` context would put a long-lived token of the user's account into a
/// log — which is precisely the exposure ADR 0034 keeps out of the Gateway.
impl std::fmt::Debug for Handover {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Handover")
            .field("user_id", &self.user_id)
            .field("device_id", &self.device_id)
            .field("access_token", &"<redacted>")
            .finish()
    }
}

/// The file in `SENSOR_STATE_DIR` that holds a handed-over credential, beside
/// the [`STORE_SUBDIR`] whose crypto store belongs to that same device.
///
/// # Why a credential is written down at all
///
/// `bring_up_owner_device` says the acting device needs no session file, because
/// the credential "arrives from configuration every start and names its device,
/// so there is nothing to remember". A handed-over one arrives **once**, from a
/// browser the user has since closed: not remembering it would mean a deployment
/// that acts as the owner until its next restart and silently stops afterwards,
/// which is the class of degradation this product has shipped repeatedly. So it
/// is written, `0600`, atomically, beside the session file that has held a token
/// of the Sensor's own account since the first ticket — the exposure ADR 0034
/// accepted and stated: this volume is not encrypted, and what grows is that the
/// token on it is now the user's as well as the Sensor's.
///
/// It is also the answer to *whose crypto store is this*: a crypto store belongs
/// to one device, so a handover naming a different device is one whose store has
/// to go, and this file is what says which device the store on disk was built
/// for.
pub const CREDENTIAL_FILE: &str = "owner-device.json";

/// What is written to [`CREDENTIAL_FILE`].
///
/// The same three fields the to-device event carries, read back by the same
/// [`credential_in`]: the file format and the wire format are one shape stated
/// once, so a handover that can be read cannot be a credential that cannot be
/// reloaded.
pub fn credential_document(handover: &Handover) -> serde_json::Value {
    serde_json::json!({
        "user_id": handover.user_id,
        "device_id": handover.device_id,
        "access_token": handover.access_token,
    })
}

/// The credential a document carries, or why it is not one.
///
/// Only [`NotAHandover::Unreadable`] ever comes back: whose account it is, and
/// whether the device is the expected one, are questions about a *delivery*, and
/// [`handover_in`] asks them.
pub fn credential_in(document: &serde_json::Value) -> Result<Handover, NotAHandover> {
    let string = |name: &str| -> Result<String, NotAHandover> {
        document
            .get(name)
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
            .filter(|value| !value.is_empty())
            .ok_or(NotAHandover::Unreadable)
    };
    Ok(Handover {
        user_id: string("user_id")?,
        device_id: string("device_id")?,
        access_token: string("access_token")?,
    })
}

/// Why a to-device event is not a handover this Sensor will act on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotAHandover {
    /// Another to-device event entirely. The ordinary case: a homeserver
    /// delivers key requests, verification starts and whatever else on the same
    /// channel, and a Sensor that logged about each would drown the one that
    /// matters.
    AnotherType,
    /// It arrived in the clear, or this Sensor could not decrypt it.
    NotEncrypted,
    /// Decrypted, and from a device this deployment does not expect.
    UnexpectedSender,
    /// The shape is wrong: a field missing, or one that is not a string.
    Unreadable,
    /// A credential for an account that is not the owner's.
    NotTheOwners,
}

impl NotAHandover {
    /// The label of `twalk_sensor_handovers_refused_total{why}`.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AnotherType => "another_type",
            Self::NotEncrypted => "not_encrypted",
            Self::UnexpectedSender => "unexpected_sender",
            Self::Unreadable => "unreadable",
            Self::NotTheOwners => "not_the_owners",
        }
    }
}

/// What the Sensor knows about a to-device event before it reads its content.
///
/// A struct of what matrix-sdk can be asked rather than the SDK's own types, for
/// the reason [`JoinAnswer`] and [`SyncAnswer`] are: the decision is policy,
/// gets tested without a homeserver, and `main.rs` does the asking.
#[derive(Debug, Clone)]
pub struct Delivered<'a> {
    pub event_type: &'a str,
    /// Whether the event arrived Olm-encrypted **and decrypted**: the two are
    /// one question here, because an event this Sensor could not decrypt is one
    /// it knows nothing about.
    pub decrypted: bool,
    /// The account that sent it, as the homeserver addressed it.
    pub sender: &'a str,
    /// The sender's device, as the decryption itself reported it — never as the
    /// event's own content claims it. A field inside a payload is the sender's
    /// word; `EncryptionInfo` is the crypto machine's.
    ///
    /// A device id is only ever unique **within one account**: two accounts can
    /// each have a device called `ABCDEF`, so this is meaningless without
    /// [`Delivered::sender`] beside it, and [`handover_in`] reads the two
    /// together.
    pub sender_device: Option<&'a str>,
}

/// The state event in the handover room that says which device the credential
/// will come from, and the one the Sensor answers with.
///
/// # Why the expected device is a fact in the room and not a configured value
///
/// [`handover_in`] refuses a credential from a device this deployment does not
/// expect, and something has to say which device that is. It cannot be
/// configuration: the browser's device is minted by the login the user has just
/// performed, so nobody could write it into an environment file beforehand — and
/// an onboarding that asked them to would be the manual step ADR 0034 removed.
///
/// So the owner states it **in the handover room**, as a state event whose
/// `state_key` is empty and whose `device_id` is the browser's own. That room is
/// [#226](https://github.com/linagora/twalk/issues/226)'s: the owner created it
/// and holds power level 100 in it, the Sensor sits at 0, and `state_default` is
/// 50 — so this is a sentence only the owner's account can write, authenticated
/// by the homeserver rather than by anything Twalk checks. An attacker who could
/// write it would already hold the account whose credential is being handed
/// over.
///
/// The Sensor answers in the same room with [`HANDOVER_HELD_TYPE`], which is the
/// **acknowledgement** ADR 0034 requires: the Companion reports success when the
/// Sensor says it holds the credential, never when its own send resolves, because
/// a to-device send to an untracked user resolves successfully having sent
/// nothing. Sending it is what the room's one power-level exception is for — the
/// Sensor may write that single state type and nothing else — and the ordinary
/// case for the Companion is to read it back within a second or two.
///
/// Both travel in the clear, unlike the credential: a device id is not a secret,
/// and a state event the Companion can read with one request beats a second
/// encrypted channel whose failure would be indistinguishable from the first's.
pub const HANDOVER_OFFER_TYPE: &str = "fr.linagora.twalk.owner_device.handover.from";

/// The `m.room.create` type of the room those two travel in (#226).
///
/// `companion/src/lib/matrix/handover.ts` is the authority on the room's shape and
/// creates it; this is the Sensor's copy of the one fact it has to recognise, for
/// the reason the Companion Gateway's test harness keeps its own: a room type is a
/// value in a wire protocol between two components, and each end states it.
pub const HANDOVER_ROOM_TYPE: &str = "fr.linagora.twalk.handover";

/// The Sensor's acknowledgement. See [`HANDOVER_OFFER_TYPE`].
pub const HANDOVER_HELD_TYPE: &str = "fr.linagora.twalk.owner_device.handover.held";

/// The device the owner's own state event offers the credential from.
///
/// `None` when there is no such event, or its content does not name a device:
/// [`handover_in`] then refuses every handover, which is the right answer for a
/// room in which the owner has offered nothing.
pub fn offered_from(content: Option<&serde_json::Value>) -> Option<&str> {
    content?
        .get("device_id")?
        .as_str()
        .filter(|device| !device.is_empty())
}

/// What the Sensor writes in the handover room once it holds the credential.
///
/// It names the device it now acts through and the device it came from, so that
/// a Companion reading it can tell **its own** handover from an earlier one: a
/// deployment onboarded twice has two acknowledgements in this room's history,
/// and the browser waiting for the second must not be satisfied by the first.
pub fn held(handover: &Handover, offered_by: &str) -> serde_json::Value {
    serde_json::json!({
        "user_id": handover.user_id,
        "device_id": handover.device_id,
        "offered_by": offered_by,
    })
}

/// Reads a to-device event for the credential, or says why it is not one.
///
/// `expected_device` is the device the handover is expected from — the browser
/// that offered it in the handover room ([`HANDOVER_OFFER_TYPE`], read with
/// [`offered_from`]). `owner` is the account the credential must belong to, and
/// the only account this Sensor accepts a handover from at all.
pub fn handover_in(
    delivered: &Delivered<'_>,
    content: &serde_json::Value,
    expected_device: Option<&str>,
    owner: &str,
) -> Result<Handover, NotAHandover> {
    if delivered.event_type != HANDOVER_EVENT_TYPE {
        return Err(NotAHandover::AnotherType);
    }
    if !delivered.decrypted {
        return Err(NotAHandover::NotEncrypted);
    }
    // The account first: any account on any homeserver can send a to-device
    // event to the Sensor, and a device id is unique only within an account, so
    // an expected device matched without its owner would match a stranger's
    // device of the same name.
    if delivered.sender != owner {
        return Err(NotAHandover::UnexpectedSender);
    }
    // And an expected device that is not configured refuses everything: a Sensor
    // that accepted a credential from any device of the owner's would accept one
    // from a browser session somebody else left open on their account.
    match (expected_device, delivered.sender_device) {
        (Some(expected), Some(sender)) if expected == sender => {}
        _ => return Err(NotAHandover::UnexpectedSender),
    }
    let handover = credential_in(content)?;
    if handover.user_id != owner {
        return Err(NotAHandover::NotTheOwners);
    }
    Ok(handover)
}

/// What the owner's device may do with one pending invitation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Invitation {
    /// A portal of a configured bridge: accept it, so the owner is a **joined**
    /// member of the room their conversation lives in and the bridge relays
    /// what they send there.
    JoinPortal,
    /// Refused, with the reason to log and count.
    Refuse(Refusal),
}

/// Why an invitation to the owner's device was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The inviter is not one of the bridge bots this deployment named. The
    /// ordinary case, and the safe one: anybody on any homeserver may invite
    /// the owner's account into a room.
    InviterIsNotABridgeBot,
    /// `SENSOR_BRIDGE_BOTS` is empty, so no invitation can ever be recognised
    /// as a portal's. Refused like any other, and worth its own reason because
    /// the symptom — the owner joins nothing, every reply reaches nobody — has
    /// one configuration line behind it.
    NoBridgeBotsConfigured,
}

impl Refusal {
    /// The metric's label value.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InviterIsNotABridgeBot => "inviter_is_not_a_bridge_bot",
            Self::NoBridgeBotsConfigured => "no_bridge_bots_configured",
        }
    }
}

/// Whether the owner's device may accept an invitation, decided **on the
/// inviter alone**.
///
/// The reasoning is the whole of this function and it is a security argument,
/// so it is written here rather than left to a reader. Three things arrive with
/// an invitation and two of them are the *inviter's* to choose: the room id,
/// the room's name, and its state — including the `m.bridge` marker that says
/// "this is a WhatsApp portal". Anybody with an account anywhere may create a
/// room, write whatever `m.bridge` marker they like into it, and invite
/// `@michel:`. So the marker cannot be the gate: joining on it would let a
/// stranger put a device of the user's own account into a room of their
/// choosing, and that device *posts messages*.
///
/// What is **not** the inviter's to choose is who the homeserver records as the
/// sender of the `m.room.member` invite. That is the one authenticated fact in
/// the invitation, and it is the gate: an exact match against the bridge bots
/// the deployment named (`SENSOR_BRIDGE_BOTS`), each one this deployment's own
/// appservice identity. A portal of a configured bridge is invited by that
/// bridge's bot; nothing else is joined, whatever it claims about itself.
///
/// `SENSOR_BRIDGE_BOTS` and not `SENSOR_ALLOWED_INVITERS`, for the reason issue
/// #152 separated the two lists in the first place: that one answers a
/// different question (who may put the **Sensor** in a room) and also names the
/// operator, whose own invitations are not portals and must not be a way to
/// place their device anywhere.
///
/// The marker is still read afterwards, to log which network the portal is of.
/// Corroboration in a log line is a different thing from a gate.
pub fn invitation(inviter: &str, bridge_bots: &BridgeBots) -> Invitation {
    if bridge_bots.is_empty() {
        return Invitation::Refuse(Refusal::NoBridgeBotsConfigured);
    }
    if bridge_bots.contains(inviter) {
        Invitation::JoinPortal
    } else {
        Invitation::Refuse(Refusal::InviterIsNotABridgeBot)
    }
}

/// What the homeserver answered a join with, reduced to the two facts that
/// decide whether trying again can ever change the answer.
///
/// Plain data rather than matrix-sdk's error type, so the decision below can
/// be made — and tested — from what was *answered*, which is the only thing
/// the decision is allowed to rest on (issue #237: attempt counts alone told
/// the loop nothing, and it ran a permanent refusal at sync frequency).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinAnswer {
    /// The HTTP status, when the request reached a homeserver at all.
    pub status: Option<u16>,
    /// The Matrix `errcode` (`M_FORBIDDEN`, `M_UNKNOWN`…), when the body had one.
    pub errcode: Option<String>,
}

/// Whether a failed join is worth trying again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinFailure {
    /// The homeserver said no in a way that will not change: the room is gone
    /// or unreachable, the invitation is no longer valid, the request itself
    /// is refused. Said once, counted once, never retried in this process.
    Permanent,
    /// Nothing about the room was decided — the request was throttled, the
    /// server or the network failed. Retried, with a delay that grows.
    Transient,
}

/// Decides, from what the homeserver answered, whether a join can ever succeed.
///
/// The one this was written for is `404 M_UNKNOWN "Can't join remote room
/// because no servers that are in the room have been provided"`: an orphan
/// portal every member has left, which the homeserver has no route into and
/// never will. Treating it as a blip is what produced seventy-eight attempts
/// in five minutes, at `ERROR`, for one room — a log an operator stops
/// reading, in which the *next* real failure arrives unread.
///
/// The rule is on the **status class**, and the errcode only refines it:
///
/// - `429` is a throttle, whatever its body says, and clears on its own;
/// - every other `4xx` is the homeserver saying this request, for this room,
///   as this user, is refused — not found, not invited any more, banned,
///   restricted and ungrantable, malformed. Nothing this loop does changes any
///   of that, so trying again is noise;
/// - `5xx` and no status at all (the request never got an answer) say nothing
///   about the room, so they are retried.
///
/// The human-readable `error` string is deliberately not consulted: it is
/// prose, it differs between homeservers, and a decision that greps it is a
/// decision that silently stops working on the next Synapse release.
pub fn join_failure(answer: &JoinAnswer) -> JoinFailure {
    match answer.status {
        Some(429) => JoinFailure::Transient,
        // A throttle can also arrive as `M_LIMIT_EXCEEDED` behind a proxy that
        // rewrote the status; it is a throttle all the same.
        Some(status)
            if (400..500).contains(&status)
                && answer.errcode.as_deref() != Some("M_LIMIT_EXCEEDED") =>
        {
            JoinFailure::Permanent
        }
        _ => JoinFailure::Transient,
    }
}

/// How long to wait before the `attempt`-th retry of a transiently failed join
/// (the first retry is attempt 1).
///
/// Doubles from thirty seconds and stops growing at thirty minutes: a portal
/// whose homeserver is down for an afternoon is picked up within half an hour
/// of its return, and a portal that fails transiently for ever costs the log
/// two lines an hour rather than sixteen a minute. The base is the sync
/// timeout, because a retry sooner than that cannot have new information.
pub fn retry_delay(attempt: u32) -> std::time::Duration {
    const BASE_SECS: u64 = 30;
    const CAP_SECS: u64 = 30 * 60;
    let doubled = BASE_SECS.saturating_mul(1u64 << attempt.saturating_sub(1).min(16));
    std::time::Duration::from_secs(doubled.min(CAP_SECS))
}

/// What a reply the Sensor has just posted reached — the distinction issue #216
/// is about, which was invisible before this: an event id existed, a stream
/// position existed, every component reported itself healthy, and the contact
/// received nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reach {
    /// The contact. Either the reply was posted by a device of the owner's own
    /// account into a room the owner is a **joined** member of — which is what
    /// a bridge relays — or the room is not a portal at all, so no bridge
    /// stands between the room and the person reading it.
    Contact,
    /// Nobody. The reply was posted by `@sensor:` into a portal room: Synapse
    /// accepted it and returned an event id, and the bridge ignored it, because
    /// it relays only the logged-in user's own account (issue #123). The
    /// message exists in a Matrix room the contact cannot see.
    Nobody,
}

impl Reach {
    /// The value carried on the bus and in the metric's label.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Contact => "contact",
            Self::Nobody => "nobody",
        }
    }

    /// True when the contact receives the reply. The name is the question a
    /// consumer is really asking, and it is deliberately not `== Contact`
    /// spelled out at every call site.
    pub fn reaches_the_contact(&self) -> bool {
        matches!(self, Self::Contact)
    }
}

/// What a posted reply reached, from the two facts that decide it.
///
/// `by_the_owners_device` is true only when the reply was sent by the owner's
/// own device, which the Sensor lets happen only for a room that device is a
/// **joined** member of — so "posted by the owner's device" already carries
/// "the owner is in the room", which is the half of the answer the bridge cares
/// about.
///
/// `the_room_is_a_portal` is whether a bridge stands between the room and the
/// contact. A room no bridge marked is native Matrix traffic (ADR 0009): the
/// room *is* the conversation, so a message in it has reached the person
/// reading it, under the Sensor's identity rather than the user's. That
/// remaining difference — who the contact sees it from — is ADR 0019's
/// question and not this one; what #216 asks is whether the message arrived at
/// all.
pub fn reach(by_the_owners_device: bool, the_room_is_a_portal: bool) -> Reach {
    match (by_the_owners_device, the_room_is_a_portal) {
        (true, _) => Reach::Contact,
        (false, false) => Reach::Contact,
        (false, true) => Reach::Nobody,
    }
}

/// What a homeserver's refusal says about the owner device's **credential**
/// (issue #229).
///
/// Asked of a failed sync and of a failed send, which is why it is named after
/// the refusal and not after the sync: the sync notices a revocation when its
/// long poll comes back, up to thirty seconds later, and an approval that
/// arrives inside that window is sent under a token the homeserver has already
/// forgotten.
///
/// ADR 0025 accepted a long-lived access token for the owner's own account at
/// rest, and the mitigation it named was neither encryption nor scope: it was
/// that the token is *a device among their devices*, revocable from any Matrix
/// client without Twalk's involvement. That mitigation is only real if revoking
/// it produces a visible result — and until this ticket it produced none. The
/// owner revoked the device from their phone, the sync loop warned and retried
/// for ever, approvals went on being accepted, and nothing arrived.
///
/// So a sync failure is read for which of two situations it is, because they are
/// two and must not share one signal: a homeserver that is merely away, and a
/// credential that is gone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AfterRefusal {
    /// The homeserver did not answer, or answered something a later attempt may
    /// not: it is restarting, the network is down, a proxy is in the way. Retry,
    /// which is what both paths have always done.
    Retry,
    /// The credential is gone. The homeserver says it does not know this token,
    /// which is what it says about a device the owner revoked — and Twalk holds
    /// no password for the owner's account (ADR 0025: it is given a device, never
    /// the account), so there is nothing to log back in with. Retrying is not
    /// wrong so much as pointless, and being quiet about it is the defect.
    CredentialGone,
}

/// Reads a homeserver's refusal for whether the acting credential is gone.
///
/// One argument, the Matrix error code, because one code decides it —
/// [`JoinAnswer`] carries a status as well because a join is refused by status
/// alone often enough to matter, and nothing here is. `main.rs` does the asking
/// of `matrix_sdk`; this decides, and gets tested without a homeserver.
///
/// `M_UNKNOWN_TOKEN` and nothing else. It is what Synapse answers for a token it
/// has no record of — a device the owner deleted, a token an admin invalidated —
/// and the `soft_logout` flag beside it makes no difference here: it tells a
/// client whether it may re-authenticate the same device with a password, and
/// Twalk has no password to offer. `M_MISSING_TOKEN` is deliberately *not* read
/// as gone: it means no token was sent at all, which is a bug in this process
/// rather than a decision of the owner's, and reporting a revocation for it would
/// send an operator to the wrong place.
///
/// A refusal with no readable code is a retry, not a revocation: a proxy that
/// answers `401` with an HTML page is a deployment problem, and naming the
/// owner's own credential for it would be a lie that costs them a device.
///
/// Asked of a failed **sync** and of a failed **send**, which is what closes the
/// window between the two: the sync notices a revocation when its long poll
/// comes back, up to thirty seconds later, and an approval that arrives inside
/// that window is sent under a token the homeserver has already forgotten.
pub fn after_refusal(errcode: Option<&str>) -> AfterRefusal {
    match errcode {
        Some("M_UNKNOWN_TOKEN") => AfterRefusal::CredentialGone,
        _ => AfterRefusal::Retry,
    }
}

/// The one sentence an operator needs when the acting credential is gone: which
/// credential, and what puts it back.
///
/// Here rather than inline at the log site so that the log and the reply's
/// dead-letter reason say the same thing — the owner reads one on the approval
/// screen and the operator reads the other in `docker logs`, and two different
/// accounts of one situation is how a deployment gets debugged twice.
pub const REVOKED_REMEDY: &str = concat!(
    "SENSOR_OWNER_DEVICE_ACCESS_TOKEN names a device the homeserver no longer knows: the owner ",
    "revoked it, or an admin did. Replies cannot be sent as the owner until a new device is ",
    "provisioned: run docker-compose/provision-owner-device.sh, then restart the Sensor. This ",
    "is not a homeserver that is unreachable — that answers differently and is retried."
);

#[cfg(test)]
mod tests {
    use super::*;

    const WHATSAPP_BOT: &str = "@whatsappbot:twalk.localhost";
    const SIGNAL_BOT: &str = "@signalbot:twalk.localhost";
    const OWNER: &str = "@michel:twalk.localhost";
    const STRANGER: &str = "@mallory:elsewhere.example";

    fn bots() -> BridgeBots {
        BridgeBots::new([WHATSAPP_BOT.to_owned(), SIGNAL_BOT.to_owned()])
    }

    #[test]
    fn a_configured_bridges_bot_places_the_owners_device_in_its_portal() {
        assert_eq!(invitation(WHATSAPP_BOT, &bots()), Invitation::JoinPortal);
        assert_eq!(invitation(SIGNAL_BOT, &bots()), Invitation::JoinPortal);
    }

    #[test]
    fn nobody_else_may_place_a_device_of_the_users_account_anywhere() {
        // The room id, the room's name and its `m.bridge` marker are all the
        // inviter's to choose, so a stranger claiming to be a WhatsApp portal
        // is exactly the input this refuses. The inviter is the only
        // authenticated fact in an invitation.
        assert_eq!(
            invitation(STRANGER, &bots()),
            Invitation::Refuse(Refusal::InviterIsNotABridgeBot)
        );
        // The operator's own invitations are not portals either: their list is
        // SENSOR_ALLOWED_INVITERS, which answers who may put the *Sensor* in a
        // room, and reusing it here would make it a way to place the user's
        // own device in any room at all.
        assert_eq!(
            invitation(OWNER, &bots()),
            Invitation::Refuse(Refusal::InviterIsNotABridgeBot)
        );
    }

    #[test]
    fn a_deployment_that_named_no_bridge_bot_joins_nothing_and_says_which_line_it_is() {
        // The symptom is "every reply reaches nobody", which is the defect
        // itself; the cause is one unset variable, so it gets its own reason
        // rather than being counted as a stranger's invitation.
        assert_eq!(
            invitation(WHATSAPP_BOT, &BridgeBots::new(Vec::<String>::new())),
            Invitation::Refuse(Refusal::NoBridgeBotsConfigured)
        );
    }

    fn answer(status: Option<u16>, errcode: Option<&str>) -> JoinAnswer {
        JoinAnswer {
            status,
            errcode: errcode.map(str::to_owned),
        }
    }

    #[test]
    fn an_orphan_portal_is_given_up_on_from_what_synapse_answered() {
        // Issue #237, verbatim from the reference deployment: every member had
        // left, the homeserver had no server to join through, and it said so
        // with a 404 — seventy-eight times in five minutes, because the loop
        // read none of it.
        assert_eq!(
            join_failure(&answer(Some(404), Some("M_UNKNOWN"))),
            JoinFailure::Permanent
        );
        // The invitation was withdrawn, or the owner was banned: not this
        // device's to change either.
        assert_eq!(
            join_failure(&answer(Some(403), Some("M_FORBIDDEN"))),
            JoinFailure::Permanent
        );
        assert_eq!(
            join_failure(&answer(Some(404), Some("M_NOT_FOUND"))),
            JoinFailure::Permanent
        );
        assert_eq!(
            join_failure(&answer(Some(400), Some("M_UNABLE_TO_GRANT_JOIN"))),
            JoinFailure::Permanent
        );
        // A 4xx with no parsable body is still the homeserver refusing.
        assert_eq!(
            join_failure(&answer(Some(404), None)),
            JoinFailure::Permanent
        );
    }

    #[test]
    fn a_throttle_a_server_error_and_no_answer_at_all_are_retried() {
        assert_eq!(
            join_failure(&answer(Some(429), Some("M_LIMIT_EXCEEDED"))),
            JoinFailure::Transient
        );
        // The same throttle with its status rewritten by a proxy in front.
        assert_eq!(
            join_failure(&answer(Some(400), Some("M_LIMIT_EXCEEDED"))),
            JoinFailure::Transient
        );
        assert_eq!(
            join_failure(&answer(Some(502), None)),
            JoinFailure::Transient
        );
        assert_eq!(
            join_failure(&answer(Some(500), Some("M_UNKNOWN"))),
            JoinFailure::Transient
        );
        // The request never reached a homeserver: nothing about the room is known.
        assert_eq!(join_failure(&answer(None, None)), JoinFailure::Transient);
    }

    #[test]
    fn the_retry_delay_doubles_from_the_sync_timeout_and_stops_at_half_an_hour() {
        use std::time::Duration;
        assert_eq!(retry_delay(1), Duration::from_secs(30));
        assert_eq!(retry_delay(2), Duration::from_secs(60));
        assert_eq!(retry_delay(3), Duration::from_secs(120));
        assert_eq!(retry_delay(7), Duration::from_secs(30 * 60));
        assert_eq!(retry_delay(8), Duration::from_secs(30 * 60), "capped");
        assert_eq!(
            retry_delay(u32::MAX),
            Duration::from_secs(30 * 60),
            "no overflow"
        );
        // Attempt 0 is not a retry; treated as the first.
        assert_eq!(retry_delay(0), Duration::from_secs(30));
    }

    #[test]
    fn only_an_unknown_token_is_a_revoked_credential() {
        // What Synapse answers for a device the owner deleted.
        assert_eq!(
            after_refusal(Some("M_UNKNOWN_TOKEN")),
            AfterRefusal::CredentialGone
        );

        // A homeserver that is away, in the shapes it goes away in: nothing
        // readable at all, a rate limit, an internal error.
        for errcode in [None, Some("M_LIMIT_EXCEEDED"), Some("M_UNKNOWN")] {
            assert_eq!(
                after_refusal(errcode),
                AfterRefusal::Retry,
                "errcode {errcode:?}"
            );
        }

        // A token this process failed to send is a bug here, not a decision of
        // the owner's: naming their credential for it sends an operator to the
        // wrong place. Same for a refusal nobody can read — a proxy answering
        // `401` with an HTML page — which is the `None` above.
        assert_eq!(after_refusal(Some("M_MISSING_TOKEN")), AfterRefusal::Retry);
    }

    #[test]
    fn the_remedy_names_the_credential_and_the_distinction() {
        assert!(REVOKED_REMEDY.contains("SENSOR_OWNER_DEVICE_ACCESS_TOKEN"));
        assert!(
            REVOKED_REMEDY.contains("unreachable"),
            "a revoked device and a homeserver that is away must not share one \
             signal, so the message that names one says it is not the other"
        );
    }

    #[test]
    fn only_the_sensors_own_post_into_a_portal_reaches_nobody() {
        assert_eq!(
            reach(true, true),
            Reach::Contact,
            "the user's own account in a portal room is what a bridge relays"
        );
        assert_eq!(
            reach(false, true),
            Reach::Nobody,
            "issue #123: the bridge ignores @sensor: without a log line"
        );
        assert_eq!(
            reach(false, false),
            Reach::Contact,
            "native Matrix (ADR 0009) has no bridge to ignore it: the room is the conversation"
        );
        assert_eq!(reach(true, false), Reach::Contact);
        assert!(
            reach(false, true).as_str() == "nobody" && !reach(false, true).reaches_the_contact()
        );
    }
    /// The credential is written down in exactly the shape it arrived in, and
    /// nothing that logs it can print it (#228).
    #[test]
    fn a_held_credential_reloads_as_itself_and_never_prints_itself() {
        let handover = Handover {
            user_id: OWNER.to_owned(),
            device_id: "TWALKDEVICE".to_owned(),
            access_token: "syt_the-owners-own-device".to_owned(),
        };
        // The file and the wire are one shape: what the browser sent reloads as
        // what the browser sent, through the same reader.
        let document = credential_document(&handover);
        assert_eq!(credential_in(&document), Ok(handover.clone()));
        assert_eq!(
            credential_in(&serde_json::json!({
                "user_id": OWNER,
                "device_id": "TWALKDEVICE",
                "access_token": "syt_the-owners-own-device",
                "written_by_a_later_version": "something",
            })),
            Ok(handover.clone()),
            "a field this version does not know is not a credential it cannot read"
        );
        // And a file that is half a credential is no credential: acting on a
        // token whose device is unknown would open somebody else's crypto store.
        for broken in [
            serde_json::json!({}),
            serde_json::json!({ "user_id": OWNER, "device_id": "TWALKDEVICE" }),
            serde_json::json!({ "user_id": OWNER, "access_token": "syt_x" }),
            serde_json::json!({ "user_id": "", "device_id": "D", "access_token": "t" }),
        ] {
            assert_eq!(
                credential_in(&broken),
                Err(NotAHandover::Unreadable),
                "{broken}"
            );
        }

        // The token is in the document and in nothing that renders the struct:
        // one `{handover:?}` in a log line or an `anyhow` context would put a
        // long-lived token of the user's account on disk in plain text.
        assert!(document.to_string().contains("syt_the-owners-own-device"));
        assert!(
            !format!("{handover:?}").contains("syt_"),
            "{handover:?} prints the token"
        );
        assert!(format!("{handover:?}").contains("TWALKDEVICE"));
    }

    /// The two state events the handover room carries (#228): the owner's offer,
    /// which is where the expected device comes from, and the Sensor's
    /// acknowledgement, which is the only thing the Companion may read as
    /// success.
    #[test]
    fn the_offer_names_the_device_and_the_acknowledgement_names_both() {
        // No event at all is a room in which nothing was offered, and that
        // refuses every handover rather than accepting any.
        assert_eq!(offered_from(None), None);
        assert_eq!(offered_from(Some(&serde_json::json!({}))), None);
        assert_eq!(
            offered_from(Some(&serde_json::json!({ "device_id": "" }))),
            None
        );
        assert_eq!(
            offered_from(Some(&serde_json::json!({ "device_id": 7 }))),
            None
        );
        assert_eq!(
            offered_from(Some(&serde_json::json!({ "device_id": "BROWSERDEV" }))),
            Some("BROWSERDEV")
        );

        // The acknowledgement names the device the Sensor now acts through and
        // the device that offered it, so a browser waiting for its own handover
        // is not satisfied by an earlier onboarding's.
        let handover = Handover {
            user_id: OWNER.to_owned(),
            device_id: "TWALKDEVICE".to_owned(),
            access_token: "syt_never-in-a-state-event".to_owned(),
        };
        let acknowledgement = held(&handover, "BROWSERDEV");
        assert_eq!(
            acknowledgement,
            serde_json::json!({
                "user_id": OWNER,
                "device_id": "TWALKDEVICE",
                "offered_by": "BROWSERDEV",
            })
        );
        // And it does not carry the credential: this event is unencrypted state
        // in a room, readable by every member and by the homeserver's admin.
        assert!(
            !acknowledgement.to_string().contains("syt_"),
            "the acknowledgement must not carry the token: {acknowledgement}"
        );
    }

    /// The handover's three refusals and its one acceptance (#228).
    #[test]
    fn a_handover_is_accepted_only_decrypted_and_from_the_device_expected() {
        const BROWSER: &str = "BROWSERDEV";
        let content = serde_json::json!({
            "user_id": OWNER,
            "device_id": "TWALKDEVICE",
            "access_token": "syt_the-owners-own-device",
        });
        let delivered =
            |event_type: &'static str, decrypted: bool, sender: Option<&'static str>| Delivered {
                event_type,
                decrypted,
                sender: OWNER,
                sender_device: sender,
            };
        let read = |d: Delivered<'_>, content: &serde_json::Value, expected: Option<&str>| {
            handover_in(&d, content, expected, OWNER)
        };

        // The one that is accepted, and what it yields.
        assert_eq!(
            read(
                delivered(HANDOVER_EVENT_TYPE, true, Some(BROWSER)),
                &content,
                Some(BROWSER)
            ),
            Ok(Handover {
                user_id: OWNER.to_owned(),
                device_id: "TWALKDEVICE".to_owned(),
                access_token: "syt_the-owners-own-device".to_owned(),
            })
        );

        // Another to-device event entirely: the ordinary case, and not worth a
        // word in the log.
        assert_eq!(
            read(
                delivered("m.room_key_request", true, Some(BROWSER)),
                &content,
                Some(BROWSER)
            ),
            Err(NotAHandover::AnotherType)
        );

        // In the clear: either an attacker's or a bug, and the two get the same
        // answer because nothing about a plaintext event says which.
        assert_eq!(
            read(
                delivered(HANDOVER_EVENT_TYPE, false, Some(BROWSER)),
                &content,
                Some(BROWSER)
            ),
            Err(NotAHandover::NotEncrypted)
        );

        // From a device nobody expected — including another device of the
        // owner's own, which is the case a check on the *sender* would miss.
        assert_eq!(
            read(
                delivered(HANDOVER_EVENT_TYPE, true, Some("SOMEOTHERDEV")),
                &content,
                Some(BROWSER)
            ),
            Err(NotAHandover::UnexpectedSender)
        );
        // When the deployment expects none, nothing is accepted: a Sensor that
        // took a credential from any device of the owner's would take one from a
        // browser session somebody else opened on their account.
        assert_eq!(
            read(
                delivered(HANDOVER_EVENT_TYPE, true, Some(BROWSER)),
                &content,
                None
            ),
            Err(NotAHandover::UnexpectedSender)
        );
        // And a decryption that named no device is not a device that matched.
        assert_eq!(
            read(
                delivered(HANDOVER_EVENT_TYPE, true, None),
                &content,
                Some(BROWSER)
            ),
            Err(NotAHandover::UnexpectedSender)
        );

        // A stranger's account, with a device of the very name the owner
        // offered: a device id is unique within an account and nowhere else, so
        // this is the handover a check on the device alone would have accepted.
        assert_eq!(
            handover_in(
                &Delivered {
                    event_type: HANDOVER_EVENT_TYPE,
                    decrypted: true,
                    sender: STRANGER,
                    sender_device: Some(BROWSER),
                },
                &content,
                Some(BROWSER),
                OWNER,
            ),
            Err(NotAHandover::UnexpectedSender)
        );

        // A credential for somebody else's account: refused here for the reason
        // it is refused at startup — a device of another account would join
        // portal rooms as a stranger and write under a Matrix ID nobody chose.
        let theirs = serde_json::json!({
            "user_id": STRANGER,
            "device_id": "TWALKDEVICE",
            "access_token": "syt_not-the-owners",
        });
        assert_eq!(
            read(
                delivered(HANDOVER_EVENT_TYPE, true, Some(BROWSER)),
                &theirs,
                Some(BROWSER)
            ),
            Err(NotAHandover::NotTheOwners)
        );

        // And every shape that is not the credential.
        for broken in [
            serde_json::json!({ "user_id": OWNER, "device_id": "D" }),
            serde_json::json!({ "user_id": OWNER, "device_id": "D", "access_token": "" }),
            serde_json::json!({ "user_id": OWNER, "device_id": 7, "access_token": "t" }),
            serde_json::json!("not an object at all"),
        ] {
            assert_eq!(
                read(
                    delivered(HANDOVER_EVENT_TYPE, true, Some(BROWSER)),
                    &broken,
                    Some(BROWSER)
                ),
                Err(NotAHandover::Unreadable),
                "{broken}"
            );
        }
    }

    #[test]
    fn every_handover_refusal_has_a_label_of_its_own() {
        // The labels are a metric's, so a collision would merge two facts an
        // operator has to tell apart.
        let labels: Vec<&str> = [
            NotAHandover::AnotherType,
            NotAHandover::NotEncrypted,
            NotAHandover::UnexpectedSender,
            NotAHandover::Unreadable,
            NotAHandover::NotTheOwners,
        ]
        .iter()
        .map(NotAHandover::as_str)
        .collect();
        let mut unique = labels.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(labels.len(), unique.len(), "{labels:?}");
    }
}
