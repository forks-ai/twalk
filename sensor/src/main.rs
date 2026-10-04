//! The Twalk Sensor binary. All the decision logic lives in the library
//! modules; this file only wires them to matrix-sdk and NATS JetStream.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use async_nats::jetstream::AckKind;
use futures::StreamExt;
use matrix_sdk::authentication::matrix::MatrixSession;
use matrix_sdk::config::SyncSettings;
use matrix_sdk::deserialized_responses::{ProcessedToDeviceEvent, RawAnySyncOrStrippedState};
use matrix_sdk::encryption::recovery::RecoveryState;
use matrix_sdk::encryption::{BackupDownloadStrategy, EncryptionSettings};
use matrix_sdk::ruma::api::client::filter::{
    Filter as EventTypeFilter, FilterDefinition, RoomEventFilter, RoomFilter,
};
use matrix_sdk::ruma::api::client::state::{get_state_event_for_key, get_state_events};
use matrix_sdk::ruma::api::client::sync::sync_events;
use matrix_sdk::ruma::api::error::ErrorKind;
use matrix_sdk::ruma::events::presence::PresenceEvent;
use matrix_sdk::ruma::events::reaction::OriginalSyncReactionEvent;
use matrix_sdk::ruma::events::relation::Reply;
use matrix_sdk::ruma::events::room::create::OriginalSyncRoomCreateEvent;
use matrix_sdk::ruma::events::room::encrypted::OriginalSyncRoomEncryptedEvent;
use matrix_sdk::ruma::events::room::member::{MembershipState, StrippedRoomMemberEvent};
use matrix_sdk::ruma::events::room::message::{
    MessageType, OriginalSyncRoomMessageEvent, Relation, RoomMessageEventContent,
};
use matrix_sdk::ruma::events::room::MediaSource;
use matrix_sdk::ruma::events::{
    AnySyncMessageLikeEvent, AnySyncTimelineEvent, AnyToDeviceEvent, SyncMessageLikeEvent,
};
use matrix_sdk::ruma::presence::PresenceState;
use matrix_sdk::ruma::{EventId, OwnedEventId, OwnedTransactionId, OwnedUserId, UInt};
use matrix_sdk::{Client, LoopCtrl, Room, RoomState};
use tracing::{error, info, warn};
use twalk_sensor::bridge_bot::BridgeBots;
use twalk_sensor::config::Config;
use twalk_sensor::consent::{Consent, ConsentCache, ConsentSnapshotSource};
use twalk_sensor::metrics::{DropReason, Metrics, OwnerDeviceInvite};
use twalk_sensor::owner_device::Reach;
use twalk_sensor::{bus, connection, consent, network, normalize, outbound, owner_device};

#[tokio::main]
async fn main() -> Result<()> {
    let config = Config::from_env()?;
    tracing_subscriber::fmt()
        // Not `config.log_level` directly: see `Config::log_filter` for the one
        // directive it puts in front, and the 16 006 warnings in five days that
        // bought it (#452).
        .with_env_filter(config.log_filter())
        .init();
    info!(homeserver = %config.homeserver_url, user = %config.user_id, "sensor starting");

    // Observability (ticket 10): one shared metrics registry, optionally
    // served over HTTP in the Prometheus text format. Binding fails fast and
    // loud — a configured-but-unusable endpoint is an operator error to fix,
    // not a condition to swallow.
    let metrics = Arc::new(Metrics::new());
    if let Some(listen) = config.metrics_listen {
        let listener = tokio::net::TcpListener::bind(listen)
            .await
            .with_context(|| format!("failed to bind the metrics endpoint on {listen}"))?;
        info!(%listen, "serving metrics");
        tokio::spawn(serve_metrics(listener, metrics.clone()));
    }
    // In-flight publishes are spawned through this tracker: a graceful
    // shutdown drains them before exiting instead of cutting them off.
    let publish_tracker = PublishTracker::default();

    // Persistence (ticket 03): with SENSOR_STATE_DIR set, the SDK's state
    // and crypto stores live in that directory (sqlite), so the sync token
    // survives restarts and the sync loop resumes where it stopped instead
    // of re-syncing (and re-emitting) the recent timeline. The stores are
    // not encrypted at rest: the directory is the operator's to protect
    // (volume permissions, disk encryption). Without SENSOR_STATE_DIR the
    // Sensor keeps the in-memory behaviour: a fresh login and initial sync
    // on every start.
    //
    // Encryption (ticket 04): all cryptography is delegated to the SDK's
    // crypto crate — the Sensor implements no primitive itself.
    // Cross-signing is bootstrapped automatically when the account has none
    // (the first password login carries the UIAA credentials for it); a
    // server-side key backup is created when none exists, so room keys
    // survive a device replacement; and when a backup key is later restored
    // through the recovery key, the backed-up room keys are downloaded in
    // one shot — the Sensor's rooms are few and the download is bounded.
    let encryption_settings = EncryptionSettings {
        auto_enable_cross_signing: true,
        auto_enable_backups: true,
        backup_download_strategy: BackupDownloadStrategy::OneShot,
    };

    // With a persisted store, a fresh password login on every start would
    // mint a new device each time — growing the account's device list and
    // resetting the crypto identity the crypto store was persisted for. The
    // session is therefore kept in `session.json` in the state directory:
    // restore it when present, log in otherwise and persist the new session
    // for the next start. Restoring also reloads the persisted sync token,
    // which `SyncSettings::default()` (SyncToken::ReusePrevious) picks up.
    //
    // Whether the persisted session is usable is decided before the client
    // opens the store (issue #28): the crypto store belongs to the session's
    // device, and matrix-sdk refuses to open it for the new device a fresh
    // login mints. So when the session is missing, unparseable or its token
    // was revoked, the stale crypto store is moved aside first and the client
    // starts on a clean one (the state store and its sync token are kept).
    let session_file = config
        .state_dir
        .as_ref()
        .map(|dir| dir.join("session.json"));
    let mut session = session_file.as_deref().and_then(load_session);
    if let Some(persisted) = &session {
        if access_token_revoked(&config.homeserver_url, &persisted.tokens.access_token).await {
            warn!(
                device_id = %persisted.meta.device_id,
                "the persisted access token was revoked (M_UNKNOWN_TOKEN), falling back to a fresh login"
            );
            session = None;
        }
    }
    // Only a fresh password login mints a new device, and only then is the
    // existing crypto store stale. A configured access token names the
    // device it belongs to, so its store is the right one and is kept — if
    // the operator points a new token at a store from another device,
    // matrix-sdk says so loudly rather than being second-guessed here.
    if session.is_none() && config.access_token.is_none() {
        if let Some(state_dir) = &config.state_dir {
            set_stale_store_aside(state_dir).context("failed to move the stale store aside")?;
        }
    }

    let client = match &config.state_dir {
        Some(state_dir) => {
            Client::builder()
                .homeserver_url(&config.homeserver_url)
                .sqlite_store(state_dir, None)
                .with_encryption_settings(encryption_settings)
                .build()
                .await?
        }
        None => {
            Client::builder()
                .homeserver_url(&config.homeserver_url)
                .with_encryption_settings(encryption_settings)
                .build()
                .await?
        }
    };

    // A session that parses but fails to restore is fatal: it points at
    // store corruption the operator should see, and logging in past a
    // half-restored session is not safe (the SDK refuses to set
    // authentication data twice).
    if let Some(session) = session {
        client
            .restore_session(session)
            .await
            .context("failed to restore the persisted session")?;
        info!("restored the persisted session");
    } else {
        match (&config.access_token, &config.device_id) {
            // A pre-provisioned device: the operator obtained the token out
            // of band (Synapse's admin registration API, or an SSO login),
            // which is the only way in on a homeserver whose password login
            // is disabled. Restoring it is a local operation — the first
            // sync is what proves the token — so an invalid one fails there
            // with M_UNKNOWN_TOKEN like a revoked persisted session does.
            (Some(access_token), Some(device_id)) => {
                let session = MatrixSession {
                    meta: matrix_sdk::SessionMeta {
                        user_id: matrix_sdk::ruma::UserId::parse(&config.user_id)
                            .context("SENSOR_USER_ID is not a valid Matrix user ID")?,
                        device_id: device_id.as_str().into(),
                    },
                    tokens: matrix_sdk::SessionTokens {
                        access_token: access_token.clone(),
                        refresh_token: None,
                    },
                };
                client
                    .restore_session(session)
                    .await
                    .context("failed to start from the configured access token")?;
                info!(%device_id, "started from the configured access token");
            }
            _ => {
                let password = config
                    .password
                    .as_deref()
                    .expect("config validation guarantees a password when no token is set");
                client
                    .matrix_auth()
                    .login_username(&config.user_id, password)
                    .initial_device_display_name("twalk-sensor")
                    .send()
                    .await
                    .context("matrix login failed")?;
                info!("logged in to the homeserver");
            }
        }
        if let Some(session_file) = &session_file {
            let session = client
                .matrix_auth()
                .session()
                .expect("a session exists right after login");
            write_private_file(session_file, &serde_json::to_vec(&session)?)
                .context("failed to persist the session")?;
        }
    }

    // Cryptographic identity bootstrap (ticket 04). Let the automatic
    // cross-signing/bootstrap tasks settle first, then, when the operator
    // configured SENSOR_RECOVERY_KEY, open the account's secret storage with
    // it and import what it holds: the cross-signing private keys (so this
    // device is the same identity, not a new one) and the key-backup
    // decryption key, which triggers the one-shot download of the backed-up
    // room keys — this is what lets a replacement device read history. A
    // failed recovery (wrong key, no secret storage on the account) is
    // logged loudly but is not fatal: live traffic still decrypts, senders
    // share Megolm keys with the new device directly.
    client
        .encryption()
        .wait_for_e2ee_initialization_tasks()
        .await;
    if let Some(recovery_key) = &config.recovery_key {
        let recovery = client.encryption().recovery();
        match recovery.recover_and_fix_backup(recovery_key).await {
            Ok(()) => info!(
                state = ?recovery.state(),
                "recovered the cryptographic identity from the recovery key"
            ),
            Err(error) => error!(
                %error,
                "recovery with SENSOR_RECOVERY_KEY failed; continuing with the local device identity only"
            ),
        }
    }

    // And when nobody ever had one to configure (#451). The block above *uses*
    // a recovery key; this one mints the account's first, because a key backup
    // whose key lives only inside the crypto store it insures protects
    // nothing: a replacement device starts empty, finds no backup key, and
    // what is in the backup stays sealed. Measured on the reference
    // deployment — a live backup, twenty room keys over seven rooms, and no
    // secret storage at all.
    //
    // `Recovery::enable` creates the secret storage key and uploads the
    // secrets this device already holds, the existing backup key among them.
    // So on a deployment that has run without one, this does not only protect
    // what comes next: it makes the keys already in the backup openable.
    //
    // The decision is `recovery_key::decide`, with no I/O, so each course is a
    // case a test states rather than a branch read off this function.
    {
        use twalk_sensor::recovery_key::{decide, Plan, StorageState};
        let recovery = client.encryption().recovery();
        let state = match recovery.state() {
            RecoveryState::Unknown => StorageState::Unknown,
            RecoveryState::Enabled => StorageState::Enabled,
            RecoveryState::Disabled => StorageState::Disabled,
            RecoveryState::Incomplete => StorageState::Incomplete,
        };
        // Said once, every start, about **this** client — the observing one.
        // It takes the place of what `matrix_sdk_crypto::backups` used to say
        // from two clients at once and indistinguishably (#452): that target is
        // silenced below ERROR by `Config::log_filter`, because the owner's
        // device warns on every sync about a backup it must not have.
        info!(
            recovery = ?recovery.state(),
            backup = ?client.encryption().backups().state(),
            "the observing client's secret storage and key backup, as it sees \
             them. The owner's device (ADR 0034) has neither, by design"
        );
        match decide(
            config.recovery_key.is_some(),
            state,
            config.recovery_key_out.as_deref(),
            config.state_dir.as_deref(),
        ) {
            Plan::OperatorHasOne | Plan::AlreadyEnabled | Plan::TooEarly => {}
            Plan::IncompleteWithoutTheKey => warn!(
                "this account's secret storage exists but this device is missing some of its \
                 secrets, and no SENSOR_RECOVERY_KEY is configured to import them. Only that key \
                 can complete this device; minting a second one would orphan the first"
            ),
            Plan::NoOutputConfigured => warn!(
                "this account has no secret storage, so the key that opens its server-side key \
                 backup exists only in this crypto store — the one thing the backup is meant to \
                 survive. Losing the store loses both, and SENSOR_RECOVERY_KEY cannot help \
                 because there is nothing for it to open. Set SENSOR_RECOVERY_KEY_OUT to a file \
                 outside SENSOR_STATE_DIR for one start and the key is minted there (#451)"
            ),
            // A configured-but-impossible instruction about a secret, caught
            // before any crypto runs: the operator's to fix, the way a
            // configured-but-unusable metrics endpoint is.
            Plan::RefusedInsideTheStore { out, state_dir } => {
                return Err(anyhow!(
                    "SENSOR_RECOVERY_KEY_OUT ({}) is inside SENSOR_STATE_DIR ({}). The key would \
                     then be lost with the very store it exists to survive — a copy that dies \
                     with what it protects is not a copy. Name a file outside the store",
                    out.display(),
                    state_dir.display()
                ))
            }
            // Three steps in an order that matters, and none of them fatal:
            // this is an opt-in the operator turned on, and failing it must
            // not take observation down with it — the posture the configured
            // recovery above already takes.
            Plan::MintInto(path) => {
                // **Prove the file can be written before minting anything.** A
                // key created on the account and then not written down is
                // worse than no key: secret storage would exist, sealed by
                // something nobody holds, and the account would be stuck that
                // way. So an empty file first, at the mode the real one needs.
                if let Err(error) = write_private_file(&path, b"") {
                    error!(
                        %error,
                        path = %path.display(),
                        "SENSOR_RECOVERY_KEY_OUT cannot be written, so no key was minted — a key \
                         created on the account and then not written down would seal its secret \
                         storage with something nobody has. Fix the path or its permissions and \
                         start again (#451)"
                    );
                } else {
                    // Deliberately not `wait_for_backups_to_upload`: the
                    // upload runs on the sync loop this function is about to
                    // start, and an account with a long history would hold up
                    // observing for it.
                    match recovery.enable().await {
                        Err(error) => {
                            let _ = std::fs::remove_file(&path);
                            error!(
                                %error,
                                "could not create this account's secret storage, so it still has \
                                 no recovery key; continuing with the local device identity only. \
                                 A key backup that exists on the homeserver and that this device \
                                 is not connected to is the usual cause (#451)"
                            );
                        }
                        Ok(key) => match write_private_file(&path, key.as_bytes()) {
                            Ok(()) => info!(
                                path = %path.display(),
                                state = ?recovery.state(),
                                "minted this account's recovery key and wrote it at mode 0600. \
                                 Take it off this host — into SENSOR_RECOVERY_KEY or wherever you \
                                 keep secrets — and delete the file: left here, it is lost with \
                                 the store it exists to survive. The room keys already in the key \
                                 backup become openable with it (#451)"
                            ),
                            // The window the empty-file probe above narrows to
                            // almost nothing, said plainly because the account
                            // is then in the state that probe exists to avoid.
                            Err(error) => error!(
                                %error,
                                path = %path.display(),
                                "this account's secret storage was created but its recovery key \
                                 could not be written down, so the key backup is now sealed by a \
                                 key nobody holds. Delete the account's \
                                 m.secret_storage.default_key and start again with a writable \
                                 path (#451)"
                            ),
                        },
                    }
                }
            }
        }
    }

    let nats = async_nats::connect(&config.nats_url)
        .await
        .context("failed to connect to NATS")?;
    let jetstream = async_nats::jetstream::new(nats);
    // The stream's retention policy (issue #174, ADR 0037): created with it,
    // or reconciled onto an existing stream in place, field by field. A
    // refused update is logged and the Sensor runs on the stream's existing
    // policy; only a bus that cannot be asked at all is fatal here.
    bus::ensure_stream(&jetstream, &config.stream_policy()?)
        .await
        .context("failed to ensure the twalk stream")?;
    info!(stream = normalize::STREAM_NAME, "bus ready");

    // The operator, when the deployment named one (ADR 0018). Their own
    // messages and reactions arrive under network ghosts indistinguishable in
    // shape from a contact's, so the set is confirmed by the deployment and
    // handed over here; an identity that is not in it stays a contact.
    // Logged at startup because the set is the whole of what makes the
    // exemption correct: an operator has to be able to read back what their
    // deployment confirmed.
    //
    // Resolved before the consent cache because the cache is built around
    // it: the owner has no consent state (ADR 0021), so a decision about one
    // of their identities is refused entry rather than filtered at every
    // read.
    let owner = config.owner();
    match &owner {
        Some(owner) => info!(
            operator = %owner.matrix_id(),
            identities = ?owner.identities(),
            "recognising the operator's own traffic as outbound.* and dropping their presence"
        ),
        None => info!(
            "no operator configured (SENSOR_OWNER): the user's own messages are published as \
             a contact's"
        ),
    }

    // The bridges' own bots (issue #152). A bridge materialises ghosts for
    // people and one bot for itself — mautrix's `sender_localpart` — and the
    // bot is neither the owner nor a contact: it creates portals, puppets
    // ghosts and sits in every portal room of its network. Nothing is
    // published about it, on any type.
    //
    // Named by the deployment for the same reason the operator's identities
    // are: the alternatives infer it, and every inference here can suppress a
    // real person (see `twalk_sensor::bridge_bot`). Logged at startup because
    // the set is the whole of what makes the suppression correct, and because
    // a silent empty set is how this defect survives a release.
    let bridge_bots = config.bridge_bots();
    // Rooms whose replacement has been announced once (issue #254): the first
    // stray event in a replaced room is a line, the rest are the same fact.
    let replaced_rooms: Arc<Mutex<HashSet<matrix_sdk::ruma::OwnedRoomId>>> =
        Arc::new(Mutex::new(HashSet::new()));
    // The registry of connections every event is stamped with (ADR 0033,
    // #269): the Gateway's, read off the consent snapshot below — which
    // `bring_up_consent` waits for before the sync loop starts, so the
    // implicit one here is only ever stamped with on a deployment that has no
    // Gateway at all. Rooms whose connection could not be resolved are said
    // once each.
    let registry: Arc<std::sync::RwLock<connection::Registry>> =
        Arc::new(std::sync::RwLock::new(connection::Registry::implicit()));
    let unresolved_rooms: Arc<Mutex<HashSet<matrix_sdk::ruma::OwnedRoomId>>> =
        Arc::new(Mutex::new(HashSet::new()));
    if bridge_bots.is_empty() {
        info!(
            "no bridge bots configured (SENSOR_BRIDGE_BOTS): a bridge's own bot is published as \
             a contact, which on the reference deployment was 95% of the bus (issue #152). A \
             deployment that runs bridges names their bots here — the same accounts \
             SENSOR_ALLOWED_INVITERS already lists"
        );
    } else {
        info!(
            bridge_bots = ?bridge_bots.ids(),
            "recognising these accounts as the bridges' own bots and publishing nothing about them"
        );
    }

    // The owner's own device (ADR 0025, ADR 0034, issue #123): the identity
    // Twalk *acts* as, beside the `@sensor:` identity it observes with. One
    // observes, one acts, and nothing below confuses them — the client built
    // here registers no event handler, publishes nothing, and is never what
    // `client.joined_rooms()` answers, so ADR 0024's membership-is-consent
    // property and the consent gate stay exactly as they were.
    //
    // Brought up after the bridge bots because it depends on them: a portal
    // invitation is recognised by its *inviter*, and that list is the only
    // authenticated way to tell a portal from a room a stranger built (see
    // `twalk_sensor::owner_device::invitation`).
    //
    // Failing to bring it up is fatal, unlike a failed consent snapshot. A
    // Sensor that starts without its consent snapshot publishes degraded
    // labels and recovers; a Sensor that starts with a token for the wrong
    // account writes into other people's conversations under a Matrix ID that
    // is not the one it was told to act as, and nothing downstream can undo
    // that.
    //
    // Held in a cell rather than a variable because since #228 it is not the
    // same device for the life of the process: the owner's browser hands one
    // over while the Sensor runs, and the send path asks the cell per approval
    // for the same reason it already asks the metrics whether the credential is
    // still good (#229).
    let owner_device = Arc::new(OwnerDevice::new());
    let brought_up = bring_up_owner_device(&config, owner.as_ref(), &metrics).await?;
    // What this deployment can do as the owner, said on the bus before anything
    // else happens (#404, ADR 0041): the Companion Gateway draws the approval
    // screen from it, so a screen opened while the Sensor is starting is one that
    // has already been told. An owner nobody named is announced to nobody — the
    // event names them — which is why this is built beside `owner`.
    let announcer = owner.as_ref().map(|owner| {
        Arc::new(OwnerDeviceAnnouncer::new(
            jetstream.clone(),
            client
                .user_id()
                .map(|id| id.server_name().as_str().to_owned())
                .unwrap_or_default(),
            owner.matrix_id().to_owned(),
            metrics.clone(),
        ))
    });
    if let Some(announcer) = &announcer {
        announcer
            .announce(brought_up.state, brought_up.device_id.as_deref())
            .await;
    }
    if let Some(device) = brought_up.client {
        owner_device
            .hold(
                device,
                bridge_bots.clone(),
                metrics.clone(),
                announcer.clone(),
            )
            .await;
    }

    // Consent labelling (ticket 05): every published event carries the
    // sender's current consent state from this cache. It is filled from the
    // Companion Gateway's snapshot and then from the durable
    // consent.state.changed consumer, in that order and without overlap
    // (ticket #51, ADR 0010) — see `bring_up_consent`. The Sensor never
    // writes consent state (ADR 0006).
    //
    // Built around the two identities that have no consent state: the
    // operator (ADR 0021) and the bridges' bots (issue #152). A decision
    // about either is refused entry rather than filtered at every read.
    let consent_cache = ConsentCache::for_people_only(owner.clone(), bridge_bots.clone());
    let snapshot_source = match config.consent_snapshot() {
        Some((url, token)) => Some(consent::GatewaySnapshot::new(url, token)?),
        None => None,
    };
    if !bring_up_consent(
        jetstream.clone(),
        consent_cache.clone(),
        snapshot_source,
        registry.clone(),
        metrics.clone(),
    )
    .await
    {
        return Ok(());
    }

    let own_user = client.user_id().unwrap().to_owned();

    // Observation scope is invitation-driven: join when the inviter is a
    // configured bridge provisioning user or the operator, ignore everyone
    // else. No room is observed by default.
    {
        let allowed = config.allowed_inviters.clone();
        let own_user = own_user.clone();
        let invite_metrics = metrics.clone();
        client.add_event_handler(
            move |event: StrippedRoomMemberEvent, room: Room, _client: Client| {
                let allowed = allowed.clone();
                let own_user = own_user.clone();
                let metrics = invite_metrics.clone();
                async move {
                    if event.state_key != own_user {
                        return;
                    }
                    if event.content.membership != MembershipState::Invite {
                        return;
                    }
                    let inviter = event.sender.to_string();
                    if allowed.contains(&inviter) {
                        info!(room = %room.room_id(), %inviter, "joining observed room");
                        if let Err(error) = room.join().await {
                            metrics.record_invite_failed();
                            warn!(room = %room.room_id(), %error, "failed to join invited room");
                        } else {
                            metrics.record_invite_joined();
                        }
                    } else {
                        // Counted, not only logged. A bridge bot missing from
                        // SENSOR_ALLOWED_INVITERS makes every conversation the
                        // user chooses land here, and the only symptom is a
                        // silence somewhere else entirely (#105).
                        let ignored = metrics.record_invite_ignored();
                        warn!(
                            room = %room.room_id(),
                            %inviter,
                            ignored,
                            "ignoring an invitation from a user SENSOR_ALLOWED_INVITERS does not \
                             name: if this is a bridge bot, this room's conversation will never \
                             reach the bus"
                        );
                    }
                }
            },
        );
    }

    // A room replaced another one (ADR 0029, issue #254): its `m.room.create`
    // names the predecessor. If the Sensor is still in that predecessor, it
    // leaves it — the register reads its membership there as `observing`,
    // and `observed_rooms` counts it, so a dead room kept would be one
    // conversation counted twice and reported observed where nothing can
    // arrive any more. The create event comes with the join's own state, so
    // this runs once per successor joined, and again harmlessly after a
    // restart's initial sync if the predecessor is somehow still held.
    client.add_event_handler(
        move |event: OriginalSyncRoomCreateEvent, room: Room, client: Client| async move {
            let Some(predecessor) = event.content.predecessor else {
                return;
            };
            let Some(dead) = client.get_room(&predecessor.room_id) else {
                return;
            };
            if dead.state() != RoomState::Joined {
                return;
            }
            match dead.leave().await {
                Ok(()) => info!(
                    room = %room.room_id(),
                    predecessor = %predecessor.room_id,
                    "joined a room that replaced another the Sensor was in, so it left the room it \
                     replaced: one conversation, one membership, one room counted"
                ),
                Err(error) => warn!(
                    room = %room.room_id(),
                    predecessor = %predecessor.room_id,
                    %error,
                    "could not leave the room this one replaced; it stays counted until it can"
                ),
            }
        },
    );

    // Inbound messages: normalize and publish. Text, media (image, video,
    // audio, file), sticker (relayed by some bridges as an m.room.message
    // msgtype) and location shapes produce events; other msgtypes (notices,
    // emotes, verification requests, ...) have no v1 shape and are skipped.
    {
        let jetstream = jetstream.clone();
        let own_user = own_user.clone();
        let owner = owner.clone();
        let bridge_bots = bridge_bots.clone();
        let replaced_rooms = replaced_rooms.clone();
        let registry = registry.clone();
        let unresolved_rooms = unresolved_rooms.clone();
        let consent_cache = consent_cache.clone();
        let publish_tracker = publish_tracker.clone();
        let metrics = metrics.clone();
        client.add_event_handler(move |event: OriginalSyncRoomMessageEvent, room: Room, _client: Client| {
            let jetstream = jetstream.clone();
            let own_user = own_user.clone();
            let owner = owner.clone();
            let bridge_bots = bridge_bots.clone();
            let replaced_rooms = replaced_rooms.clone();
            let registry = registry.clone();
            let unresolved_rooms = unresolved_rooms.clone();
            let consent_cache = consent_cache.clone();
            let publish_tracker = publish_tracker.clone();
            let metrics = metrics.clone();
            async move {
                if event.sender == own_user {
                    return; // never loop on our own outbound traffic
                }
                if dropped_as_a_replaced_room(&room, "message", &metrics, &replaced_rooms).await {
                    return;
                }
                // A bridge's own bot posts into the portal rooms it maintains
                // (issue #152). Most of what it says is an `m.notice`, which
                // has no v1 shape and is skipped below anyway — but not all of
                // it is, and the point is not the msgtype: the bot is a
                // service identity, so it must not reach the consent cache or
                // acquire a `contact` object, whatever it sends.
                if dropped_as_a_bridge_bot(&bridge_bots, &event.sender, "message", &metrics) {
                    return;
                }
                if let Some(Relation::Replacement(replacement)) = &event.content.relates_to {
                    // An edit is a new event (`* new text` fallback body)
                    // replacing an earlier one: no v1 event type exists for
                    // it, and publishing it would read as a fresh message.
                    tracing::debug!(
                        room = %room.room_id(),
                        event_id = %event.event_id,
                        replaces = %replacement.event_id,
                        "skipping message edit, no v1 event type"
                    );
                    return;
                }
                let Some(attachments) = attachments_for(&event.content.msgtype) else {
                    return; // no v1 shape for this msgtype
                };
                let body = event.content.body().to_owned();
                let sender: OwnedUserId = event.sender.clone();
                let bridge_contents = room_bridge_contents(&room).await;
                // Unresolvable means a bridge marked this room but named
                // no network this version knows: an unsupported portal, not
                // native Matrix traffic, which resolves to `matrix`.
                let Some(network) = network::resolve(&bridge_contents, sender.localpart()) else {
                    warn!(room = %room.room_id(), %sender, "cannot determine the network, skipping event");
                    return;
                };
                let Some(connection) =
                    connection_of(&room, network, &registry, &unresolved_rooms, &metrics).await
                else {
                    return;
                };

                // The user's own message. Its own event type, the operator's
                // Matrix ID as the subject, and no consent extension at all:
                // the extension carries a contact's decision, and the user is
                // not a contact (ADR 0018). Nothing below this branch runs
                // for it — the consent cache is not consulted, no contact is
                // resolved, and no display name of the operator's reaches the
                // bus, so the user never enters the consent model.
                if let Some(owner) = owner.as_ref().filter(|o| o.is_owner(sender.as_str())) {
                    let (reply_target, thread_root) = relation_targets(&event.content);
                    let reply_to = match reply_target {
                        Some(parent_id) => Some(normalize::ReplyTo {
                            matrix_event_id: parent_id.to_string(),
                            // The quoted message is somebody else's content
                            // travelling inside the user's event, and the
                            // user's own message is not a way around their
                            // own decision about that person (issue #110).
                            quoted: quoted_message(
                                &room,
                                &parent_id,
                                &own_user,
                                Some(owner),
                                &bridge_bots,
                                &consent_cache,
                                &connection,
                            )
                            .await,
                        }),
                        None => None,
                    };
                    let input = normalize::OutboundMessage {
                        matrix_event_id: event.event_id.to_string(),
                        matrix_room_id: room.room_id().to_string(),
                        server_name: own_user.server_name().as_str().to_owned(),
                        owner_matrix_id: owner.matrix_id().to_owned(),
                        body,
                        network,
                        connection: connection.clone(),
                        reply_to,
                        thread_root: thread_root.map(|event_id| event_id.to_string()),
                        attachments,
                        produced_at: rfc3339(std::time::SystemTime::now()),
                        network_timestamp: Some(rfc3339_ms(u64::from(event.origin_server_ts.0))),
                    };
                    let envelope = normalize::build_outbound_message_sent(&input);
                    publish_tracker
                        .publish(
                            jetstream,
                            normalize::OUTBOUND_MESSAGE_SENT_TYPE,
                            envelope,
                            network,
                            None,
                            metrics,
                        )
                        .await;
                    return;
                }

                let display_name = room
                    .get_member(&sender)
                    .await
                    .ok()
                    .flatten()
                    .and_then(|member| member.display_name().map(str::to_owned))
                    .unwrap_or_else(|| sender.localpart().to_owned());
                let consent = consent_cache.state(sender.as_str(), &connection);
                // The native network identifier is contact PII: derived
                // here, but published only for a granted contact (the
                // builders enforce the gate).
                let network_identifier =
                    network::ghost_network_identifier(network, sender.localpart());
                let (reply_target, thread_root) = relation_targets(&event.content);
                let reply_to = match reply_target {
                    Some(parent_id) => Some(normalize::ReplyTo {
                        matrix_event_id: parent_id.to_string(),
                        // A revoked sender's event keeps the relation and
                        // publishes no excerpt (ADR 0012), so the quoted
                        // message is not even fetched: the Sensor collects
                        // nothing it would not publish. Otherwise it is
                        // fetched with the author it belongs to, and the
                        // builder publishes it only if that author is
                        // granted (issue #110). An unreachable parent is not an error
                        // either: the reply still publishes, with an empty
                        // excerpt.
                        quoted: if consent.reduces_publication() {
                            None
                        } else {
                            quoted_message(&room, &parent_id, &own_user, owner.as_ref(), &bridge_bots, &consent_cache, &connection).await
                        },
                    }),
                    None => None,
                };
                let input = normalize::InboundMessage {
                    matrix_event_id: event.event_id.to_string(),
                    matrix_room_id: room.room_id().to_string(),
                    server_name: own_user.server_name().as_str().to_owned(),
                    sender: sender.to_string(),
                    body,
                    network,
                    connection: connection.clone(),
                    consent,
                    display_name,
                    network_identifier,
                    reply_to,
                    thread_root: thread_root.map(|event_id| event_id.to_string()),
                    attachments,
                    produced_at: rfc3339(std::time::SystemTime::now()),
                    // Bridge traffic carries the original network time in
                    // origin_server_ts (mautrix massages it through the
                    // appservice ts override), so for a portal room the
                    // timestamp is the source network's. On native Matrix
                    // traffic (ADR 0009) Matrix *is* the source network, and
                    // origin_server_ts is its own timestamp: the same field
                    // is the right answer for a different reason, and the
                    // homeserver's receive time still never masquerades as
                    // another network's.
                    network_timestamp: Some(rfc3339_ms(u64::from(event.origin_server_ts.0))),
                };
                let envelope = normalize::build_message_received(&input);
                publish_tracker
                    .publish(
                        jetstream,
                        normalize::MESSAGE_RECEIVED_TYPE,
                        envelope,
                        network,
                        Some(consent),
                        metrics,
                    )
                    .await;
            }
        });
    }

    // Decryption failures (ticket 04). matrix-sdk-crypto re-types an event
    // it decrypted to its inner type, so an m.room.encrypted event that
    // still reaches the handlers is one the crypto stack could not decrypt.
    // It is logged, counted and skipped — never fatal, never blocking the
    // other rooms. A key that arrives later does not re-dispatch the event
    // (no event cache), so a skipped event stays unpublished; portal rooms
    // share keys at send time, so live traffic does not hit this.
    {
        let metrics = metrics.clone();
        client.add_event_handler(move |event: OriginalSyncRoomEncryptedEvent, room: Room| {
            let metrics = metrics.clone();
            async move {
                let failures = metrics.record_decryption_failure();
                warn!(
                    room = %room.room_id(),
                    event_id = %event.event_id,
                    sender = %event.sender,
                    failures,
                    "cannot decrypt event, skipping it"
                );
            }
        });
    }

    // Inbound reactions: normalize and publish. Reaction removals arrive as
    // redactions, never as m.reaction events, so they produce no event, per
    // the contract.
    {
        let jetstream = jetstream.clone();
        let own_user = own_user.clone();
        let owner = owner.clone();
        let bridge_bots = bridge_bots.clone();
        let replaced_rooms = replaced_rooms.clone();
        let registry = registry.clone();
        let unresolved_rooms = unresolved_rooms.clone();
        let consent_cache = consent_cache.clone();
        let publish_tracker = publish_tracker.clone();
        let metrics = metrics.clone();
        client.add_event_handler(move |event: OriginalSyncReactionEvent, room: Room, _client: Client| {
            let jetstream = jetstream.clone();
            let own_user = own_user.clone();
            let owner = owner.clone();
            let bridge_bots = bridge_bots.clone();
            let replaced_rooms = replaced_rooms.clone();
            let registry = registry.clone();
            let unresolved_rooms = unresolved_rooms.clone();
            let consent_cache = consent_cache.clone();
            let publish_tracker = publish_tracker.clone();
            let metrics = metrics.clone();
            async move {
                if event.sender == own_user {
                    return; // never loop on our own outbound traffic
                }
                if dropped_as_a_replaced_room(&room, "reaction", &metrics, &replaced_rooms).await
                {
                    return;
                }
                // A bridge's own bot reacts: mautrix answers a command with
                // ✅ or ❌, and several bridges mark a message it could not
                // relay (issue #152). Same rule as a message.
                if dropped_as_a_bridge_bot(&bridge_bots, &event.sender, "reaction", &metrics) {
                    return;
                }
                let reactor: OwnedUserId = event.sender.clone();
                let Some(network) = resolve_network(&room, &reactor).await else {
                    warn!(room = %room.room_id(), %reactor, "cannot determine the network, skipping event");
                    return;
                };
                let Some(connection) =
                    connection_of(&room, network, &registry, &unresolved_rooms, &metrics).await
                else {
                    return;
                };

                // The user's own reaction. Its own event type, the operator's
                // Matrix ID as the subject, and no consent extension at all:
                // the extension carries a contact's decision, and the user is
                // not a contact (ADR 0021, symmetrical with ADR 0018's
                // `outbound.message.sent`). Nothing below this branch runs
                // for it — the consent cache is not consulted, so a
                // network-wide grant can no longer label the operator
                // `granted`, and no `contact` object is built, so neither
                // their display name nor the phone number their ghost
                // localpart carries reaches the bus.
                if let Some(owner) = owner.as_ref().filter(|o| o.is_owner(reactor.as_str())) {
                    let target_event_id = event.content.relates_to.event_id.clone();
                    // The targeted message is somebody else's content
                    // travelling inside the user's event, and reacting to a
                    // contact is not a way around the user's own decision
                    // about them (issue #110). There is no carrier decision
                    // to reduce publication here, so the builder consults
                    // the quoted author's alone.
                    let excerpt = quoted_message(
                        &room,
                        &target_event_id,
                        &own_user,
                        Some(owner),
                        &bridge_bots,
                        &consent_cache,
                        &connection,
                    )
                    .await;
                    let input = normalize::OutboundReaction {
                        matrix_event_id: event.event_id.to_string(),
                        matrix_room_id: room.room_id().to_string(),
                        server_name: own_user.server_name().as_str().to_owned(),
                        owner_matrix_id: owner.matrix_id().to_owned(),
                        reaction: event.content.relates_to.key.clone(),
                        target_event_id: target_event_id.to_string(),
                        target_excerpt: excerpt,
                        network,
                        connection: connection.clone(),
                        produced_at: rfc3339(std::time::SystemTime::now()),
                        // Bridges report network timestamps in bridge-specific
                        // fields; mapping them arrives with the enrichment work.
                        network_timestamp: None,
                    };
                    let envelope = normalize::build_outbound_reaction_added(&input);
                    publish_tracker
                        .publish(
                            jetstream,
                            normalize::OUTBOUND_REACTION_ADDED_TYPE,
                            envelope,
                            network,
                            None,
                            metrics,
                        )
                        .await;
                    return;
                }

                let display_name = room
                    .get_member(&reactor)
                    .await
                    .ok()
                    .flatten()
                    .and_then(|member| member.display_name().map(str::to_owned))
                    .unwrap_or_else(|| reactor.localpart().to_owned());
                let consent = consent_cache.state(reactor.as_str(), &connection);
                let network_identifier =
                    network::ghost_network_identifier(network, reactor.localpart());
                let target_event_id = event.content.relates_to.event_id.clone();
                // An excerpt quotes a message: for a revoked reactor it is
                // neither published nor fetched (ADR 0012). For every other
                // reactor it is fetched with the author it belongs to, and
                // the builder publishes it only if that author is granted
                // (issue #110).
                let excerpt = if consent.reduces_publication() {
                    None
                } else {
                    quoted_message(&room, &target_event_id, &own_user, owner.as_ref(), &bridge_bots, &consent_cache, &connection).await
                };
                let input = normalize::InboundReaction {
                    matrix_event_id: event.event_id.to_string(),
                    matrix_room_id: room.room_id().to_string(),
                    server_name: own_user.server_name().as_str().to_owned(),
                    reactor: reactor.to_string(),
                    reaction: event.content.relates_to.key.clone(),
                    target_event_id: target_event_id.to_string(),
                    target_excerpt: excerpt,
                    network,
                    connection: connection.clone(),
                    consent,
                    display_name,
                    network_identifier,
                    produced_at: rfc3339(std::time::SystemTime::now()),
                    // Bridges report network timestamps in bridge-specific
                    // fields; mapping them arrives with the enrichment work.
                    network_timestamp: None,
                };
                let envelope = normalize::build_reaction_added(&input);
                publish_tracker
                    .publish(
                        jetstream,
                        normalize::REACTION_ADDED_TYPE,
                        envelope,
                        network,
                        Some(consent),
                        metrics,
                    )
                    .await;
            }
        });
    }

    // A contact's presence. Presence updates in Matrix are NOT room-scoped:
    // they arrive in the sync response's presence list for every user sharing
    // a room with the Sensor (matrix-sdk dispatches them as `PresenceEvent`s
    // with no room context). Two consequences, and issue #150 is the second.
    //
    // The contract's `source` is a portal room URI, so one observed room has
    // to be named: the first, in room-id order, of the rooms that resolve to
    // the subject's own network — a tie-break among rooms that already agree,
    // which is all an ordering may ever decide here.
    //
    // The **network** is the subject's, from something that identifies them
    // (`network::subject_network`), and no longer the first bridged room in id
    // order. That sort was a fabrication with consequences: consent is looked
    // up by `(subject, network)`, so a native Matrix contact who is a member
    // of a bridged portal had their presence published as `whatsapp` and the
    // decision the user took about them *on Matrix* did not govern it. A
    // subject the Sensor cannot attribute to one network is not published at
    // all rather than published under a guess.
    //
    // Presence is best-effort: every failure mode logs and returns, so a
    // bridge without presence support can neither break nor slow the rest of
    // the pipeline.
    {
        let jetstream = jetstream.clone();
        let own_user = own_user.clone();
        let owner = owner.clone();
        let bridge_bots = bridge_bots.clone();
        let registry = registry.clone();
        let unresolved_rooms = unresolved_rooms.clone();
        let consent_cache = consent_cache.clone();
        let publish_tracker = publish_tracker.clone();
        let metrics = metrics.clone();
        client.add_event_handler(move |event: PresenceEvent, client: Client| {
            let jetstream = jetstream.clone();
            let own_user = own_user.clone();
            let owner = owner.clone();
            let bridge_bots = bridge_bots.clone();
            let registry = registry.clone();
            let unresolved_rooms = unresolved_rooms.clone();
            let consent_cache = consent_cache.clone();
            let publish_tracker = publish_tracker.clone();
            let metrics = metrics.clone();
            async move {
                let sender: OwnedUserId = event.sender.clone();
                if sender == own_user {
                    return; // never loop on our own presence
                }
                // A bridge's own bot, which is online for as long as the
                // bridge runs (issue #152). This is the path that produced
                // 1,150 of the reference deployment's 1,216 presence events —
                // two service accounts, two a minute, forever — and told
                // nobody anything: a robot is online.
                if dropped_as_a_bridge_bot(&bridge_bots, &sender, "presence", &metrics) {
                    return;
                }
                // The user's own presence is not published at all — no type
                // of its own, no event (ADR 0021). Unlike their message or
                // their reaction, it tells nobody anything they do not
                // already know: the user knows whether they are online. It
                // reaches here under any of their identities — a network
                // ghost the bridge materialised for them, or their own
                // Matrix account, which mautrix invites into every portal
                // room and whose presence transitions Synapse broadcasts to
                // everyone sharing a room, which is what made this the
                // highest-volume event on the reference deployment.
                //
                // A *contact's* presence is still published, and the test
                // for that is deliberate: the rule is the same one #109
                // established, an exact match against the identities the
                // deployment confirmed. An unconfirmed identity is a
                // contact, so failing safe here means publishing.
                if owner.as_ref().is_some_and(|o| o.is_owner(sender.as_str())) {
                    tracing::debug!(
                        %sender,
                        "skipping the operator's own presence, which is nobody's news"
                    );
                    return;
                }
                let presence = match event.content.presence.as_str() {
                    "online" => normalize::Presence::Online,
                    "offline" => normalize::Presence::Offline,
                    "unavailable" => normalize::Presence::Unavailable,
                    other => {
                        warn!(%sender, presence = %other, "unknown presence state, skipping event");
                        return;
                    }
                };
                // Presence EDUs carry no homeserver timestamp: the Sensor's
                // receipt instant is the natural key's receipt timestamp.
                // `time` and the id derive from this one instant (truncated
                // to milliseconds) so consumers can recompute the id.
                let receipt_timestamp_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
                    .unwrap_or_default();

                let mut shared_room_ids = Vec::new();
                for room in client.joined_rooms() {
                    let shares_room = room
                        .get_member(&sender)
                        .await
                        .ok()
                        .flatten()
                        .is_some_and(|member| *member.membership() == MembershipState::Join);
                    if shares_room {
                        shared_room_ids.push(room.room_id().to_owned());
                    }
                }
                if shared_room_ids.is_empty() {
                    return; // not an observed contact: shares no observed room
                }
                shared_room_ids.sort_unstable();
                // Every shared room that resolves to a network, in room-id
                // order. A room that resolves to nothing — a portal of a
                // bridge this version does not support — is left out, exactly
                // as it was before, and contributes nothing to the answer.
                let mut attributed: Vec<(Room, network::Network)> = Vec::new();
                for room_id in &shared_room_ids {
                    let Some(candidate) = client.get_room(room_id) else {
                        continue;
                    };
                    // A replaced room is not a conversation's address any
                    // more (ADR 0029): until the Sensor has left it, it must
                    // not be the room a presence is attributed to.
                    if replacement_room(&candidate).await.is_some() {
                        continue;
                    }
                    if let Some(network) = resolve_network(&candidate, &sender).await {
                        attributed.push((candidate, network));
                    }
                }
                if attributed.is_empty() {
                    // Rooms the subject shares, none of which any bridge this
                    // version supports marked: the answer before #150 and the
                    // answer now. Counted as well as warned, because it is a
                    // subject the bus never hears about.
                    let dropped = metrics.record_dropped(DropReason::UnattributableSubject);
                    warn!(
                        %sender,
                        dropped,
                        "cannot determine the network in any shared room, skipping event"
                    );
                    return;
                }
                let networks: Vec<network::Network> =
                    attributed.iter().map(|(_, network)| *network).collect();
                let network = match network::subject_network(sender.localpart(), &networks) {
                    network::SubjectNetwork::One(network) => network,
                    // Portals of several networks holding a subject that is a
                    // ghost of none of them, and which shares no unbridged
                    // room either: the honest answer is that the Sensor does
                    // not know. Publishing an arbitrary one would make the
                    // consent model read the row of a network this person may
                    // not be on (issue #150). At `warn` and counted, because a
                    // real person behind this is a person missing from the bus.
                    network::SubjectNetwork::Ambiguous(networks) => {
                        let dropped = metrics.record_dropped(DropReason::UnattributableSubject);
                        warn!(
                            %sender,
                            networks = ?networks.iter().map(|n| n.as_str()).collect::<Vec<_>>(),
                            dropped,
                            "not publishing presence: this subject is a member of portals of \
                             several networks and is a ghost of none of them, so naming one would \
                             be a guess — and consent is looked up by (subject, network)"
                        );
                        return;
                    }
                    // Unreachable from here: the shared-room list is not empty
                    // above, so a subject with no ghost prefix has at least one
                    // network and one with a prefix answers from it. Kept as an
                    // arm rather than an `unwrap` so that a future rule cannot
                    // turn it into a panic inside an event handler.
                    network::SubjectNetwork::Unattributable => {
                        let dropped = metrics.record_dropped(DropReason::UnattributableSubject);
                        warn!(
                            %sender,
                            dropped,
                            "cannot determine the network for this subject, skipping event"
                        );
                        return;
                    }
                };
                // The room to name as `source`: the first, in room-id order,
                // that resolves to the network already decided. The ordering is
                // a tie-break among rooms that agree and no longer decides
                // anything a consumer can read.
                //
                // Falling back to the first shared room when none of them
                // agrees is deliberate, and it is the rule about failing safe
                // rather than an oversight. It is reachable in one shape only —
                // a ghost of one bridge that shares nothing but another
                // bridge's portals, which is a misconfigured deployment — and
                // the alternative would be to drop a person for it. The
                // network stays the subject's own, which is the answer this
                // ticket is about; `source` names a room the subject shares,
                // which is all the contract claims of it, and the disagreement
                // is warned so it is not a silence.
                let Some((room, room_network)) = attributed
                    .iter()
                    .find(|(_, candidate)| *candidate == network)
                    .or_else(|| attributed.first())
                else {
                    return; // unreachable: the list is not empty above
                };
                if *room_network != network {
                    warn!(
                        %sender,
                        network = %network.as_str(),
                        room = %room.room_id(),
                        room_network = %room_network.as_str(),
                        "publishing presence with a source room of another network: no observed \
                         room this subject shares resolves to their own network, so the event \
                         names one they do share. A ghost that is only in another bridge's \
                         portals is a misconfigured deployment, and dropping the person would be \
                         worse than naming the room"
                    );
                }
                // The connection is the source room's (ADR 0033): presence is
                // not room-scoped, and the room chosen above is the one whose
                // perimeter this event is attributed to. With two
                // connections of one network holding the same subject, that
                // is the first shared room's connection, in room-id order —
                // the tie ADR 0027 lets an ordering break — and the consent
                // label is that perimeter's. A subject present through two
                // accounts is one presence event under one of them, not
                // two; a consumer that needs the other perimeter's answer
                // reads it off the messages, which are room-scoped. With two
                // connections of one network holding the same subject, that
                // is the first shared room's connection, in room-id order —
                // the tie ADR 0027 lets an ordering break — and the consent
                // label is that perimeter's. A subject present through two
                // accounts is one presence event under one of them, not
                // two; a consumer that needs the other perimeter's answer
                // reads it off the messages, which are room-scoped.
                let Some(connection) =
                    connection_of(&room, network, &registry, &unresolved_rooms, &metrics).await
                else {
                    return;
                };
                let display_name = room
                    .get_member(&sender)
                    .await
                    .ok()
                    .flatten()
                    .and_then(|member| member.display_name().map(str::to_owned))
                    .unwrap_or_else(|| sender.localpart().to_owned());
                let consent = consent_cache.state(sender.as_str(), &connection);
                let network_identifier =
                    network::ghost_network_identifier(network, sender.localpart());
                let last_active_at = event
                    .content
                    .last_active_ago
                    .map(|ago| rfc3339_ms(receipt_timestamp_ms.saturating_sub(u64::from(ago))));
                let input = normalize::InboundPresence {
                    matrix_user_id: sender.to_string(),
                    presence,
                    server_name: own_user.server_name().as_str().to_owned(),
                    matrix_room_id: room.room_id().to_string(),
                    network,
                    connection,
                    consent,
                    display_name,
                    network_identifier,
                    produced_at: rfc3339_ms(receipt_timestamp_ms),
                    receipt_timestamp_ms,
                    last_active_at,
                };
                let envelope = normalize::build_presence_updated(&input);
                publish_tracker
                    .publish(
                        jetstream,
                        normalize::PRESENCE_UPDATED_TYPE,
                        envelope,
                        network,
                        Some(consent),
                        metrics,
                    )
                    .await;
            }
        });
    }

    // Outbound: approved replies flow back from the bus into the portal
    // rooms. Runs concurrently with the sync loop, which feeds the client
    // the room knowledge the send path needs.
    {
        let client = client.clone();
        let owner_device = owner_device.clone();
        let jetstream = jetstream.clone();
        let retry_base = config.send_retry_base;
        let max_attempts = config.send_retry_max_attempts;
        let metrics = metrics.clone();
        let announcer = announcer.clone();
        tokio::spawn(async move {
            consume_approved_replies(
                client,
                owner_device,
                jetstream,
                retry_base,
                max_attempts,
                metrics,
                announcer,
            )
            .await;
        });
    }

    info!("sensor running");
    // The sync callback runs once per completed sync response: it drives the
    // sync-age gauge (the operator's lag signal). Boxed so the shutdown path
    // can drop the loop itself, not just a pinned reference to it.
    let sync_metrics = metrics.clone();
    // One sweep for predecessors still held across a restart (issue #254),
    // after the first sync has told the store what is joined.
    let swept_predecessors = Arc::new(AtomicBool::new(false));
    // The credential the owner's browser hands over arrives on this loop's
    // to-device channel (ADR 0034, #228), and only where there is an owner for it
    // to belong to: a deployment that names none has nothing to act as, so there
    // is nothing a handover could mean.
    let handovers = owner.as_ref().map(|owner| {
        Arc::new(Handovers {
            owner: owner.matrix_id().to_owned(),
            homeserver_url: config.homeserver_url.clone(),
            state_dir: config.state_dir.clone(),
            bridge_bots: bridge_bots.clone(),
            held: owner_device.clone(),
            metrics: metrics.clone(),
            announcer: announcer.clone(),
        })
    });
    let mut sync = Box::pin(client.sync_with_callback(SyncSettings::default(), {
        let client = client.clone();
        move |response: matrix_sdk::sync::SyncResponse| {
            sync_metrics.record_sync(now_unix_seconds());
            // Observation scope is invitation-driven and starts empty,
            // so how many rooms the Sensor is actually in is a fact
            // worth exposing rather than inferring from a silence
            // (#105). Read from the SDK's own state, after the sync
            // that may have changed it.
            let sweep = if swept_predecessors.swap(true, Ordering::Relaxed) {
                None
            } else {
                Some(client.clone())
            };
            let sync_metrics = sync_metrics.clone();
            let client = client.clone();
            let handovers = handovers.clone();
            async move {
                if let Some(client) = sweep {
                    leave_replaced_predecessors(&client).await;
                }
                if let Some(handovers) = &handovers {
                    receive_handovers(&client, &response.to_device, handovers).await;
                }
                sync_metrics.record_observed_rooms(client.joined_rooms().len() as u64);
                LoopCtrl::Continue
            }
        }
    }));
    tokio::select! {
        result = &mut sync => {
            result.context("sync loop failed")?;
        }
        _ = shutdown_signal() => {
            // Dropping the sync future stops the loop; publishes already in
            // flight live in the tracker (spawned, not awaited inline) and
            // are drained below. The bus consumers need no draining: a
            // message they leave unacked is redelivered after the ack
            // deadline, so at-least-once holds across the restart.
            info!("shutdown signal received, draining in-flight work");
            drop(sync);
            if publish_tracker.wait_for_idle(Duration::from_secs(5)).await {
                info!("in-flight publishes drained, shutting down");
            } else {
                warn!("shutdown timed out with publishes still in flight; the events stay dedup-able on the bus");
            }
        }
    }
    Ok(())
}

/// Resolves when the process is asked to stop (SIGTERM, or SIGINT from an
/// interactive operator).
async fn shutdown_signal() {
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("installing a SIGTERM handler never fails");
    tokio::select! {
        _ = sigterm.recv() => {}
        _ = tokio::signal::ctrl_c() => {}
    }
}

fn now_unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default()
}

/// Serves the Prometheus text exposition over HTTP/1.1, one connection at a
/// time, any path — the endpoint has exactly one document.
async fn serve_metrics(listener: tokio::net::TcpListener, metrics: Arc<Metrics>) {
    loop {
        match listener.accept().await {
            Ok((mut socket, _peer)) => {
                let metrics = metrics.clone();
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    // Drain the request head first (bounded); responding
                    // without reading risks an RST that discards the answer.
                    let mut request = Vec::with_capacity(1024);
                    let mut chunk = [0u8; 1024];
                    while !request.windows(4).any(|window| window == b"\r\n\r\n")
                        && request.len() < 8192
                    {
                        match socket.read(&mut chunk).await {
                            Ok(0) | Err(_) => break,
                            Ok(read) => request.extend_from_slice(&chunk[..read]),
                        }
                    }
                    let body = metrics.render(now_unix_seconds());
                    let response = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: text/plain; version=0.0.4; charset=utf-8\r\ncontent-length: {}\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                    let _ = socket.shutdown().await;
                });
            }
            Err(error) => warn!(%error, "metrics accept failed"),
        }
    }
}

/// Says on the bus whether this deployment can act as the owner (#404, ADR 0041).
///
/// One per run, holding the last state it published so that `from_state` is a real
/// transition and a state that has not changed is not republished — the contract's
/// `unknown` is the first event of a run, and a consumer reads it as the state.
///
/// Publishing is **best effort and never fatal**: a bus that refuses this event is
/// a bus that refuses everything else too, and the Sensor's job is to keep
/// observing. What the Companion Gateway loses is the freshness of one screen's
/// sentence, which it degrades to `unknown` on its own (ADR 0041).
struct OwnerDeviceAnnouncer {
    jetstream: async_nats::jetstream::Context,
    /// The homeserver's server name: the `source`'s authority, as every event the
    /// Sensor publishes spells it.
    server_name: String,
    /// The owner's Matrix ID. Without one there is nobody to name and nothing is
    /// published at all, which is why this is built only beside a configured owner.
    owner: String,
    metrics: Arc<Metrics>,
    last: tokio::sync::Mutex<Option<owner_device::DeviceState>>,
}

impl OwnerDeviceAnnouncer {
    fn new(
        jetstream: async_nats::jetstream::Context,
        server_name: String,
        owner: String,
        metrics: Arc<Metrics>,
    ) -> Self {
        Self {
            jetstream,
            server_name,
            owner,
            metrics,
            last: tokio::sync::Mutex::new(None),
        }
    }

    /// Publishes `to` when it differs from what this run last said.
    ///
    /// `device_id` is the device the state is about, absent when there is none. The
    /// instant is this process's own: the event's id is keyed on it, so two runs
    /// observing the same state publish two events — which is what the contract
    /// wants, since each is that run's own first word.
    async fn announce(&self, to: owner_device::DeviceState, device_id: Option<&str>) {
        let from = {
            let mut last = self.last.lock().await;
            if *last == Some(to) {
                return;
            }
            let previous = *last;
            *last = Some(to);
            previous
        };
        let occurred_at = rfc3339(std::time::SystemTime::now());
        let envelope = owner_device::state_changed(
            &self.server_name,
            &self.owner,
            device_id,
            from,
            to,
            &occurred_at,
        );
        let id = envelope["id"].as_str().unwrap_or_default().to_owned();
        let mut headers = async_nats::header::HeaderMap::new();
        headers.insert(async_nats::header::NATS_MESSAGE_ID, id.as_str());
        // No `network`, no `connection`, no `consent`: the headers duplicate the
        // envelope's extensions, and this event has none of them because it is
        // about no contact and no conversation. A consumer filtering on `consent`
        // is filtering for events about a person, and a persona's trigger
        // allowlist never names this type.
        let payload = serde_json::to_vec(&envelope).expect("the envelope is serializable");
        let subject = normalize::bus_subject(owner_device::STATE_CHANGED_TYPE);
        match self
            .jetstream
            .publish_with_headers(subject, headers, payload.into())
            .await
        {
            Ok(ack) => match ack.await {
                Ok(_) => {
                    self.metrics
                        .record_published(owner_device::STATE_CHANGED_TYPE);
                    info!(
                        %id,
                        from = from.map_or("unknown", owner_device::DeviceState::as_str),
                        to = to.as_str(),
                        device_id = device_id.unwrap_or("none"),
                        "said on the bus whether this deployment can act as the owner"
                    );
                }
                Err(error) => warn!(%id, %error, "the owner device's state was not acked"),
            },
            Err(error) => warn!(%id, %error, "the owner device's state could not be published"),
        }
    }
}

/// Counts publishes that are in flight (spawned, not yet acked) so a graceful
/// shutdown can drain them instead of cutting them off mid-request.
#[derive(Clone, Default)]
struct PublishTracker {
    in_flight: Arc<AtomicU64>,
    idle: Arc<tokio::sync::Notify>,
}

impl PublishTracker {
    /// Publishes through a detached task, awaited here: normal operation
    /// keeps the handler's ordering, while a shutdown that drops the handler
    /// futures leaves the publish running to completion.
    async fn publish(
        &self,
        jetstream: async_nats::jetstream::Context,
        event_type: &'static str,
        envelope: serde_json::Value,
        network: network::Network,
        consent: Option<Consent>,
        metrics: Arc<Metrics>,
    ) {
        self.in_flight.fetch_add(1, Ordering::Relaxed);
        let tracker = self.clone();
        let task = tokio::spawn(async move {
            publish_envelope(
                &jetstream, event_type, &envelope, network, consent, &metrics,
            )
            .await;
            if tracker.in_flight.fetch_sub(1, Ordering::Relaxed) == 1 {
                tracker.idle.notify_waiters();
            }
        });
        let _ = task.await;
    }

    /// True once no publish is in flight; false when the deadline expired.
    async fn wait_for_idle(&self, timeout: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let notified = self.idle.notified();
            if self.in_flight.load(Ordering::Relaxed) == 0 {
                return true;
            }
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                return self.in_flight.load(Ordering::Relaxed) == 0;
            }
        }
    }
}

/// Loads the Matrix session persisted in `session_file` (ticket 03).
/// Returns None — and the caller logs in fresh — when there is no file or
/// the file is unreadable or unparseable.
fn load_session(session_file: &Path) -> Option<MatrixSession> {
    if !session_file.is_file() {
        return None;
    }
    let session = std::fs::read_to_string(session_file)
        .with_context(|| format!("failed to read {}", session_file.display()))
        .and_then(|raw| {
            serde_json::from_str::<MatrixSession>(&raw)
                .with_context(|| format!("failed to parse {}", session_file.display()))
        });
    match session {
        Ok(session) => Some(session),
        Err(error) => {
            warn!(
                error = format!("{error:#}"),
                "persisted session is unusable, falling back to a fresh login"
            );
            None
        }
    }
}

/// True only when the homeserver positively rejects the access token with
/// `M_UNKNOWN_TOKEN` (device deleted, password changed, logged out). Any
/// other outcome — valid token, homeserver unreachable, unexpected answer —
/// keeps the persisted session: a transient failure must never cost the
/// device its crypto store.
async fn access_token_revoked(homeserver_url: &str, access_token: &str) -> bool {
    let url = format!(
        "{}/_matrix/client/v3/account/whoami",
        homeserver_url.trim_end_matches('/')
    );
    let response = matrix_sdk::reqwest::Client::new()
        .get(url)
        .bearer_auth(access_token)
        .timeout(Duration::from_secs(30))
        .send()
        .await;
    let response = match response {
        Ok(response) => response,
        Err(error) => {
            warn!(%error, "cannot check the persisted access token, restoring the session as is");
            return false;
        }
    };
    if response.status() != matrix_sdk::reqwest::StatusCode::UNAUTHORIZED {
        return false;
    }
    let body = response.text().await.unwrap_or_default();
    serde_json::from_str::<serde_json::Value>(&body)
        .ok()
        .is_some_and(|error| error["errcode"] == "M_UNKNOWN_TOKEN")
}

/// What the homeserver says an access token belongs to.
struct WhoAmI {
    user_id: String,
    /// The device the token was issued for. Synapse answers it for a device
    /// token; the specification makes it optional, so its absence is not an
    /// error.
    device_id: Option<String>,
}

/// Asks the homeserver whose token this is
/// (`GET /_matrix/client/v3/account/whoami`).
///
/// Deliberately raw HTTP and deliberately *before* any client is built: the
/// answer decides whether the Sensor may start at all, and building a client
/// first would open — and possibly create — a crypto store for a session that
/// is about to be refused.
async fn whoami(homeserver_url: &str, access_token: &str) -> Result<WhoAmI> {
    let url = format!(
        "{}/_matrix/client/v3/account/whoami",
        homeserver_url.trim_end_matches('/')
    );
    let response = matrix_sdk::reqwest::Client::new()
        .get(url)
        .bearer_auth(access_token)
        .timeout(Duration::from_secs(30))
        .send()
        .await
        .context("the whoami request failed")?;
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    if !status.is_success() {
        anyhow::bail!("the homeserver answered whoami with {status}: {body}");
    }
    let answer: serde_json::Value =
        serde_json::from_str(&body).context("the whoami answer is not JSON")?;
    Ok(WhoAmI {
        user_id: answer["user_id"]
            .as_str()
            .context("the whoami answer carries no user_id")?
            .to_owned(),
        device_id: answer["device_id"].as_str().map(str::to_owned),
    })
}

/// The **owner device** (`CONTEXT.md`) — the device of the owner's own account
/// that Twalk acts through — which is not the same device for the life of the
/// process (#228, ADR 0034).
///
/// Before this it was an `Option<Client>` built at startup and captured by the
/// send path, which was true while the only way to get one was configuration.
/// A credential now arrives from the owner's browser **while the Sensor runs**,
/// and a deployment that had to be restarted to use it would be one whose
/// onboarding reported success and changed nothing — so the send path reads this
/// cell per approval, exactly as it already asks the metrics per approval whether
/// the credential it holds is still good (#229).
///
/// It also owns the device's own sync loop, because the two cannot be separated:
/// that loop is what joins portal rooms as the owner and what discovers a revoked
/// token, and a replaced device must not leave the previous one's loop running —
/// it would go on syncing a credential nothing acts through, and go on reporting
/// its room counts over the new device's.
struct OwnerDevice {
    held: tokio::sync::RwLock<Held>,
}

/// The client and the task that syncs it; neither outlives the other.
#[derive(Default)]
struct Held {
    client: Option<Client>,
    syncing: Option<tokio::task::JoinHandle<()>>,
}

impl OwnerDevice {
    fn new() -> Self {
        Self {
            held: tokio::sync::RwLock::new(Held::default()),
        }
    }

    /// The device to act through now, or `None` — which is a deployment that was
    /// given none and is a supported state, not a fault.
    async fn current(&self) -> Option<Client> {
        self.held.read().await.client.clone()
    }

    /// The device this cell is holding, for the one decision that needs to know
    /// whether a handover is a *different* device: its crypto store.
    async fn device_id(&self) -> Option<String> {
        self.held
            .read()
            .await
            .client
            .as_ref()
            .and_then(|client| client.device_id().map(|device| device.to_string()))
    }

    /// Takes `client` as the device to act through, and starts its sync loop.
    ///
    /// A device already held is dropped and its loop aborted first. Aborting is
    /// what a replacement needs and what a graceful stop cannot give: the loop
    /// never returns by design (it retries for as long as the Sensor runs), so
    /// there is nothing to await.
    async fn hold(
        &self,
        client: Client,
        bridge_bots: BridgeBots,
        metrics: Arc<Metrics>,
        announcer: Option<Arc<OwnerDeviceAnnouncer>>,
    ) {
        let mut held = self.held.write().await;
        if let Some(previous) = held.syncing.take() {
            previous.abort();
        }
        let syncing = {
            let client = client.clone();
            tokio::spawn(
                async move { run_owner_device(client, bridge_bots, metrics, announcer).await },
            )
        };
        *held = Held {
            client: Some(client),
            syncing: Some(syncing),
        };
    }
}

/// Where the credential the owner device runs on came from, which is the only
/// thing two of its refusals need to name: the variable an operator would edit,
/// or the act a user would repeat. A refusal that named neither would be one
/// nobody can do anything about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CredentialFrom {
    /// `SENSOR_OWNER_DEVICE_ACCESS_TOKEN`: provisioned by script, and an
    /// operator's to fix.
    Configuration,
    /// The owner's browser, over the handover room (ADR 0034). Theirs to repeat,
    /// and arriving while this process runs.
    AHandover,
}

impl CredentialFrom {
    fn as_str(self) -> &'static str {
        match self {
            Self::Configuration => "SENSOR_OWNER_DEVICE_ACCESS_TOKEN",
            Self::AHandover => "the credential the owner's browser handed over",
        }
    }
}

/// The credential a previous run was handed, as [`owner_device::CREDENTIAL_FILE`]
/// holds it.
///
/// A file that is not there is the ordinary case and says nothing; a file that is
/// there and unreadable is a `warn` and nothing more, because the deployment can
/// still run as `@sensor:` and the remedy is to onboard again — refusing to start
/// over it would take a working Sensor down for a credential it never had.
fn load_held_credential(path: &Path) -> Option<owner_device::Handover> {
    if !path.is_file() {
        return None;
    }
    let read = std::fs::read_to_string(path)
        .map_err(|error| error.to_string())
        .and_then(|text| {
            serde_json::from_str::<serde_json::Value>(&text).map_err(|error| error.to_string())
        });
    match read {
        Ok(document) => match owner_device::credential_in(&document) {
            Ok(handover) => Some(handover),
            Err(why) => {
                warn!(
                    file = %path.display(),
                    why = why.as_str(),
                    "the handed-over credential on the volume is not a credential: ignoring it and \
                     acting as the Sensor's own account until onboarding hands over another"
                );
                None
            }
        },
        Err(error) => {
            warn!(
                file = %path.display(),
                %error,
                "the handed-over credential on the volume could not be read: ignoring it"
            );
            None
        }
    }
}

/// Builds the **second** Matrix client: a device of the owner's own account,
/// which is what a bridge relays to its network (ADR 0025, ADR 0034, #123).
///
/// `None` — no credential configured and none handed over — is the behaviour
/// every deployment had before ADR 0034: approved replies are posted by
/// `@sensor:`, and on a bridged conversation the contact receives nothing. That
/// is said once, here, at
/// startup, and named after the issue, because a degradation nobody is told
/// about is the failure this product has shipped repeatedly.
///
/// Three things this client deliberately does **not** have.
///
/// Its own **store subdirectory** (`owner_device::STORE_SUBDIR`), never the
/// Sensor's: a crypto store belongs to one device, and matrix-sdk refuses to
/// open one belonging to another (`CryptoStoreError::MismatchedAccount`).
///
/// `EncryptionSettings::default()`, which is to say **no cross-signing
/// bootstrap, no key backup and no backup download** — the opposite of the
/// Sensor's own settings a few dozen lines above. That is not an omission: all
/// four configured bridges carry `verification_levels.send: unverified`, so an
/// unverified device's messages are relayed like any other; cross-signing is
/// what a device needs to *read* encrypted history, and this one reads none.
/// It follows that this device needs no recovery key, which is the step ADR
/// 0025 called "the hard part" and which no automation may shortcut.
///
/// A credential from **either** of two places, and no session of its own. The
/// Sensor persists its own session because a fresh password login would mint a
/// new device each start. A *configured* credential needs no remembering for the
/// opposite reason: it arrives from the environment every start and names its
/// device. A **handed-over** one (#228, ADR 0034) arrives once, from a browser
/// the user has since closed, so it is the one thing here that is written down —
/// `owner_device::CREDENTIAL_FILE`, which is also what says which device the
/// crypto store beside it belongs to.
async fn bring_up_owner_device(
    config: &Config,
    owner: Option<&twalk_sensor::owner::Owner>,
    metrics: &Metrics,
) -> Result<BroughtUp> {
    let held = config
        .state_dir
        .as_ref()
        .map(|dir| dir.join(owner_device::CREDENTIAL_FILE))
        .as_deref()
        .and_then(load_held_credential);
    // Which credential, when there are two. The handed-over one wins, and the
    // reason is not a preference: it is the owner's own most recent act, taken in
    // their browser, and it is the remedy for the device the configured one names
    // having been revoked (#229). A deployment where configuration won would be
    // one that could never be re-onboarded — onboarding would report a handover
    // the Sensor acknowledged and go on acting through the old device.
    let credential = match (&held, config.owner_device()) {
        (Some(handover), configured) => {
            if let Some((_, configured_device)) = configured {
                if configured_device != handover.device_id {
                    info!(
                        handed_over = %handover.device_id,
                        configured = configured_device,
                        "acting through the device the owner's browser handed over, not the one \
                         SENSOR_OWNER_DEVICE_ACCESS_TOKEN names: a handover is the owner's own \
                         latest decision and the remedy for a revoked device (ADR 0034). The \
                         configured one is left alone — it is a device of their account like any \
                         other and theirs to revoke"
                    );
                }
            }
            (handover.access_token.as_str(), handover.device_id.as_str())
        }
        (None, Some((access_token, device_id))) => (access_token, device_id),
        (None, None) => {
            info!(
                "no device of the owner's account configured (SENSOR_OWNER_DEVICE_ACCESS_TOKEN) \
                 and none handed over: approved replies are posted by the Sensor's own account, \
                 which a mautrix bridge does not relay to its network — on a bridged conversation \
                 the contact receives nothing, and the Sensor says so per reply on \
                 twalk.persona.reply.approved.v1.posted (reach=nobody). This is issue #123's \
                 defect, degraded on purpose rather than silently; onboarding hands one over \
                 (ADR 0034), and a deployment provisioned by script sets the variable"
            );
            return Ok(BroughtUp::without_a_device(
                owner_device::DeviceState::NotConfigured,
            ));
        }
    };
    let Some(owner) = owner else {
        // Configuration guarantees an owner beside a *configured* credential, and
        // a handover is only ever accepted when one is configured — so this is a
        // deployment whose SENSOR_OWNER was taken away after a handover. Not
        // fatal: the Sensor observes and publishes exactly as it did, and nothing
        // can act as an owner nobody named.
        warn!(
            "a device credential is held and SENSOR_OWNER names nobody: nothing can be acted as, \
             so approved replies are posted by the Sensor's own account. Set SENSOR_OWNER to the \
             account the credential belongs to"
        );
        // Nothing is said on the bus either: the event names the owner, and there is
        // no owner to name (#404).
        return Ok(BroughtUp::without_a_device(
            owner_device::DeviceState::NotConfigured,
        ));
    };
    let (access_token, device_id) = credential;
    let device_id_owned = device_id.to_owned();
    let handed_over = held.is_some();
    let opened = open_owner_device(
        &config.homeserver_url,
        config.state_dir.as_deref(),
        owner.matrix_id(),
        access_token,
        device_id,
        if handed_over {
            CredentialFrom::AHandover
        } else {
            CredentialFrom::Configuration
        },
        false,
    )
    .await;
    let client = match opened {
        Ok(client) => client,
        // A **configured** credential that cannot be used is fatal, as it has
        // always been: it is an operator's to fix, and a Sensor that started
        // anyway would act as nobody while its configuration says otherwise.
        Err(error) if !handed_over => return Err(error),
        // A **handed-over** one is not, and the reason is a deadlock. The owner
        // revokes the device from their phone (which is ADR 0025's whole
        // mitigation and #229's whole subject) and restarts the deployment: the
        // credential is still on the volume, the homeserver no longer knows it,
        // and a Sensor that refused to start over that could not be re-onboarded
        // — the remedy needs a running Sensor to accept the new handover. So the
        // deployment starts, observes and publishes exactly as it did, and says
        // what is true: it was given a device and cannot act through it.
        Err(error) => {
            metrics.record_owner_device_present();
            metrics.record_owner_device_credential_gone();
            error!(
                device_id,
                %error,
                "the device the owner's browser handed over cannot be used — revoked, or the \
                 homeserver would not answer for it. This deployment observes and publishes as \
                 before and posts approved replies as its own account, which a bridge does not \
                 relay: twalk_sensor_owner_device_credential_gone is 1 and every reply to a \
                 bridged conversation is refused rather than silently delivered to nobody. The \
                 remedy is the owner's: onboard again in the Companion, which hands over a new \
                 device without a restart. The credential is kept, in case the homeserver was \
                 merely away"
            );
            return Ok(BroughtUp {
                client: None,
                state: owner_device::DeviceState::CredentialGone,
                device_id: Some(device_id_owned),
            });
        }
    };
    metrics.record_owner_device_present();
    info!(
        acting_as = owner.matrix_id(),
        device_id,
        handed_over,
        "holding a device of the owner's own account: approved replies are posted by it, so a \
         bridge relays them (ADR 0025). It observes nothing, publishes nothing, and reads no \
         history — no cross-signing and no recovery key (ADR 0034)"
    );
    Ok(BroughtUp {
        client: Some(client),
        state: owner_device::DeviceState::Present,
        device_id: Some(device_id_owned),
    })
}

/// What bringing the owner device up came to: the client when there is one, and the
/// state the deployment is in either way (#404).
///
/// The state is returned rather than inferred from `client.is_none()` because the two
/// reasons there is no client are different facts with different remedies — none was
/// ever given, or the one given is refused by the homeserver — and the approval screen
/// draws them differently.
struct BroughtUp {
    client: Option<Client>,
    state: owner_device::DeviceState,
    device_id: Option<String>,
}

impl BroughtUp {
    /// Nothing held, and the state that says why — which is never `Present`,
    /// because a deployment that holds no device cannot act as the owner.
    fn without_a_device(state: owner_device::DeviceState) -> Self {
        Self {
            client: None,
            state,
            device_id: None,
        }
    }
}

/// Builds the client one credential of the owner's account acts through, whether
/// it came from configuration or from the owner's browser (#228).
///
/// The two checks are the same for both and are made **before** the store is
/// touched, because a token for the wrong account is a configuration error whose
/// natural discovery is a contact receiving a reply from a stranger, and because
/// a device of somebody else's account joining portal rooms is worse than not
/// starting. They fail the caller: fatal at startup, and a handover the Sensor
/// does not acknowledge at runtime.
///
/// `clear_store` is for the second case. A crypto store belongs to one device —
/// matrix-sdk refuses to open one built by another
/// (`CryptoStoreError::MismatchedAccount`) — so a handover of a *different*
/// device is one whose store has to go. Deleting it rather than setting it aside
/// the way `set_stale_store_aside` does for the Sensor's own is the difference ADR
/// 0034 rests on: this device reads no history, holds no room keys anybody will
/// want again, and its identity dies with the credential it belonged to. The
/// directory may still be open by a reply in flight on the device being replaced;
/// on Linux unlinking an open sqlite file leaves that reply writing to an inode
/// nobody will read again, and the new store is built from new files.
///
/// A store that cannot be opened at all is cleared once and retried, even when
/// the caller did not ask: that is the state a deployment is in when its
/// credential file was removed by hand while the store on disk still belonged to
/// the device the file named, and a Sensor that refused to start over it would be
/// down for a credential it no longer has.
async fn open_owner_device(
    homeserver_url: &str,
    state_dir: Option<&Path>,
    owner: &str,
    access_token: &str,
    device_id: &str,
    source: CredentialFrom,
    clear_store: bool,
) -> Result<Client> {
    let identity = whoami(homeserver_url, access_token)
        .await
        .context("could not ask the homeserver whose owner-device credential this is")?;
    if identity.user_id != owner {
        anyhow::bail!(
            "{} belongs to {} and SENSOR_OWNER is {}: the device Twalk acts through must be \
             a device of the owner's own account, because that is the only account a bridge \
             relays. Refusing it rather than writing into conversations as somebody else",
            source.as_str(),
            identity.user_id,
            owner
        );
    }
    // The homeserver already knows which device the token was issued for, so
    // there is no reason to let matrix-sdk discover a mismatch later.
    if let Some(reported) = &identity.device_id {
        if reported != device_id {
            anyhow::bail!(
                "{} was issued for device {reported} and the deployment names {device_id}: the \
                 crypto store is bound to the device",
                source.as_str()
            );
        }
    }

    let store_dir = state_dir.map(|dir| dir.join(owner_device::STORE_SUBDIR));
    if clear_store {
        clear_owner_device_store(store_dir.as_deref(), device_id);
    }
    let session = MatrixSession {
        meta: matrix_sdk::SessionMeta {
            user_id: matrix_sdk::ruma::UserId::parse(owner)
                .context("SENSOR_OWNER is not a valid Matrix user ID")?,
            device_id: device_id.into(),
        },
        tokens: matrix_sdk::SessionTokens {
            access_token: access_token.to_owned(),
            refresh_token: None,
        },
    };
    match open_with_store(homeserver_url, store_dir.as_deref(), session.clone()).await {
        Ok(client) => Ok(client),
        Err(error) if store_dir.is_some() && !clear_store => {
            warn!(
                %error,
                device_id,
                "the owner device's crypto store could not be opened: clearing it and starting \
                 this device on a clean one. Nothing is lost — the device Twalk acts through reads \
                 no history and holds no room keys anybody will ask for again"
            );
            clear_owner_device_store(store_dir.as_deref(), device_id);
            open_with_store(homeserver_url, store_dir.as_deref(), session).await
        }
        Err(error) => Err(error),
    }
}

/// Builds the client and restores the session, which is where a store belonging
/// to another device is discovered.
async fn open_with_store(
    homeserver_url: &str,
    store_dir: Option<&Path>,
    session: MatrixSession,
) -> Result<Client> {
    let builder = Client::builder()
        .homeserver_url(homeserver_url)
        .with_encryption_settings(EncryptionSettings::default());
    let client = match store_dir {
        Some(dir) => builder.sqlite_store(dir, None).build().await,
        None => builder.build().await,
    }
    .context("failed to build the owner device's client")?;
    client
        .restore_session(session)
        .await
        .context("failed to start from the owner device's token")?;
    Ok(client)
}

/// Removes the crypto store the previous owner device built. Never fatal: a
/// store that cannot be removed is reported and the open below says what it means.
fn clear_owner_device_store(store_dir: Option<&Path>, for_device: &str) {
    let Some(dir) = store_dir else {
        return;
    };
    if !dir.exists() {
        return;
    }
    match std::fs::remove_dir_all(dir) {
        Ok(()) => info!(
            store = %dir.display(),
            device_id = for_device,
            "cleared the previous owner device's crypto store: a crypto store belongs to one \
             device, and this one reads no history"
        ),
        Err(error) => warn!(
            store = %dir.display(),
            %error,
            "could not clear the previous owner device's crypto store"
        ),
    }
}

/// Everything accepting a handover needs that a sync response does not carry
/// (#228, ADR 0034).
struct Handovers {
    /// The account a credential may belong to, and the only account a handover is
    /// accepted from. A deployment with no `SENSOR_OWNER` has none, and then
    /// nothing here runs at all.
    owner: String,
    homeserver_url: String,
    state_dir: Option<std::path::PathBuf>,
    /// The device's own sync loop needs them to tell a portal invitation from a
    /// room a stranger built, exactly as the startup path does.
    bridge_bots: BridgeBots,
    held: Arc<OwnerDevice>,
    metrics: Arc<Metrics>,
    /// Says on the bus that this deployment can act as the owner again, the moment
    /// a handover is taken (#404): that is what makes re-onboarding clear a revoked
    /// device on the approval screen with nothing else to do and no reload.
    announcer: Option<Arc<OwnerDeviceAnnouncer>>,
}

/// Reads the sync response's to-device events for the credential the owner's
/// browser hands over (ADR 0034, #228).
///
/// # Why here, and not in an event handler
///
/// The decision needs the event's `EncryptionInfo` — whether it decrypted, and
/// which device sent it — and that is what `ProcessedToDeviceEvent` carries and
/// what `add_event_handler` does not: a handler receives a deserialized event of a
/// type ruma knows, and this one is ours. It is also the only place where "it
/// arrived in the clear" and "it arrived and could not be decrypted" are still two
/// distinguishable facts.
///
/// # What it costs to look
///
/// Nothing for ordinary traffic: key requests, verification starts and everything
/// else on this channel are read no further than their `type`, and counted by
/// nothing. A **candidate** — the handover type, decrypted, from the owner's own
/// account — costs one `GET` of the handover room's offer, because the expected
/// device is a fact in that room and the store is the wrong place to read it
/// from: a room whose state has not arrived in a sync yet reads as a room with no
/// offer, and the handover it would refuse is the one the deployment is waiting
/// for. Only the owner's own devices can produce a candidate, so nobody else can
/// make this Sensor issue a request.
async fn receive_handovers(client: &Client, events: &[ProcessedToDeviceEvent], ctx: &Handovers) {
    for event in events {
        let (decrypted, sender, sender_device, raw) = match event {
            ProcessedToDeviceEvent::Decrypted {
                raw,
                encryption_info,
            } => (
                true,
                encryption_info.sender.to_string(),
                encryption_info
                    .sender_device
                    .as_ref()
                    .map(|device| device.to_string()),
                raw,
            ),
            ProcessedToDeviceEvent::PlainText(raw) => {
                (false, event_field(raw, "sender"), None, raw)
            }
            ProcessedToDeviceEvent::UnableToDecrypt {
                encrypted_event: unreadable,
                ..
            }
            | ProcessedToDeviceEvent::Invalid(unreadable) => {
                // Two ways an event cannot be read, and one answer. The type is
                // inside what could not be read, so neither can be *known* to be a
                // handover: an Olm message this Sensor has no session for, and one
                // whose ciphertext is not a well-formed Olm message at all
                // (measured: matrix-sdk reports the second as `Invalid`, not as a
                // decryption failure).
                //
                // Counted as a refused handover only when the owner has an offer
                // standing in the handover room and the event came from their
                // account: that is a deployment waiting for a credential that will
                // not arrive, and ADR 0034 records why it must read as a refusal
                // rather than as an error nobody recognises — hardening the
                // Sensor's trust requirement to `CrossSigned` turns this channel
                // into exactly these events.
                if event_field(unreadable, "sender") == ctx.owner
                    && !offers_standing(client, ctx).await.is_empty()
                {
                    ctx.metrics
                        .record_handover_refused(owner_device::NotAHandover::NotEncrypted);
                    warn!(
                        sender = %ctx.owner,
                        event_type = event_field(unreadable, "type"),
                        "a to-device event from the owner's account could not be read while a \
                         handover was offered in the handover room: no credential was taken from \
                         it. Onboarding will report that the Sensor never acknowledged one"
                    );
                }
                continue;
            }
        };
        let event_type = event_field(raw, "type");
        if event_type != owner_device::HANDOVER_EVENT_TYPE {
            continue;
        }
        // The offers are read only for a candidate: a plaintext event claiming this
        // type is refused on its encryption, and anybody can send one.
        let offers = if decrypted && sender == ctx.owner {
            offers_standing(client, ctx).await
        } else {
            Vec::new()
        };
        let content = serde_json::from_str::<serde_json::Value>(raw.json().get())
            .map(|event| event.get("content").cloned().unwrap_or_default())
            .unwrap_or_default();
        let delivered = owner_device::Delivered {
            event_type: &event_type,
            decrypted,
            sender: &sender,
            sender_device: sender_device.as_deref(),
        };
        // Asked of the policy once per offer standing, and once with none when
        // there are none: whether a delivery is a handover is
        // `owner_device::handover_in`'s to say, and what is here is only the facts
        // it needs. The room that offered this device is the room the
        // acknowledgement belongs in.
        let mut taken = None;
        // With no offer the policy refuses on the device, so that is the reason to
        // report unless an offer produced a **better** one: `Unreadable` and
        // `NotTheOwners` are facts about the delivery itself and say the same thing
        // whichever offer was passed, while a second `UnexpectedSender` says only
        // that another room expects another device. Keeping the last refusal would
        // report whichever offer happened to be read last.
        let mut refusal = owner_device::NotAHandover::UnexpectedSender;
        for (room, offered) in &offers {
            match owner_device::handover_in(&delivered, &content, Some(offered), &ctx.owner) {
                Ok(handover) => {
                    taken = Some((room.clone(), handover));
                    break;
                }
                Err(why) => {
                    if why != owner_device::NotAHandover::UnexpectedSender {
                        refusal = why;
                    }
                }
            }
        }
        if offers.is_empty() {
            refusal = owner_device::handover_in(&delivered, &content, None, &ctx.owner)
                .expect_err("a handover with nothing offered is refused");
        }
        match taken {
            Some((room, handover)) => {
                let offered_by = sender_device.unwrap_or_default();
                take_the_handover(&room, handover, &offered_by, ctx).await;
            }
            None => {
                let why = refusal;
                ctx.metrics.record_handover_refused(why);
                warn!(
                    why = why.as_str(),
                    sender = %sender,
                    sender_device = sender_device.as_deref().unwrap_or("none"),
                    offers = offers.len(),
                    "refused a to-device event claiming to hand over a device credential; nothing \
                     was taken from it and the Sensor goes on as it was. Anybody can send one, so \
                     twalk_sensor_handovers_refused_total is where this belongs as well as here"
                );
            }
        }
    }
}

/// One field of a to-device event, as the homeserver addressed it or the
/// decryption produced it. Absent, or not a string, reads as empty — which
/// matches nothing.
fn event_field(raw: &matrix_sdk::ruma::serde::Raw<AnyToDeviceEvent>, name: &str) -> String {
    raw.get_field::<String>(name)
        .ok()
        .flatten()
        .unwrap_or_default()
}

/// The rooms the owner's account and this Sensor share that were created to hand a
/// credential over (#226), as their own `m.room.create` names them.
///
/// Found rather than configured, and found by the two facts nobody can forge: the
/// room type `m.room.create` carries for its whole life — it can be neither
/// replaced nor redacted — and the owner being its creator. A room somebody else
/// built with the same type is not one of these.
///
/// **Rooms**, plural, and that is not pedantry. The Companion keeps one per owner
/// and finds it by its canonical alias, but the Sensor cannot rely on that being
/// the only one it is joined to: its account outlives any store, and a homeserver
/// several deployments have been onboarded against — every test stack, and any
/// owner who left a room and was onboarded again — holds more than one. A Sensor
/// that picked the first would read a stale offer and refuse the handover it was
/// waiting for. (Measured, and it is how this function came to be written this
/// way: the refusal said `sender_device` and `offered` were different devices, and
/// the offer it had read belonged to a room from a previous run.)
fn handover_rooms(client: &Client, owner: &str) -> Vec<Room> {
    client
        .joined_rooms()
        .into_iter()
        .filter(|room| {
            room.room_type()
                .is_some_and(|room_type| room_type.as_str() == owner_device::HANDOVER_ROOM_TYPE)
                && room.creators().is_some_and(|creators| {
                    creators.iter().any(|creator| creator.as_str() == owner)
                })
        })
        .collect()
}

/// Every device the owner has offered a handover from, and the room they offered
/// it in — read from the homeserver and not from the store.
///
/// The store is the wrong source for the same reason `the_room_is_a_portal` gives:
/// a room the Sensor is in whose state has not arrived in a sync yet answers "no
/// offer", and believing it would refuse the very handover this deployment is
/// waiting for. One `GET` per room, which in a deployment is one; an unreadable
/// answer is no offer, because a handover nobody offered is one nobody asked for.
async fn offers_standing(client: &Client, ctx: &Handovers) -> Vec<(Room, String)> {
    let mut offers = Vec::new();
    for room in handover_rooms(client, &ctx.owner) {
        let answer = client
            .send(get_state_event_for_key::v3::Request::new(
                room.room_id().to_owned(),
                owner_device::HANDOVER_OFFER_TYPE.into(),
                String::new(),
            ))
            .await;
        match answer {
            Ok(response) => {
                let content =
                    serde_json::from_str::<serde_json::Value>(response.event_or_content.get()).ok();
                if let Some(device) = owner_device::offered_from(content.as_ref()) {
                    offers.push((room, device.to_owned()));
                }
            }
            Err(error) => {
                // `M_NOT_FOUND` is the ordinary answer in a room where nothing has
                // been offered, and is not worth a line.
                if !matches!(
                    error.client_api_error_kind(),
                    Some(matrix_sdk::ruma::api::error::ErrorKind::NotFound)
                ) {
                    warn!(
                        room = %room.room_id(),
                        %error,
                        "could not read who the owner offered a device handover from in this room"
                    );
                }
            }
        }
    }
    offers
}

/// Holds a handed-over credential: uses it, writes it down, acts through it, and
/// only then says so in the handover room (#228).
///
/// The order is the whole of it, and each step is what makes the next one true.
/// The credential is **used** first — the same two checks the startup path makes,
/// on the account and the device — because a token that cannot be used is not a
/// credential this deployment holds. It is **written down** next, because the
/// acknowledgement means "this deployment holds it", and one that is only in
/// memory is one the next restart loses: a deployment that acted as the owner
/// until its next restart and silently stopped afterwards is the failure this
/// product has shipped repeatedly. It is **acted through** next, which is what
/// makes onboarding change anything at all without a restart. And it is
/// **acknowledged** last, because ADR 0034 says the Companion reports success
/// when the Sensor says it holds the credential and never when its own send
/// resolves — a to-device send to an untracked user resolves successfully having
/// sent nothing.
///
/// Every way this can fail leaves the acknowledgement unwritten, which is the
/// honest answer: onboarding reports a handover the Sensor never took, and the
/// user can hand over another one. The previous device is left alone — it is a
/// device of their account like any other, and revoking it is theirs to do from
/// any Matrix client, which is ADR 0025's own mitigation.
async fn take_the_handover(
    room: &Room,
    handover: owner_device::Handover,
    offered_by: &str,
    ctx: &Handovers,
) {
    let replacing = ctx.held.device_id().await;
    let clear_store = replacing
        .as_deref()
        .is_some_and(|held| held != handover.device_id);
    let opened = match open_owner_device(
        &ctx.homeserver_url,
        ctx.state_dir.as_deref(),
        &ctx.owner,
        &handover.access_token,
        &handover.device_id,
        CredentialFrom::AHandover,
        clear_store,
    )
    .await
    {
        Ok(client) => client,
        Err(error) => {
            error!(
                device_id = %handover.device_id,
                %error,
                "a credential was handed over and this Sensor cannot use it: nothing is \
                 acknowledged, so onboarding reports the handover failed rather than reporting a \
                 device this deployment does not have"
            );
            return;
        }
    };

    match &ctx.state_dir {
        Some(dir) => {
            let path = dir.join(owner_device::CREDENTIAL_FILE);
            let document = owner_device::credential_document(&handover).to_string();
            if let Err(error) = write_private_file(&path, document.as_bytes()) {
                error!(
                    file = %path.display(),
                    %error,
                    "a credential was handed over and could not be written down: nothing is \
                     acknowledged, because a credential this deployment loses on its next restart \
                     is not one it holds"
                );
                return;
            }
        }
        None => warn!(
            "a credential was handed over and there is no SENSOR_STATE_DIR to write it to: this \
             deployment acts through it now and loses it on its next restart. Configure a state \
             directory"
        ),
    }

    // The gauge and the bus are both told **before** the sync loop starts, and
    // the order is the point: `hold` spawns a loop that announces
    // `credential_gone` the moment a sync is refused, so a `present` published
    // after it could land last and leave the bus saying the deployment can act
    // while the gauge says it cannot. The credential has already been used
    // successfully to get here, so saying `present` now is not a guess.
    ctx.metrics.record_handover_held();
    if let Some(announcer) = &ctx.announcer {
        announcer
            .announce(
                owner_device::DeviceState::Present,
                Some(&handover.device_id),
            )
            .await;
    }
    ctx.held
        .hold(
            opened,
            ctx.bridge_bots.clone(),
            ctx.metrics.clone(),
            ctx.announcer.clone(),
        )
        .await;

    match room
        .send_state_event_raw(
            owner_device::HANDOVER_HELD_TYPE,
            "",
            owner_device::held(&handover, offered_by),
        )
        .await
    {
        Ok(_) => info!(
            device_id = %handover.device_id,
            offered_by,
            room = %room.room_id(),
            replacing = replacing.as_deref().unwrap_or("nothing"),
            "holding the device the owner's browser handed over, and said so in the handover \
             room: approved replies are posted by it from now on, so a bridge relays them \
             (ADR 0025, ADR 0034)"
        ),
        Err(error) => warn!(
            device_id = %handover.device_id,
            room = %room.room_id(),
            %error,
            "the credential is held and the acknowledgement could not be written in the handover \
             room: onboarding will report that the handover failed although this deployment has \
             it. The room's power levels are what let the Sensor write that one state event — a \
             room created before they granted it needs the Companion to add the exception"
        ),
    }
}

/// How long the owner-device's `/sync` may long-poll, and how long to wait
/// before retrying a failed one.
const OWNER_DEVICE_SYNC_TIMEOUT: Duration = Duration::from_secs(30);
const OWNER_DEVICE_RETRY_DELAY: Duration = Duration::from_secs(5);

/// The **minimum** sync that makes `room.send` work with Megolm, and why it is
/// the minimum.
///
/// matrix-sdk's send path is almost self-sufficient for encryption: for an
/// encrypted room, `Room::send` runs `ensure_room_encryption_ready`, which
/// fetches the member list over `/members` if it is stale, issues its own
/// `/keys/query` for members whose devices are untracked or dirty, claims
/// one-time keys and shares the Megolm session by sending the to-device
/// requests itself. None of that needs a sync loop.
///
/// Two things do. The Olm machine's **own** outgoing requests — chiefly the
/// upload of this device's identity keys, without which no recipient (the
/// bridge included) can make sense of the room keys it sends — are dispatched
/// by `Client::sync_once`, before and after the `/sync` call. And an
/// **invitation** only becomes visible in a sync response. So the loop is one
/// `sync_once` after another, and nothing more.
///
/// What the filter takes away is what a write-only device has no business
/// reading. `timeline.limit = 0`: no message events at all, which is ADR 0034's
/// "it never reads history" as a request parameter rather than as a promise —
/// and it costs nothing, because an invitation arrives as room *state*, not as
/// timeline. Presence and ephemeral events are dropped for the same reason
/// nothing subscribes to them here. Room **state** is kept, because it is what
/// makes a room known, joined and known-to-be-encrypted.
///
/// `set_presence: offline` is the one choice the ADRs do not settle, and it is
/// deliberate: syncing as `online` would have Synapse broadcast the owner's
/// account as online to everyone sharing a room with them — including, through
/// a bridge that relays presence, their contacts on the network — which would
/// make Twalk's own machinery visible as the user's presence. ADR 0021 already
/// decided the owner's presence is nobody's news; creating some would be worse
/// than not publishing it.
///
/// **No event handler is registered on this client.** That is the guarantee,
/// stronger than the filter: whatever a sync response carries, there is nothing
/// to dispatch it to and nothing that could publish it.
fn owner_device_sync_settings() -> SyncSettings {
    // ruma's filter types are `#[non_exhaustive]`, so each one starts from its
    // own default and only the fields this device wants are set.
    let nothing = || {
        let mut filter = EventTypeFilter::default();
        filter.not_types = vec!["*".to_owned()];
        filter
    };
    let no_room_events = || {
        let mut filter = RoomEventFilter::default();
        filter.not_types = vec!["*".to_owned()];
        filter
    };
    let mut timeline = RoomEventFilter::default();
    timeline.limit = Some(UInt::from(0u8));
    let mut room = RoomFilter::default();
    room.timeline = timeline;
    room.ephemeral = no_room_events();
    room.account_data = no_room_events();
    let mut filter = FilterDefinition::default();
    filter.presence = nothing();
    filter.account_data = nothing();
    filter.room = room;
    SyncSettings::default()
        .filter(sync_events::v3::Filter::FilterDefinition(filter))
        .timeout(OWNER_DEVICE_SYNC_TIMEOUT)
        .set_presence(PresenceState::Offline)
}

/// Drives the owner's device for as long as the Sensor runs: sync, then accept
/// whatever portal invitations arrived.
///
/// Never returns, and a failed sync is retried rather than fatal — the same
/// shape the bus consumers have, and for the same reason: the owner has to keep
/// being joined to portals as the bridges build them, one per conversation as it
/// becomes active, which on the reference deployment was eighteen new rooms in
/// one morning (ADR 0024, #105).
async fn run_owner_device(
    client: Client,
    bridge_bots: BridgeBots,
    metrics: Arc<Metrics>,
    // Says on the bus when this device's credential is gone (#404). `None` on a
    // deployment with no owner named, where the event would name nobody.
    announcer: Option<Arc<OwnerDeviceAnnouncer>>,
) {
    let settings = owner_device_sync_settings();
    // A refused invitation is refused on every sync, so the log line and the
    // counter would otherwise repeat forever. Each room is decided once per
    // process; the bounded memory cost is one room id per invitation the owner
    // holds, which is the same order as the number the homeserver already keeps.
    let mut decided = Decided::default();
    loop {
        match client.sync_once(settings.clone()).await {
            Ok(_) => {
                join_portal_invitations(&client, &bridge_bots, &metrics, &mut decided).await;
                metrics.record_owner_device_rooms(client.joined_rooms().len() as u64);
                metrics.record_owner_device_unjoinable_portals(decided.unjoinable.len() as u64);
            }
            Err(error) => match owner_device::after_refusal(matrix_errcode(&error).as_deref()) {
                owner_device::AfterRefusal::CredentialGone => {
                    // ADR 0025's mitigation for a long-lived token at rest is
                    // that the owner can revoke it from any Matrix client
                    // without Twalk's involvement — which is only a mitigation
                    // if revoking it produces a visible result (#229). So: said
                    // once at `error` with the credential and the remedy named,
                    // recorded on `/metrics` for a deployment nobody is
                    // watching the logs of, and this loop **ends**. Nothing in
                    // this process can put the token back, and a revocation
                    // retried every thirty seconds for ever is the silence
                    // wearing a warning's clothes.
                    metrics.record_owner_device_credential_gone();
                    error!(%error, "{}", owner_device::REVOKED_REMEDY);
                    // And on the bus, so the approval screen stops offering a
                    // delivery this deployment can no longer perform instead of
                    // the owner finding out by pressing the button (#404).
                    if let Some(announcer) = &announcer {
                        announcer
                            .announce(
                                owner_device::DeviceState::CredentialGone,
                                client.device_id().map(|device| device.as_str()),
                            )
                            .await;
                    }
                    return;
                }
                owner_device::AfterRefusal::Retry => {
                    warn!(
                        %error,
                        "the owner's device could not sync; approved replies stay unsendable as \
                         the user until it does, and are retried rather than reported as sent. \
                         Retrying"
                    );
                    tokio::time::sleep(OWNER_DEVICE_RETRY_DELAY).await;
                }
            },
        }
    }
}

/// What the owner-device loop has already decided about the invitations it
/// holds, so that nothing is said twice and nothing permanent is retried.
///
/// Per process, like the homeserver's own list of pending invitations it
/// mirrors: a restart re-decides each room once, which is one log line per
/// room per restart and not one per sync (issue #237).
#[derive(Default)]
struct Decided {
    /// Invitations refused on their inviter: decided once, never looked at again.
    refused: HashSet<matrix_sdk::ruma::OwnedRoomId>,
    /// Portals the homeserver refused to let the device join, in a way that
    /// will not change. Given up on, once. Their count is the gauge
    /// `twalk_sensor_owner_device_unjoinable_portals`.
    unjoinable: HashSet<matrix_sdk::ruma::OwnedRoomId>,
    /// Portals whose join failed transiently: how many times, and when the
    /// next attempt may be made. Removed on success, or when the failure
    /// turns out to be permanent.
    retrying: HashMap<matrix_sdk::ruma::OwnedRoomId, (u32, tokio::time::Instant)>,
}

/// The Matrix error code a failure carries, when it carries one: what
/// [`owner_device::after_refusal`] decides on (#229). `None` for anything that
/// is not a Matrix API error — nothing answered, TLS, a proxy's HTML page.
fn matrix_errcode(error: &matrix_sdk::Error) -> Option<String> {
    error
        .as_client_api_error()
        .and_then(|error| error.error_kind())
        .map(|kind| kind.errcode().to_string())
}

/// Reduces a failed join to what the homeserver answered, for
/// `owner_device::join_failure` to decide on.
fn join_answer(error: &matrix_sdk::Error) -> owner_device::JoinAnswer {
    let api_error = error.as_client_api_error();
    owner_device::JoinAnswer {
        status: api_error.map(|error| error.status_code.as_u16()),
        errcode: api_error
            .and_then(|error| error.error_kind())
            .map(|kind| kind.errcode().to_string()),
    }
}

/// Accepts the pending invitations that are portals of a configured bridge, and
/// refuses every other one.
///
/// The policy — and the reason a room id in an invitation may not be trusted —
/// is `twalk_sensor::owner_device::invitation`, which is where to argue with it;
/// whether a failed join is worth another try is
/// `twalk_sensor::owner_device::join_failure`. What is here is the I/O and what
/// gets said about it.
async fn join_portal_invitations(
    client: &Client,
    bridge_bots: &BridgeBots,
    metrics: &Metrics,
    decided: &mut Decided,
) {
    for room in client.invited_rooms() {
        let room_id = room.room_id().to_owned();
        if decided.refused.contains(&room_id) || decided.unjoinable.contains(&room_id) {
            continue;
        }
        if let Some((_, not_before)) = decided.retrying.get(&room_id) {
            if tokio::time::Instant::now() < *not_before {
                continue;
            }
        }
        let inviter = match room.invite_details().await {
            Ok(invite) => invite.inviter_id.to_string(),
            Err(error) => {
                // No `m.room.member` invite event for us in the stripped state:
                // there is no authenticated inviter to check, so there is
                // nothing that could make this a portal.
                warn!(
                    room = %room.room_id(),
                    %error,
                    "cannot read who invited the owner's device, leaving the invitation alone"
                );
                continue;
            }
        };
        match owner_device::invitation(&inviter, bridge_bots) {
            owner_device::Invitation::JoinPortal => {
                // The `m.bridge` marker is read *after* the decision and only
                // to name the network in the log line. It is the inviter's to
                // write, so it corroborates and never decides.
                let network = network::resolve(&room_bridge_contents(&room).await, "")
                    .map(|network| network.as_str());
                match room.join().await {
                    Ok(()) => {
                        decided.retrying.remove(&room_id);
                        let joined = metrics.record_owner_device_invite(OwnerDeviceInvite::Joined);
                        info!(
                            room = %room.room_id(),
                            %inviter,
                            network,
                            joined,
                            "the owner's device joined a portal of a configured bridge: replies \
                             posted here are relayed to the network as the user's own"
                        );
                    }
                    Err(error) => match owner_device::join_failure(&join_answer(&error)) {
                        owner_device::JoinFailure::Permanent => {
                            decided.retrying.remove(&room_id);
                            decided.unjoinable.insert(room_id);
                            let unjoinable =
                                metrics.record_owner_device_invite(OwnerDeviceInvite::Unjoinable);
                            warn!(
                                room = %room.room_id(),
                                %inviter,
                                network,
                                %error,
                                unjoinable,
                                "this portal can never be joined by the owner's device — the \
                                 homeserver's answer will not change — so an approved reply in \
                                 this conversation cannot be delivered as the user. Not retrying; \
                                 twalk_sensor_owner_device_unjoinable_portals counts it"
                            );
                        }
                        owner_device::JoinFailure::Transient => {
                            let attempt = decided.retrying.get(&room_id).map_or(1, |(n, _)| n + 1);
                            let delay = owner_device::retry_delay(attempt);
                            decided
                                .retrying
                                .insert(room_id, (attempt, tokio::time::Instant::now() + delay));
                            metrics.record_owner_device_invite(OwnerDeviceInvite::Failed);
                            warn!(
                                room = %room.room_id(),
                                %inviter,
                                %error,
                                attempt,
                                retry_in_secs = delay.as_secs(),
                                "the owner's device failed to join a portal for a reason that can \
                                 clear; retrying"
                            );
                        }
                    },
                }
            }
            owner_device::Invitation::Refuse(reason) => {
                if !decided.refused.insert(room_id) {
                    continue;
                }
                let refused = metrics.record_owner_device_invite(OwnerDeviceInvite::Refused);
                warn!(
                    room = %room.room_id(),
                    %inviter,
                    reason = reason.as_str(),
                    refused,
                    "not joining the owner's device to this room: only a portal invited by a \
                     bridge bot SENSOR_BRIDGE_BOTS names is joined, because everything else in an \
                     invitation — the room id, its name, its m.bridge marker — is chosen by \
                     whoever sent it"
                );
            }
        }
    }
}

/// The crypto store matrix-sdk's sqlite backend keeps in the state
/// directory; its `-wal`/`-shm` companions share this prefix.
const CRYPTO_STORE_FILE: &str = "matrix-sdk-crypto.sqlite3";

/// Moves the previous device's crypto store (and its dead session file)
/// into a timestamped `stale-store-*` subdirectory of `state_dir`, so the
/// new device starts on a clean crypto store (issue #28). Nothing is
/// deleted: the operator decides what to do with the old store.
///
/// Only the crypto store is bound to the device: in matrix-sdk 0.19 the
/// account check (`CryptoStoreError::MismatchedAccount`) lives in the
/// `OlmMachine` alone, while the state and event-cache stores are opened and
/// reloaded (rooms, sync token) on login and restore alike without any
/// user/device check. They are therefore kept, so the sync resumes from the
/// persisted token and the recent timeline is not re-emitted on the bus.
///
/// The subdirectory stays inside `state_dir` because that is typically a
/// volume mount point, which cannot be renamed itself, and a rename within
/// it never crosses filesystems.
fn set_stale_store_aside(state_dir: &Path) -> Result<()> {
    let entries = match std::fs::read_dir(state_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to list {}", state_dir.display()))
        }
    };
    let mut stale = Vec::new();
    for entry in entries {
        let name = entry?.file_name();
        let name_str = name.to_string_lossy();
        if name_str.starts_with(CRYPTO_STORE_FILE) || name_str == "session.json" {
            stale.push(name);
        }
    }
    if !stale
        .iter()
        .any(|name| name.to_string_lossy().starts_with(CRYPTO_STORE_FILE))
    {
        return Ok(()); // no crypto store yet: a first start, nothing to set aside
    }
    let stamp = now_unix_seconds();
    let mut aside = state_dir.join(format!("stale-store-{stamp}"));
    let mut suffix = 1;
    while aside.exists() {
        aside = state_dir.join(format!("stale-store-{stamp}-{suffix}"));
        suffix += 1;
    }
    std::fs::create_dir(&aside).with_context(|| format!("failed to create {}", aside.display()))?;
    for name in &stale {
        std::fs::rename(state_dir.join(name), aside.join(name))
            .with_context(|| format!("failed to move {} aside", name.to_string_lossy()))?;
    }
    warn!(
        moved_to = %aside.display(),
        "the persisted session is unusable: moved the previous device's crypto store aside and logging in as a \
         new device on a clean crypto store. The state store and sync token are kept, so nothing is re-emitted. \
         Megolm sessions held only by the old device cannot be decrypted by the new one unless \
         SENSOR_RECOVERY_KEY restores the key backup. Delete the moved directory once it is no longer needed."
    );
    Ok(())
}

/// Writes a file readable by its owner only — the session file holds an
/// access token. The write is atomic: the contents go to a temporary file
/// in the same directory, are flushed to disk, then renamed over `path`, so
/// a crash leaves either the old file or the new one, never a partial one.
fn write_private_file(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let mut tmp_name = path.file_name().unwrap_or_default().to_os_string();
    tmp_name.push(format!(".{}.tmp", std::process::id()));
    let tmp = dir.join(tmp_name);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| {
        let mut file = options.open(&tmp)?;
        file.write_all(contents)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&tmp, path)?;
        // Persist the rename itself (directory entry) where supported.
        if let Ok(dir) = std::fs::File::open(dir) {
            let _ = dir.sync_all();
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

fn rfc3339(time: std::time::SystemTime) -> String {
    time::OffsetDateTime::from(time)
        .format(&time::format_description::well_known::Rfc3339)
        .expect("RFC 3339 formatting is infallible")
}

/// Formats a milliseconds-since-epoch timestamp as RFC 3339 with exact
/// millisecond precision: parsing the result back yields the same number,
/// which the presence id's natural key includes.
fn rfc3339_ms(ms: u64) -> String {
    time::OffsetDateTime::from_unix_timestamp_nanos(i128::from(ms) * 1_000_000)
        .expect("millisecond timestamps are in range")
        .format(&time::format_description::well_known::Rfc3339)
        .expect("RFC 3339 formatting is infallible")
}

/// Reads the contents of every `m.bridge` state event of the room (the IO),
/// the mautrix portal markers identifying the network. Mautrix keys the
/// marker with the bridge's unique id (`<homeserver domain>/<appservice id>`
/// in bridgev2), so it is read regardless of state key; ordering by state
/// key keeps the choice deterministic when several bridges marked the room.
async fn room_bridge_contents(room: &Room) -> Vec<serde_json::Value> {
    let mut markers: Vec<(String, serde_json::Value)> = room
        .get_state_events("m.bridge".into())
        .await
        .unwrap_or_default()
        .iter()
        .filter_map(|raw| {
            let json = match raw {
                RawAnySyncOrStrippedState::Sync(raw) => raw.json().get(),
                RawAnySyncOrStrippedState::Stripped(raw) => raw.json().get(),
            };
            let mut event = serde_json::from_str::<serde_json::Value>(json).ok()?;
            let state_key = event.get("state_key")?.as_str()?.to_owned();
            Some((state_key, event.get_mut("content")?.take()))
        })
        .collect();
    markers.sort_by(|(left, _), (right, _)| left.cmp(right));
    markers.into_iter().map(|(_, content)| content).collect()
}

/// Whether this sender is one of the bridges' own bots, and therefore an
/// observed event to drop before anything resolves it as a subject (issue
/// #152): no consent lookup, no display name, no `contact` object, no event.
///
/// Counted as well as logged. Both facts an operator needs are in the count:
/// that the suppression is happening at all (a flat zero on a deployment with
/// bridges means `SENSOR_BRIDGE_BOTS` names an account that does not exist),
/// and how much of the stream it was. `debug` rather than `warn` for the line
/// itself, because on a healthy deployment this is the most frequent thing the
/// Sensor does.
fn dropped_as_a_bridge_bot(
    bridge_bots: &twalk_sensor::bridge_bot::BridgeBots,
    sender: &OwnedUserId,
    what: &str,
    metrics: &Metrics,
) -> bool {
    if !bridge_bots.contains(sender.as_str()) {
        return false;
    }
    let dropped = metrics.record_dropped(DropReason::BridgeBot);
    tracing::debug!(
        %sender,
        dropped,
        "dropping a bridge bot's {what}: a bridge's own bot is neither the owner nor a contact"
    );
    true
}

/// A room carrying an `m.room.tombstone` was **replaced**: the bridge posts
/// to the successor, and what still arrives here is stray — a notice the bot
/// left behind, a client that did not follow. Publishing it would attribute a
/// conversation to a room the register no longer lists (ADR 0029, issue
/// #254). Counted under its own reason, so the silence has a number, and
/// **said once per room**, naming the successor: the first stray event is the
/// fact worth a line, the rest are the same fact.
async fn dropped_as_a_replaced_room(
    room: &Room,
    what: &str,
    metrics: &Metrics,
    announced: &Mutex<HashSet<matrix_sdk::ruma::OwnedRoomId>>,
) -> bool {
    let Some(successor) = replacement_room(room).await else {
        return false;
    };
    let dropped = metrics.record_dropped(DropReason::TombstonedRoom);
    let first_time = announced
        .lock()
        .expect("the announced-rooms set is never poisoned")
        .insert(room.room_id().to_owned());
    if first_time {
        info!(
            room = %room.room_id(),
            successor = %successor,
            dropped,
            "a {what} arrived in a room that was replaced: nothing from it is published, the \
             conversation lives in its successor"
        );
    } else {
        tracing::debug!(room = %room.room_id(), %successor, dropped, "another {what} in a replaced room");
    }
    true
}

/// The connection a room's traffic belongs to (ADR 0033, #269), looked up in
/// the registry by the bridge bot the room's own `m.bridge` marker names —
/// never derived. `None` is a room no connection covers: nothing from it is
/// published, the drop is counted under its own reason, and the room is
/// said once, because a perimeter guessed wrong is a perimeter whose
/// decisions govern somebody else's messages.
async fn connection_of(
    room: &Room,
    network: network::Network,
    registry: &std::sync::RwLock<connection::Registry>,
    unresolved: &Mutex<HashSet<matrix_sdk::ruma::OwnedRoomId>>,
    metrics: &Metrics,
) -> Option<String> {
    let markers = room_bridge_contents(room).await;
    let bridge_bot = markers
        .iter()
        .find_map(|content| content.get("bridgebot").and_then(serde_json::Value::as_str))
        .map(str::to_owned);
    let resolution = registry
        .read()
        .expect("the registry lock is never poisoned")
        .resolve(bridge_bot.as_deref(), network);
    match resolution {
        connection::Resolution::Connection(id) => Some(id),
        connection::Resolution::Unknown { reason } => {
            let dropped = metrics.record_dropped(DropReason::UnknownConnection);
            let first_time = unresolved
                .lock()
                .expect("the unresolved-rooms set is never poisoned")
                .insert(room.room_id().to_owned());
            if first_time {
                warn!(
                    room = %room.room_id(),
                    network = network.as_str(),
                    bridge_bot = bridge_bot.as_deref().unwrap_or("none"),
                    dropped,
                    "no connection covers this room ({reason}): nothing from it is published \
                     until the Gateway's registry names it (GATEWAY_CONNECTIONS), because an \
                     event stamped with a guessed perimeter is one the wrong decisions govern"
                );
            }
            None
        }
    }
}

/// The room an `m.room.tombstone` names as this room's replacement, when the
/// room carries one. An empty or absent `replacement_room` is not a
/// replacement, whatever else the tombstone says.
async fn replacement_room(room: &Room) -> Option<String> {
    let events = room
        .get_state_events("m.room.tombstone".into())
        .await
        .ok()?;
    events.iter().find_map(|raw| {
        let json = match raw {
            RawAnySyncOrStrippedState::Sync(raw) => raw.json().get(),
            RawAnySyncOrStrippedState::Stripped(raw) => raw.json().get(),
        };
        serde_json::from_str::<serde_json::Value>(json)
            .ok()?
            .get("content")?
            .get("replacement_room")?
            .as_str()
            .filter(|successor| !successor.is_empty())
            .map(str::to_owned)
    })
}

/// Leaves every joined room that another joined room names as its
/// predecessor (ADR 0029, issue #254). The `m.room.create` handler does this
/// as a successor is joined; this is the same rule applied to what the store
/// already holds, because a sync resumed from a stored token does not deliver
/// a create event again, so a predecessor still held across a restart would
/// otherwise stay counted for ever.
async fn leave_replaced_predecessors(client: &Client) {
    let joined: HashSet<matrix_sdk::ruma::OwnedRoomId> = client
        .joined_rooms()
        .iter()
        .map(|room| room.room_id().to_owned())
        .collect();
    for room in client.joined_rooms() {
        let Some(predecessor) = room
            .create_content()
            .and_then(|create| create.predecessor)
            .map(|previous| previous.room_id)
        else {
            continue;
        };
        if !joined.contains(&predecessor) {
            continue;
        }
        let Some(dead) = client.get_room(&predecessor) else {
            continue;
        };
        match dead.leave().await {
            Ok(()) => info!(
                room = %room.room_id(),
                predecessor = %predecessor,
                "still in a room that another joined room replaced (a restart resumed past its \
                 create event): left the room it replaced"
            ),
            Err(error) => warn!(
                room = %room.room_id(),
                predecessor = %predecessor,
                %error,
                "could not leave the room this one replaced; it stays counted until it can"
            ),
        }
    }
}

/// Defers to the pure attribution policy in `network::resolve`.
async fn resolve_network(room: &Room, sender: &OwnedUserId) -> Option<network::Network> {
    network::resolve(&room_bridge_contents(room).await, sender.localpart())
}

/// Splits `m.relates_to` into the contract's reply target and thread root.
/// A threaded message's fallback `m.in_reply_to` (`is_falling_back: true`)
/// exists only for thread-unaware clients and is not a real reply.
fn relation_targets(
    content: &RoomMessageEventContent,
) -> (Option<OwnedEventId>, Option<OwnedEventId>) {
    match &content.relates_to {
        Some(Relation::Reply(reply)) => (Some(reply.in_reply_to.event_id.clone()), None),
        Some(Relation::Thread(thread)) => {
            let reply = match (&thread.in_reply_to, thread.is_falling_back) {
                (Some(in_reply_to), false) => Some(in_reply_to.event_id.clone()),
                _ => None,
            };
            (reply, Some(thread.event_id.clone()))
        }
        _ => (None, None),
    }
}

/// The contract requires both pixel dimensions, each at least 1 pixel.
fn dimensions(width: Option<UInt>, height: Option<UInt>) -> Option<(u64, u64)> {
    let (width, height) = (u64::from(width?), u64::from(height?));
    (width >= 1 && height >= 1).then_some((width, height))
}

fn duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// Maps an observed msgtype to its contract attachments, or None when the
/// msgtype produces no v1 event. Attachments are `mxc://` references into
/// Matrix media storage: the binary is never downloaded.
fn attachments_for(msgtype: &MessageType) -> Option<Vec<normalize::Attachment>> {
    let mxc_uri = |source: &MediaSource| match source {
        MediaSource::Plain(mxc) => mxc.to_string(),
        MediaSource::Encrypted(file) => file.url.to_string(),
    };
    // The decryption material of encrypted media, taken from ruma's own
    // serialization of the `EncryptedFile` rather than from the content JSON
    // as it sat on the event: ruma encodes the key, the counter block and
    // the digest in the canonical unpadded base64 the contract pins, each in
    // its own alphabet. `normalize` decides what is publishable.
    let encryption = |source: &MediaSource| match source {
        MediaSource::Plain(_) => None,
        MediaSource::Encrypted(file) => serde_json::to_value(file)
            .ok()
            .as_ref()
            .and_then(normalize::attachment_encryption),
    };
    let attachment = match msgtype {
        MessageType::Text(_) => return Some(Vec::new()),
        MessageType::Image(image) => normalize::Attachment {
            kind: normalize::AttachmentKind::Image,
            mxc_uri: mxc_uri(&image.source),
            mime_type: image.info.as_deref().and_then(|info| info.mimetype.clone()),
            size_bytes: image
                .info
                .as_deref()
                .and_then(|info| info.size.map(u64::from)),
            caption: image.caption().map(str::to_owned),
            dimensions: image
                .info
                .as_deref()
                .and_then(|info| dimensions(info.width, info.height)),
            duration_ms: None,
            encryption: encryption(&image.source),
        },
        MessageType::Video(video) => normalize::Attachment {
            kind: normalize::AttachmentKind::Video,
            mxc_uri: mxc_uri(&video.source),
            mime_type: video.info.as_deref().and_then(|info| info.mimetype.clone()),
            size_bytes: video
                .info
                .as_deref()
                .and_then(|info| info.size.map(u64::from)),
            caption: video.caption().map(str::to_owned),
            dimensions: video
                .info
                .as_deref()
                .and_then(|info| dimensions(info.width, info.height)),
            duration_ms: video
                .info
                .as_deref()
                .and_then(|info| info.duration.map(duration_ms)),
            encryption: encryption(&video.source),
        },
        MessageType::Audio(audio) => normalize::Attachment {
            kind: normalize::AttachmentKind::Audio,
            mxc_uri: mxc_uri(&audio.source),
            mime_type: audio.info.as_deref().and_then(|info| info.mimetype.clone()),
            size_bytes: audio
                .info
                .as_deref()
                .and_then(|info| info.size.map(u64::from)),
            caption: audio.caption().map(str::to_owned),
            dimensions: None,
            duration_ms: audio
                .info
                .as_deref()
                .and_then(|info| info.duration.map(duration_ms)),
            encryption: encryption(&audio.source),
        },
        MessageType::File(file) => normalize::Attachment {
            kind: normalize::AttachmentKind::File,
            mxc_uri: mxc_uri(&file.source),
            mime_type: file.info.as_deref().and_then(|info| info.mimetype.clone()),
            size_bytes: file
                .info
                .as_deref()
                .and_then(|info| info.size.map(u64::from)),
            caption: file.caption().map(str::to_owned),
            dimensions: None,
            duration_ms: None,
            encryption: encryption(&file.source),
        },
        // Geo messages carry no mxc URI and the contract's attachment shape
        // requires one: in v1 a location travels as the message body only.
        MessageType::Location(_) => return Some(Vec::new()),
        // Some bridges relay stickers as m.room.message with an m.sticker
        // msgtype; ruma leaves unknown msgtypes as raw content.
        MessageType::_Custom(_) if msgtype.msgtype() == "m.sticker" => {
            match normalize::attachment_from_sticker_data(msgtype.data().as_ref()) {
                Some(attachment) => attachment,
                // A sticker without a usable mxc URI still publishes as a
                // message (its body is the alt text), without an entry.
                None => return Some(Vec::new()),
            }
        }
        _ => return None,
    };
    Some(vec![attachment])
}

/// Fetches the target of a relation from the homeserver (via the SDK's
/// `Room::event`) and extracts a contract-capped excerpt of its body — the
/// plain text for a text message, the caption or filename for media, the geo
/// description for a location — **together with the author it belongs to**.
///
/// The author is the point (issue #110). An excerpt is the quoted person's
/// content, and the event that will carry it is labelled by whoever quoted
/// them: in a group those are two different contacts, so the excerpt has to
/// travel with its own author's consent state for the builder to decide. The
/// author is resolved on the network the *quoted* message is attributable to,
/// which is the key consent state is held under — a room's own network in
/// practice, but derived per author rather than assumed.
///
/// Three answers, and two of them withhold: the deployment's own account
/// (`QuotedAuthor::Owner` — the Sensor's Matrix ID, and every identity the
/// deployment confirmed as the operator's (ADR 0018), whose own words are
/// not a third party's and about whom there is no decision to consult), a
/// contact with the state of the user's decision about them, or `Unknown`
/// for an author no network can be attributed to. A
/// target that cannot be fetched or read at all yields `None` — one more way
/// an excerpt simply does not exist.
///
/// In an encrypted room — every portal room — the fetched event is
/// `m.room.encrypted`, and `Room::event` decrypts it with the Megolm session
/// the Sensor already holds, so the excerpt is the cleartext body (issue
/// #13). When it cannot — a session the Sensor never received — the event
/// stays typed as `m.room.encrypted` and does not match below, so the
/// excerpt is omitted: an unreachable or unreadable target is not an error,
/// the event still publishes, and ciphertext is never published as an
/// excerpt.
async fn quoted_message(
    room: &Room,
    event_id: &EventId,
    own_user: &OwnedUserId,
    owner: Option<&twalk_sensor::owner::Owner>,
    bridge_bots: &twalk_sensor::bridge_bot::BridgeBots,
    consent_cache: &ConsentCache,
    connection: &str,
) -> Option<normalize::QuotedExcerpt> {
    let timeline_event = room.event(event_id, None).await.ok()?;
    let AnySyncTimelineEvent::MessageLike(AnySyncMessageLikeEvent::RoomMessage(
        SyncMessageLikeEvent::Original(message),
    )) = timeline_event.raw().deserialize().ok()?
    else {
        return None;
    };
    let author = if &message.sender == own_user
        || owner.is_some_and(|owner| owner.is_owner(message.sender.as_str()))
    {
        normalize::QuotedAuthor::Owner
    } else if bridge_bots.contains(message.sender.as_str()) {
        // A bridge's own bot wrote the quoted message (issue #152). There is
        // no decision about it to consult, and asking the consent cache would
        // be asking about a robot — so it takes the same answer as an author
        // the Sensor cannot attribute: the excerpt is withheld, the event
        // still publishes with its relation intact. The general rule holds
        // here rather than #152's inversion of it: withholding an excerpt
        // costs a line of service output, not a person's visibility.
        normalize::QuotedAuthor::Unknown
    } else {
        // The quoted author's decision on this room's connection (#271):
        // the room is the perimeter, and the quoted message travelled in it.
        match resolve_network(room, &message.sender).await {
            Some(_) => normalize::QuotedAuthor::Contact(
                consent_cache.state(message.sender.as_str(), connection),
            ),
            None => normalize::QuotedAuthor::Unknown,
        }
    };
    if !author.is_granted() {
        // The builder is what decides, and it decides the same way for every
        // call site — but the text is dropped here all the same, so the
        // Sensor keeps holding nothing it would not publish, as it already
        // does by not fetching a revoked sender's quotation at all.
        //
        // Logged because the withholding is invisible in the published event
        // by construction: an operator seeing an excerpt go missing should be
        // able to tell "the person quoted is not granted" from "the Sensor
        // could not read the message".
        tracing::debug!(
            room = %room.room_id(),
            quoted_event = %event_id,
            quoted_author = %message.sender,
            "withholding the excerpt: the quoted author is not granted"
        );
        return Some(normalize::QuotedExcerpt {
            text: String::new(),
            author,
        });
    }
    Some(normalize::QuotedExcerpt {
        text: normalize::excerpt(message.content.body()),
        author,
    })
}

/// Publishes a CloudEvents envelope on the bus with the contract's headers:
/// NATS-Msg-Id (the JetStream dedup anchor) plus the network, consent and
/// traceparent extensions duplicated for server-side filtering.
async fn publish_envelope(
    jetstream: &async_nats::jetstream::Context,
    event_type: &str,
    envelope: &serde_json::Value,
    network: network::Network,
    consent: Option<Consent>,
    metrics: &Metrics,
) {
    let id = envelope["id"].as_str().unwrap().to_owned();
    let mut headers = async_nats::header::HeaderMap::new();
    headers.insert(async_nats::header::NATS_MESSAGE_ID, id.as_str());
    headers.insert("network", network.as_str());
    // The connection travels as a header too (ADR 0033, #269): the headers
    // duplicate the envelope's extensions so a consumer can select on them
    // without deserializing the event.
    if let Some(connection) = envelope
        .get("connection")
        .and_then(serde_json::Value::as_str)
    {
        headers.insert("connection", connection);
    }
    // `outbound.message.sent` carries no consent extension at all (ADR
    // 0018), and the headers duplicate the envelope's extensions for
    // server-side filtering — so a header the envelope does not have is one
    // the bus must not carry either. A consumer filtering on `consent` is
    // filtering for events about a contact, and this is not one.
    if let Some(consent) = consent {
        headers.insert("consent", consent.as_str());
    }
    if let Some(traceparent) = envelope
        .get("traceparent")
        .and_then(serde_json::Value::as_str)
    {
        headers.insert("traceparent", traceparent);
    }
    let payload = serde_json::to_vec(envelope).expect("the envelope is serializable");
    let subject = normalize::bus_subject(event_type);
    match jetstream
        .publish_with_headers(subject, headers, payload.into())
        .await
    {
        Ok(ack) => match ack.await {
            Ok(_) => {
                metrics.record_published(event_type);
                info!(%id, "published {}", event_type);
            }
            Err(error) => warn!(%id, %error, "publish ack failed"),
        },
        Err(error) => warn!(%id, %error, "publish failed"),
    }
}

/// How long to wait before rebuilding a failed or ended durable consumer.
const CONSUMER_RECONNECT_DELAY: Duration = Duration::from_secs(1);

/// Durably consumes `twalk.persona.reply.approved.v1` and posts each approved
/// reply into its target portal room. A message is acked only after a
/// successful post; a failed send is redelivered with an exponential backoff
/// (NAK with delay, driven by the JetStream delivered count), and once the
/// delivery attempts are exhausted the event moves to the dead-letter
/// subject — an approved reply is never silently dropped.
///
/// Never returns: if the consumer fails to build or its message stream ends,
/// it is rebuilt after a short delay — approved replies must keep flowing
/// for as long as the Sensor runs.
async fn consume_approved_replies(
    client: Client,
    owner_device: Arc<OwnerDevice>,
    jetstream: async_nats::jetstream::Context,
    retry_base: Duration,
    max_attempts: i64,
    metrics: Arc<Metrics>,
    announcer: Option<Arc<OwnerDeviceAnnouncer>>,
) {
    loop {
        match run_approved_reply_consumer(
            &client,
            &owner_device,
            &jetstream,
            retry_base,
            max_attempts,
            &metrics,
            announcer.as_ref(),
        )
        .await
        {
            Ok(()) => error!("the approved-reply message stream ended; rebuilding the consumer"),
            Err(error) => error!(%error, "the approved-reply consumer failed; rebuilding it"),
        }
        tokio::time::sleep(CONSUMER_RECONNECT_DELAY).await;
    }
}

/// One incarnation of the approved-reply consumer: builds the durable pull
/// consumer and processes its messages until the stream ends.
async fn run_approved_reply_consumer(
    client: &Client,
    owner_device: &OwnerDevice,
    jetstream: &async_nats::jetstream::Context,
    retry_base: Duration,
    max_attempts: i64,
    metrics: &Metrics,
    announcer: Option<&Arc<OwnerDeviceAnnouncer>>,
) -> Result<()> {
    let stream = jetstream
        .get_stream(normalize::STREAM_NAME)
        .await
        .context("failed to get the twalk stream")?;
    let consumer = stream
        .get_or_create_consumer(
            outbound::REPLY_CONSUMER,
            async_nats::jetstream::consumer::pull::Config {
                durable_name: Some(outbound::REPLY_CONSUMER.to_owned()),
                filter_subject: normalize::bus_subject(outbound::REPLY_APPROVED_TYPE),
                ack_policy: async_nats::jetstream::consumer::AckPolicy::Explicit,
                ..Default::default()
            },
        )
        .await
        .context("failed to ensure the approved-reply consumer")?;
    let dead_letter_subject = outbound::dead_letter_subject();
    info!(
        consumer = outbound::REPLY_CONSUMER,
        "consuming approved replies"
    );

    let mut messages = consumer
        .messages()
        .await
        .context("failed to open the approved-reply message stream")?;
    while let Some(message) = messages.next().await {
        let message = match message {
            Ok(message) => message,
            Err(error) => {
                warn!(%error, "approved-reply stream error, continuing");
                continue;
            }
        };
        let delivered = match message.info() {
            Ok(info) => info.delivered,
            Err(error) => {
                // The backoff schedule is driven by the delivered count;
                // without it, assume the first attempt — and say so, so the
                // restart of the schedule is never silent.
                warn!(%error, "no delivery info on an approved reply, assuming the first attempt");
                1
            }
        };
        let job = match serde_json::from_slice::<serde_json::Value>(&message.message.payload)
            .context("payload is not valid JSON")
            .and_then(|event| outbound::ApprovedReply::parse(&event))
        {
            Ok(outbound::Parsed::Ours(job)) => job,
            Ok(outbound::Parsed::AnotherComponents { connection }) => {
                // The collector's to send (#278): acknowledged untouched, so
                // one subject serves two senders without either dead-
                // lettering the other's work.
                info!(%connection, "an approved reply for a mail connection: the collector's, not the Sensor's");
                if let Err(error) = message.ack().await {
                    warn!(%error, "ack failed on another component's approval");
                }
                continue;
            }
            Err(error) => {
                // A malformed event can never be delivered: dead-letter it
                // on the spot instead of burning retries.
                error!(%error, "unusable persona.reply.approved event, dead-lettering");
                dead_letter(
                    &jetstream,
                    &dead_letter_subject,
                    &message,
                    &format!("the event could not be read: {error:#}"),
                    metrics,
                )
                .await;
                continue;
            }
        };
        // Asked per approval and not once at startup: the credential can be
        // revoked while this process runs, which is the whole of #229 — and since
        // #228 a credential can *arrive* while it runs too, so the device itself
        // is read here and not captured when the consumer was built.
        let held = owner_device.current().await;
        // The device this attempt acts through, for the event that says its
        // credential is gone (#404): read here, because by the time the send fails
        // the cell may already be holding another.
        let acting_device_id = held
            .as_ref()
            .and_then(|device| device.device_id().map(|id| id.as_str().to_owned()));
        let acting = match &held {
            Some(device) if metrics.owner_device_can_act() => Acting::OwnersDevice(device),
            Some(_) => Acting::CredentialGone,
            None => Acting::NotConfigured,
        };
        let outcome = post_approved_reply(client, acting, &job, metrics).await;
        // Said on the bus before the failure is handled (#404): the approval
        // screen has to stop offering a delivery this very process has just
        // refused, and the gauge `classify_send_error` already moved must not
        // disagree with what the bus says. Only reachable for a send made
        // *through the owner's device*, which is what `PostError::CredentialGone`
        // means — the Sensor's own account's token is a different situation with
        // a different remedy, and is classified as one.
        if let (Err(PostError::CredentialGone(_)), Some(announcer)) = (&outcome, announcer) {
            announcer
                .announce(
                    owner_device::DeviceState::CredentialGone,
                    acting_device_id.as_deref(),
                )
                .await;
        }
        match outcome {
            Ok(posted) => {
                metrics.record_reply_reach(posted.reach);
                // Reported before the ack, like the dead-letter copy is, so the
                // answer is on the bus before the work is called done. If the
                // report itself fails it is logged and the original is acked all
                // the same: the reply *was* posted, and leaving it unacked would
                // repost it on every redelivery for as long as the report keeps
                // failing.
                report_posted_reply(jetstream, &message, &job, &posted).await;
                if let Err(error) = message.ack().await {
                    warn!(id = %job.event_id, %error, "ack failed after a successful post");
                }
                // One line, and it says which identity spoke and what that
                // reached. Before this the line said "posted approved reply" for
                // both the case where the contact received it and the case where
                // the bridge silently ignored it (#216).
                if posted.reach.reaches_the_contact() {
                    info!(
                        id = %job.event_id,
                        room = %job.room_id,
                        posted_as = %posted.posted_as,
                        reach = posted.reach.as_str(),
                        traceparent = job.traceparent.as_deref(),
                        "posted approved reply"
                    );
                } else {
                    warn!(
                        id = %job.event_id,
                        room = %job.room_id,
                        posted_as = %posted.posted_as,
                        reach = posted.reach.as_str(),
                        traceparent = job.traceparent.as_deref(),
                        "posted approved reply into a portal room as the Sensor's own account: a \
                         mautrix bridge relays only the logged-in user's own account, so the \
                         contact receives nothing. Configure the owner's device \
                         (SENSOR_OWNER_DEVICE_ACCESS_TOKEN, issue #123)"
                    );
                }
            }
            Err(PostError::Permanent(error)) => {
                metrics.record_outbound_send_failure();
                error!(id = %job.event_id, room = %job.room_id, %error, "approved reply can never be posted, dead-lettering");
                dead_letter(
                    &jetstream,
                    &dead_letter_subject,
                    &message,
                    &format!("the reply can never be posted: {error:#}"),
                    metrics,
                )
                .await;
            }
            // A credential the homeserver has forgotten is *the same transient
            // failure* as any other here, and shares these two arms rather than
            // copying them: re-provisioning inside the retry schedule still
            // sends this reply, and letting the schedule run out dead-letters it
            // with that reason, which is what the approval screen reads (#311).
            Err(PostError::Transient(error) | PostError::CredentialGone(error))
                if delivered >= max_attempts =>
            {
                metrics.record_outbound_send_failure();
                error!(id = %job.event_id, room = %job.room_id, %error, %delivered, "approved reply exhausted its retries, dead-lettering");
                dead_letter(
                    &jetstream,
                    &dead_letter_subject,
                    &message,
                    &format!("the reply exhausted its {delivered} attempts: {error:#}"),
                    metrics,
                )
                .await;
            }
            Err(PostError::Transient(error) | PostError::CredentialGone(error)) => {
                metrics.record_outbound_send_failure();
                let delay = outbound::retry_delay(retry_base, delivered);
                warn!(id = %job.event_id, room = %job.room_id, %error, %delivered, ?delay, "approved reply send failed, scheduling a retry");
                if let Err(error) = message.ack_with(AckKind::Nak(Some(delay))).await {
                    error!(id = %job.event_id, %error, "nak failed, the message will be redelivered at the ack deadline");
                }
            }
        }
    }
    Ok(())
}

/// Base delay of the consent-snapshot retry backoff, and its ceiling. An
/// unreachable Gateway is retried for as long as the Sensor runs: until it
/// answers, every sender labels `pending`, which is a degradation to get out
/// of and not a state to settle in.
const SNAPSHOT_RETRY_BASE: Duration = Duration::from_secs(1);
const SNAPSHOT_RETRY_MAX: Duration = Duration::from_secs(60);

/// Brings up the consent cache: the Gateway's snapshot first, then the stream
/// from the position it named (ADR 0010, ticket #51).
///
/// The order is the whole mechanism. The cache is last-writer-wins, so
/// nothing arbitrates between the snapshot and the stream — they are made not
/// to overlap: the snapshot holds every decision up to its `stream_sequence`,
/// and the consumer is created at `next_stream_sequence`, which is the one
/// after it. A **cold** consumer therefore starts exactly where the snapshot
/// stops; a **warm** durable consumer already exists on the bus, and
/// `get_or_create_consumer` leaves it alone — its ack floor is its own record
/// of what it applied, and resetting it would either replay decisions or skip
/// them. What a warm consumer may still hold is the decisions taken while the
/// Sensor was down: unacked, before the snapshot's position, and already in
/// the snapshot. `run_consent_consumer` acks and skips those, so the boundary
/// holds on both paths and a decision is applied from exactly one of the two.
///
/// The snapshot is read **before the sync loop starts**, and the Sensor waits
/// for it. A healthy deployment therefore has no window at all in which a
/// granted contact labels `pending`, and — since #269 — none in which an
/// event is stamped with a connection the Gateway did not name: the registry
/// of connections arrives on the same snapshot, and an event stamped from a
/// guess is one the wrong decisions govern, for ever, on the bus. An earlier
/// version started anyway and retried in the background, on the premise that
/// a Sensor which waits for its Gateway loses inbound events. It does not:
/// the sync token is not advanced while nothing syncs, so Synapse holds what
/// arrives and delivers it when the loop starts — messages received during
/// the wait are delivered late, and none is lost or mislabelled. The cost is
/// stated rather than hidden: a Gateway that is down keeps this Sensor from
/// reading Matrix until it is back, which the log, the failure counter and
/// the sync-age gauge all say; and the retry answers a shutdown signal, so a
/// Sensor waiting on a Gateway that never comes still stops when asked. The
/// stream consumer is created only once a snapshot has been applied — that is
/// what keeps the ordering exact, and it costs nothing, because the Gateway
/// is the single writer of consent state (ADR 0006): while it is unreachable
/// there are no new decisions on the stream to miss, and the durable consumer
/// holds its place for the ones taken before.
///
/// Returns whether the Sensor should go on to read Matrix: `false` is a
/// shutdown signal received while waiting.
async fn bring_up_consent<S>(
    jetstream: async_nats::jetstream::Context,
    consent_cache: ConsentCache,
    source: Option<S>,
    registry: Arc<std::sync::RwLock<connection::Registry>>,
    metrics: Arc<Metrics>,
) -> bool
where
    S: ConsentSnapshotSource + 'static,
{
    let Some(source) = source else {
        info!(
            "no Companion Gateway configured (SENSOR_GATEWAY_URL): the consent cache starts \
             cold and senders label pending until a decision arrives on the bus; the registry \
             of connections is the implicit one — one connection per network, named after it \
             — which is correct while such a deployment has one bridge per network (ADR 0033)"
        );
        tokio::spawn(consume_consent_changes(
            jetstream,
            consent_cache,
            None,
            metrics,
        ));
        return true;
    };
    let snapshot = match source.fetch_snapshot().await {
        Ok(snapshot) => snapshot,
        Err(error) => {
            let failures = metrics.record_consent_snapshot_failure();
            error!(
                %error,
                failures,
                "could not read the Companion Gateway's consent snapshot: the Sensor waits for \
                 it and reads nothing from Matrix until then — the snapshot carries every \
                 granted contact and the registry of connections every event is stamped with, \
                 and an event published without them would be mislabelled or misattributed for \
                 ever. Nothing is lost meanwhile: the homeserver holds what arrives and delivers \
                 it once the sync starts. Retrying with backoff; check the Gateway at that URL"
            );
            tokio::select! {
                snapshot = retry_consent_snapshot(&source, &metrics) => snapshot,
                _ = shutdown_signal() => {
                    info!("shutdown signal received while waiting for the consent snapshot");
                    return false;
                }
            }
        }
    };
    let start = apply_consent_snapshot(&consent_cache, &snapshot, &registry, &metrics);
    tokio::spawn(consume_consent_changes(
        jetstream,
        consent_cache,
        Some(start),
        metrics,
    ));
    true
}

/// Applies a snapshot and returns the stream sequence the consumer starts at.
fn apply_consent_snapshot(
    consent_cache: &ConsentCache,
    snapshot: &consent::ConsentSnapshot,
    registry: &std::sync::RwLock<connection::Registry>,
    metrics: &Metrics,
) -> u64 {
    consent_cache.apply_snapshot(&snapshot.state);
    if let Some(handed) = &snapshot.connections {
        *registry
            .write()
            .expect("the registry lock is never poisoned") = handed.clone();
        info!(
            connections = handed.len(),
            handed_over = handed.handed_over(),
            "the registry of connections is the Gateway's: every event is stamped from it"
        );
    }
    metrics.record_consent_snapshot(snapshot.state.entries.len());
    // Each refusal counted, and each reason said once with its number: a
    // persona entry is not a refusal and gets no line.
    let mut refused: Vec<(consent::Unusable, usize)> = Vec::new();
    for why in &snapshot.state.unusable {
        if metrics.record_consent_refused(*why).is_some() {
            match refused.iter_mut().find(|(known, _)| known == why) {
                Some((_, count)) => *count += 1,
                None => refused.push((*why, 1)),
            }
        }
    }
    for (why, count) in &refused {
        warn!(
            reason = ?why,
            count,
            "the consent snapshot holds entries this Sensor refused: {}; their subjects stay \
             pending here rather than labelled by a guessed perimeter (#271)",
            why.explained()
        );
    }
    info!(
        entries = snapshot.state.entries.len(),
        next_stream_sequence = snapshot.state.next_stream_sequence,
        "applied the Companion Gateway's consent snapshot"
    );
    snapshot.state.next_stream_sequence
}

/// Retries the snapshot until it answers, doubling the delay up to a ceiling.
/// Never gives up: giving up would leave the Sensor observing nothing for
/// ever with nothing left to say so; the caller's shutdown signal is what
/// ends it.
async fn retry_consent_snapshot<S: ConsentSnapshotSource>(
    source: &S,
    metrics: &Metrics,
) -> consent::ConsentSnapshot {
    let mut delay = SNAPSHOT_RETRY_BASE;
    loop {
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(SNAPSHOT_RETRY_MAX);
        match source.fetch_snapshot().await {
            Ok(snapshot) => {
                info!("the Companion Gateway's consent snapshot is readable again");
                return snapshot;
            }
            Err(error) => {
                let failures = metrics.record_consent_snapshot_failure();
                warn!(
                    %error,
                    failures,
                    retry_in_seconds = delay.as_secs(),
                    "the Companion Gateway's consent snapshot is still unreadable; the Sensor \
                     is not reading Matrix until it is"
                );
            }
        }
    }
}

/// Durably consumes `twalk.consent.state.changed.v1` and applies each
/// decision to the consent cache, so subsequent events label the sender with
/// the current state. Applying a decision is idempotent, so an event is acked
/// as soon as it is applied; a malformed or persona-scoped event is acked and
/// skipped — it can never become applicable, and redelivering it would poison
/// the consumer.
///
/// `start_sequence` is the position the applied snapshot handed over at. A
/// consumer created here is created at it; an existing durable one keeps its
/// own ack floor — it is never reset — and this loop skips (acking) anything
/// before the boundary, which is what a warm consumer would otherwise
/// redeliver of decisions taken while the Sensor was down and already
/// summarised by the snapshot. `None` — no Gateway configured — means no
/// boundary and the deliver-all default: the whole retained history.
///
/// Never returns: if the consumer fails to build or its message stream ends,
/// it is rebuilt after a short delay — consent changes must keep flowing for
/// as long as the Sensor runs.
async fn consume_consent_changes(
    jetstream: async_nats::jetstream::Context,
    consent_cache: ConsentCache,
    start_sequence: Option<u64>,
    metrics: Arc<Metrics>,
) {
    loop {
        match run_consent_consumer(&jetstream, &consent_cache, start_sequence, &metrics).await {
            Ok(()) => error!("the consent-change message stream ended; rebuilding the consumer"),
            Err(error) => error!(%error, "the consent-change consumer failed; rebuilding it"),
        }
        tokio::time::sleep(CONSUMER_RECONNECT_DELAY).await;
    }
}

/// One incarnation of the consent-change consumer: builds the durable pull
/// consumer and applies its messages until the stream ends.
///
/// `get_or_create_consumer` is exactly the primitive this needs: it creates
/// the durable with the given configuration when none exists, and otherwise
/// returns the existing one untouched. So a cold start honours
/// `start_sequence` — the snapshot's `next_stream_sequence`, the first
/// decision the snapshot does not already hold — and a warm one resumes at
/// its own ack floor, which is the only record of what it has applied.
async fn run_consent_consumer(
    jetstream: &async_nats::jetstream::Context,
    consent_cache: &ConsentCache,
    start_sequence: Option<u64>,
    metrics: &Metrics,
) -> Result<()> {
    let stream = jetstream
        .get_stream(normalize::STREAM_NAME)
        .await
        .context("failed to get the twalk stream")?;
    let deliver_policy = match start_sequence {
        Some(start_sequence) => {
            async_nats::jetstream::consumer::DeliverPolicy::ByStartSequence { start_sequence }
        }
        None => async_nats::jetstream::consumer::DeliverPolicy::All,
    };
    let consumer = stream
        .get_or_create_consumer(
            consent::CONSENT_CONSUMER,
            async_nats::jetstream::consumer::pull::Config {
                durable_name: Some(consent::CONSENT_CONSUMER.to_owned()),
                filter_subject: normalize::bus_subject(consent::CONSENT_CHANGED_TYPE),
                ack_policy: async_nats::jetstream::consumer::AckPolicy::Explicit,
                deliver_policy,
                ..Default::default()
            },
        )
        .await
        .context("failed to ensure the consent-change consumer")?;
    let info = consumer.cached_info();
    info!(
        consumer = consent::CONSENT_CONSUMER,
        ack_floor = info.ack_floor.stream_sequence,
        deliver_policy = ?info.config.deliver_policy,
        requested_start = ?start_sequence,
        "consuming consent changes"
    );

    let mut messages = consumer
        .messages()
        .await
        .context("failed to open the consent-change message stream")?;
    while let Some(message) = messages.next().await {
        let message = match message {
            Ok(message) => message,
            Err(error) => {
                warn!(%error, "consent-change stream error, continuing");
                continue;
            }
        };
        // Never apply anything from before the position the snapshot handed
        // over at. A consumer created here already starts there; a warm
        // durable one starts at its own ack floor, which is *earlier* when
        // decisions were taken while the Sensor was down — those are in the
        // snapshot, and applying them again would replay a history the
        // snapshot has already summarised. Acked and skipped, so the floor
        // advances: the hand-off boundary is honoured on both paths.
        if let (Some(start), Some(info)) = (start_sequence, message.info().ok()) {
            if info.stream_sequence < start {
                if let Err(error) = message.ack().await {
                    warn!(%error, "consent-change ack failed, the event will be redelivered");
                }
                continue;
            }
        }
        match serde_json::from_slice::<serde_json::Value>(&message.message.payload) {
            Ok(event) => match consent::ConsentChange::parse(&event) {
                Ok(change) => {
                    consent_cache.apply(&change);
                    info!(
                        subject = change.subject_label(),
                        state = change.new_state.as_str(),
                        connections = ?change.connections,
                        "applied a consent change"
                    );
                }
                // A persona-scoped decision is well-formed traffic that
                // simply never labels a sender (ADR 0013) and is not
                // counted; a change that names no connection, or is
                // malformed, is counted and said (#271): the decision it
                // carries is one this Sensor will not guess the perimeter
                // of, and its sender stays labelled as before.
                Err(why) => {
                    if let Some(total) = metrics.record_consent_refused(why) {
                        warn!(
                            id = event
                                .get("id")
                                .and_then(serde_json::Value::as_str)
                                .unwrap_or("<none>"),
                            reason = ?why,
                            total,
                            "refused a consent.state.changed event: {}",
                            why.explained()
                        );
                    }
                }
            },
            Err(error) => {
                warn!(%error, "consent.state.changed payload is not valid JSON, skipping")
            }
        }
        if let Err(error) = message.ack().await {
            warn!(%error, "consent-change ack failed, the event will be redelivered");
        }
    }
    Ok(())
}

/// Publishes an undeliverable event to the dead-letter subject and acks the
/// original. The dead-letter copy gets its own stable `Nats-Msg-Id`, derived
/// from the event id (the approved reply itself is published under the event
/// id in the same stream, so reusing it would get the copy dropped as a
/// duplicate); the event id stays visible in the `event-id` header. The
/// event's `network`, `consent` and `traceparent` extensions are duplicated
/// as headers, like the inbound path does. If the publish itself fails the
/// message stays unacked, so it is redelivered while attempts remain rather
/// than disappearing.
async fn dead_letter(
    jetstream: &async_nats::jetstream::Context,
    subject: &str,
    message: &async_nats::jetstream::Message,
    reason: &str,
    metrics: &Metrics,
) {
    let mut headers = async_nats::header::HeaderMap::new();
    headers.insert(
        outbound::REASON_HEADER,
        reason
            .chars()
            .take(outbound::REASON_CAP)
            .collect::<String>()
            .as_str(),
    );
    let event = serde_json::from_slice::<serde_json::Value>(&message.message.payload).ok();
    // A malformed event may carry no usable id: fall back to the id it was
    // published under, if any.
    let event_id = event
        .as_ref()
        .and_then(|event| event.get("id"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .or_else(|| {
            message
                .message
                .headers
                .as_ref()
                .and_then(|headers| headers.get(async_nats::header::NATS_MESSAGE_ID))
                .map(|id| id.as_str().to_owned())
        });
    if let Some(id) = &event_id {
        headers.insert(
            async_nats::header::NATS_MESSAGE_ID,
            outbound::dead_letter_msg_id(id).as_str(),
        );
        headers.insert(outbound::EVENT_ID_HEADER, id.as_str());
    }
    if let Some(event) = &event {
        duplicate_extensions(event, &mut headers);
    }
    match jetstream
        .publish_with_headers(subject.to_owned(), headers, message.message.payload.clone())
        .await
    {
        Ok(ack) => match ack.await {
            Ok(ack) => {
                if ack.duplicate {
                    // The derived id is unique to this event's dead-letter
                    // copy: a duplicate means an earlier attempt already
                    // stored (and counted) it, but its ack of the original
                    // was lost. The copy is safe; just ack the original.
                    warn!(
                        id = event_id.as_deref(),
                        "dead-letter copy already stored, acking the redelivered original"
                    );
                } else {
                    metrics.record_dead_lettered();
                }
                if let Err(error) = message.ack().await {
                    error!(%error, "ack failed after dead-lettering, a duplicate may be dead-lettered again");
                }
            }
            Err(error) => {
                error!(%error, "dead-letter publish ack failed, leaving the message unacked")
            }
        },
        Err(error) => error!(%error, "dead-letter publish failed, leaving the message unacked"),
    }
}

/// A send that can never succeed (malformed target, content the Sensor cannot
/// render, a request the homeserver rejects as malformed) is permanent;
/// anything else may succeed on a later attempt, e.g. once the Sensor has
/// joined the target room or been granted the power to post in it (see
/// `classify_send_error`).
enum PostError {
    Permanent(anyhow::Error),
    Transient(anyhow::Error),
    /// Transient, and the reason is the one thing a caller acts on beyond the
    /// retry: the homeserver refuses the acting credential (#229). Retried like any
    /// transient failure — a re-provisioning inside the schedule still sends the
    /// reply — and said on the bus by the caller, so the approval screen stops
    /// offering a delivery this deployment has already refused (#404).
    CredentialGone(anyhow::Error),
}

/// One posted approved reply: which identity posted it, and what that reached.
struct Posted {
    /// What the message reached — the contact, or nobody (issue #216).
    reach: Reach,
    /// The Matrix ID that posted it: the owner's own account, or the Sensor's.
    posted_as: OwnedUserId,
}

/// What the send path may act as, as the outbound loop finds it.
///
/// Three states and not an `Option`, because the middle one is the whole of
/// #229: a deployment that was **given** a device of the owner's account and no
/// longer holds a working credential for it is in a different situation from one
/// that was never given a device, and the two want different answers. Asked per
/// approval, because a credential can be revoked while this process runs.
enum Acting<'a> {
    /// A device of the owner's own account, usable now.
    OwnersDevice(&'a Client),
    /// One was configured and the homeserver no longer knows its token.
    CredentialGone,
    /// None was configured: every deployment before ADR 0025, and a supported
    /// state rather than a fault.
    NotConfigured,
}

/// Posts one approved reply into its target room, as a native reply to the
/// original message when the approval names one, **as the owner's own account
/// wherever that is what the conversation needs** (ADR 0025, issue #123).
///
/// Which identity sends is the whole of this function's judgement, and it is
/// four cases.
///
/// The owner's device is a **joined member** of the target room: it sends. That
/// is the case the product is for — the reply really is the user's, so the
/// bridge relays it to the network, and the contact receives a message from the
/// person they were writing to.
///
/// The owner's device exists but has not joined the room, **and the room is a
/// portal**: nothing is sent, and the send fails *transiently*. It is not a
/// fallback case: posting as `@sensor:` there produces an event id, a stream
/// position and total silence on the contact's phone, which is exactly the
/// outcome #123 calls the worst possible answer. Transient rather than permanent
/// because the owner's device joins portals as the bridges build them, so the
/// next attempt may well succeed; and when it never does, the retry schedule
/// dead-letters the approval, which is a reply an operator can find.
///
/// The owner's device was configured and its **credential is gone**, and the
/// room is a portal: nothing is sent either, and for a harder reason (#229).
/// The identity this reply would have to go out under is one the deployment no
/// longer holds, and no attempt can change that until a new device is
/// provisioned. Transient like the case above, because the approval is then left
/// unacked: an operator who re-provisions inside the retry schedule restarts the
/// Sensor, this delivery was never acknowledged, and the bus hands the reply to
/// the new process — so the owner's reply still goes out. When nobody does, the
/// schedule dead-letters it carrying [`owner_device::REVOKED_REMEDY`], which is
/// what the approval screen shows (#311).
///
/// There is no owner's device, or there is one and the room is **not a portal**:
/// the Sensor's own account sends, exactly as it did before any of this existed.
/// For native Matrix traffic (ADR 0009) that is not a degradation at all — no
/// bridge stands between the room and the person reading it — and for a portal
/// with no owner device configured it is the behaviour this deployment already
/// has, kept unchanged and now *reported* rather than passed off as sent.
async fn post_approved_reply(
    sensor: &Client,
    acting: Acting<'_>,
    job: &outbound::ApprovedReply,
    metrics: &Metrics,
) -> Result<Posted, PostError> {
    // Deliberate v1 limitation, mirroring the inbound text-only skeleton:
    // only text/plain is posted; markdown and HTML dead-letter as permanent
    // failures until rich formatting is specced for outbound.
    if job.format != "text/plain" {
        return Err(PostError::Permanent(anyhow!(
            "unsupported final format {}",
            job.format
        )));
    }
    let room_id = matrix_sdk::ruma::RoomId::parse(&job.room_id)
        .map_err(|error| PostError::Permanent(anyhow!(error).context("invalid target room id")))?;

    let the_room_is_a_portal = the_room_is_a_portal(sensor, &room_id).await;

    let owners_device = match acting {
        Acting::OwnersDevice(device) => Some(device),
        Acting::CredentialGone | Acting::NotConfigured => None,
    };
    let (room, by_the_owners_device) =
        match owners_device.and_then(|device| joined_room(device, &room_id)) {
            Some(room) => (room, true),
            None if owners_device.is_some() && the_room_is_a_portal => {
                return Err(PostError::Transient(anyhow!(
                    "the owner's device has not joined this portal room: a mautrix bridge relays \
                     only the logged-in user's own account, so posting as the Sensor would return \
                     an event id and reach nobody. The device joins a portal when that bridge's \
                     own bot invites it — check SENSOR_BRIDGE_BOTS"
                )))
            }
            // The deployment was given a device of the owner's account and the
            // homeserver no longer knows it (#229). Nothing is posted: this
            // reply would have gone out as the owner, and the identity the
            // deployment would have to act under is one it no longer holds.
            //
            // *Transient*, like the unjoined portal above and for the same
            // reason: the remedy is an operator's and it may arrive inside the
            // retry schedule, in which case the owner's reply still goes out.
            // When it does not, the schedule dead-letters the approval with this
            // reason — which is where the owner learns of it, on the approval
            // screen (#311), rather than from a reply that silently never came.
            None if matches!(acting, Acting::CredentialGone) && the_room_is_a_portal => {
                return Err(PostError::Transient(anyhow!(
                    "{}",
                    owner_device::REVOKED_REMEDY
                )))
            }
            None => (
                joined_room(sensor, &room_id).ok_or_else(|| {
                    PostError::Transient(anyhow!("the sensor has not joined the target room"))
                })?,
                false,
            ),
        };
    let posted_as = room
        .client()
        .user_id()
        .expect("a restored session always has a user id")
        .to_owned();

    let mut content = RoomMessageEventContent::text_plain(job.body.clone());
    if let Some(reply_to) = &job.reply_to_event_id {
        let event_id = matrix_sdk::ruma::EventId::parse(reply_to).map_err(|error| {
            PostError::Permanent(anyhow!(error).context("invalid reply target"))
        })?;
        content.relates_to = Some(Relation::Reply(Reply::with_event_id(event_id)));
    }
    // A direct send, not the send queue: the queue only enqueues locally and
    // sends in the background, so an ack after it would not be tied to
    // delivery. Awaiting the homeserver's event id is what makes the ack
    // safe. The transaction id is derived from the approval's event id, so a
    // redelivered approval whose earlier send was accepted but whose response
    // was lost is deduplicated by the homeserver instead of posted twice.
    let transaction_id = OwnedTransactionId::from(format!("twalk-{}", job.event_id));
    room.send(content)
        .with_transaction_id(transaction_id)
        .await
        .map_err(|error| classify_send_error(error, metrics, by_the_owners_device))?;
    Ok(Posted {
        reach: owner_device::reach(by_the_owners_device, the_room_is_a_portal),
        posted_as,
    })
}

/// Whether a bridge stands between this room and the contact, asked of the
/// **homeserver** rather than of the SDK's state store.
///
/// The store is the wrong source here and the difference is not academic. A
/// room the Sensor has just joined is in the store as joined — `room_joined`
/// marks it so immediately — while its state arrives only with the next sync
/// response, so `get_state_events("m.bridge")` answers "no marker" for a real
/// portal during that window. Believing it would make the Sensor report a reply
/// as having reached the contact when the bridge ignored it, which is precisely
/// the wrong answer issue #216 exists to stop, produced by the machinery meant
/// to prevent it.
///
/// One GET per approved reply, on a path a human walks a few times a minute at
/// most, and an unreadable answer counts as a portal: the cautious reading is
/// the one that refuses to claim delivery.
async fn the_room_is_a_portal(sensor: &Client, room_id: &matrix_sdk::ruma::RoomId) -> bool {
    match sensor
        .send(get_state_events::v3::Request::new(room_id.to_owned()))
        .await
    {
        Ok(response) => response.room_state.iter().any(|raw| {
            raw.get_field::<String>("type").ok().flatten().as_deref() == Some("m.bridge")
        }),
        Err(error) => {
            warn!(
                room = %room_id,
                %error,
                "cannot read this room's state to tell a portal from native Matrix traffic;                  treating it as a portal, so a reply the Sensor posts is not claimed to have                  reached anybody"
            );
            true
        }
    }
}

/// The room, only when this client has **joined** it. An invited-but-not-joined
/// room is exactly the state #123 found the owner's account in on all 33 of the
/// reference deployment's portals, and it is worth nothing to a bridge.
fn joined_room(client: &Client, room_id: &matrix_sdk::ruma::RoomId) -> Option<Room> {
    client
        .get_room(room_id)
        .filter(|room| room.state() == RoomState::Joined)
}

/// Reports what a posted reply reached, on the Sensor's own
/// `twalk.persona.reply.approved.v1.posted` subject (issue #216).
///
/// The payload is the approval **unchanged** — the same bytes the bus delivered
/// — so it stays a contract event and nothing about `persona.reply.approved.v1`
/// moves; the two new facts, what it reached and which identity posted it, are
/// headers. See `outbound::posted_subject` for why this is a subject rather than
/// a field.
///
/// A failure here is logged and nothing more. The reply was posted; a missing
/// diagnosis must not turn that into a redelivery.
async fn report_posted_reply(
    jetstream: &async_nats::jetstream::Context,
    message: &async_nats::jetstream::Message,
    job: &outbound::ApprovedReply,
    posted: &Posted,
) {
    let mut headers = async_nats::header::HeaderMap::new();
    headers.insert(
        async_nats::header::NATS_MESSAGE_ID,
        outbound::posted_msg_id(&job.event_id).as_str(),
    );
    headers.insert(outbound::EVENT_ID_HEADER, job.event_id.as_str());
    headers.insert(outbound::POSTED_REACH_HEADER, posted.reach.as_str());
    headers.insert(outbound::POSTED_AS_HEADER, posted.posted_as.as_str());
    let event = serde_json::from_slice::<serde_json::Value>(&message.message.payload).ok();
    if let Some(event) = &event {
        duplicate_extensions(event, &mut headers);
    }
    match jetstream
        .publish_with_headers(
            outbound::posted_subject(),
            headers,
            message.message.payload.clone(),
        )
        .await
    {
        Ok(ack) => match ack.await {
            Ok(_) => {}
            Err(error) => warn!(
                id = %job.event_id,
                %error,
                "the reach report's publish ack failed; the reply was posted and its reach is in \
                 the log line only"
            ),
        },
        Err(error) => warn!(
            id = %job.event_id,
            %error,
            "could not report what the posted reply reached; the reply was posted and its reach \
             is in the log line only"
        ),
    }
}

/// Copies an event's message-flow extensions into the headers of a copy the
/// Sensor publishes of it, for the server-side filtering the inbound path's
/// headers exist for. Shared by the dead-letter copy and the reach report so the
/// two cannot drift.
fn duplicate_extensions(event: &serde_json::Value, headers: &mut async_nats::header::HeaderMap) {
    for extension in ["network", "consent", "traceparent"] {
        if let Some(value) = event.get(extension).and_then(serde_json::Value::as_str) {
            headers.insert(extension, value);
        }
    }
}

/// Maps a failed Matrix send onto the outbound retry policy. Only errors
/// saying the request itself is malformed can never succeed and are
/// permanent. Everything else is transient and goes through the bounded retry
/// schedule before dead-lettering — notably `M_FORBIDDEN`, which a portal
/// room's power levels raise and which clears once the Sensor is granted the
/// right to post, and `M_LIMIT_EXCEEDED`, network and server errors.
fn classify_send_error(
    error: matrix_sdk::Error,
    metrics: &Metrics,
    by_the_owners_device: bool,
) -> PostError {
    // The acting credential, refused by the send rather than by a sync (#229).
    // This is the thirty-second window the sync loop cannot close on its own: it
    // learns of a revocation when its long poll comes back, and an approval that
    // arrives before that is sent under a token the homeserver has already
    // forgotten. Read here too, so the failure names the credential and the
    // remedy instead of "matrix send failed", and so the gauge an operator alerts
    // on moves at the first symptom rather than at the next sync.
    //
    // **Only for a send the owner's device made.** A reply into a native Matrix
    // room goes out as `@sensor:` and always has (ADR 0009), and an
    // `M_UNKNOWN_TOKEN` there is about the *Sensor's own* session: a different
    // credential, a different remedy, and nothing to do with the owner's device
    // list. Reading it as the owner device's would raise the gauge, publish
    // `credential_gone` and refuse every bridged conversation's reply on the
    // approval screen (#404) because a room with no bridge in it answered
    // badly — which is the conflation this deployment keeps closing.
    let errcode = matrix_errcode(&error);
    if matches!(
        owner_device::after_a_send_refusal(errcode.as_deref(), by_the_owners_device),
        owner_device::AfterRefusal::CredentialGone
    ) {
        metrics.record_owner_device_credential_gone();
        error!("{}", owner_device::REVOKED_REMEDY);
        // The bus is told by the caller, which is async: the gauge and the event
        // must not disagree — a deployment whose gauge says the credential is gone
        // and whose bus still says `present` would draw an approval screen that
        // offers a delivery the same process has already refused (#404).
        return PostError::CredentialGone(anyhow!("{}", owner_device::REVOKED_REMEDY));
    }
    if matches!(
        owner_device::after_refusal(errcode.as_deref()),
        owner_device::AfterRefusal::CredentialGone
    ) {
        // The Sensor's own session, refused. Named rather than folded into
        // "matrix send failed", and retried: this process's own sync will refuse
        // too, and nothing the owner does to their device list changes it.
        error!(
            "the homeserver no longer knows this Sensor's own session, which is what posts into \
             a room no bridge marked: nothing can be posted at all until the Sensor is given a \
             session again. This is not the owner's device (#123) and re-onboarding will not \
             replace it"
        );
    }
    let permanent = matches!(
        error.client_api_error_kind(),
        Some(
            ErrorKind::BadJson | ErrorKind::NotJson | ErrorKind::TooLarge | ErrorKind::InvalidParam
        )
    );
    let error = anyhow!(error).context("matrix send failed");
    if permanent {
        PostError::Permanent(error)
    } else {
        PostError::Transient(error)
    }
}
