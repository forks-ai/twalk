// matrix-sdk crypto futures overflow the default trait-solver depth when
// spawned; matrix-sdk itself sets the same limit.
#![recursion_limit = "256"]

//! Issue #451 — the account's own recovery key, minted by the Sensor.
//!
//! `encryption.rs::the_recovery_key_bootstraps_the_identity_and_restores_history`
//! already proves the restore works **given** a key: a replacement device with
//! an empty store reads history it never saw. What it also shows, by what it
//! has to do, is the gap this file closes — that test mints the key itself,
//! with a hand-made "onboarding device", because nothing in the product ever
//! produced one. `provision.sh` has no mention of it, and the reference
//! deployment therefore ran for days with a live key backup, twenty room keys
//! in it, and no secret storage at all: the only copy of the key that opens
//! that backup was inside the crypto store the backup exists to insure.
//!
//! So these tests assert what the Sensor is now responsible for:
//!
//! - it mints the key when a file is named for it, writes it where only its
//!   owner can read it, and says in words what the operator must do next;
//! - the account really does have secret storage afterwards, and the backup
//!   really does receive room keys;
//! - the minted key works — a replacement device with a fresh store rejoins
//!   the **same** cryptographic identity through it, rather than starting a new
//!   one;
//! - a key the deployment asks to be written *inside* the store it insures is
//!   refused before any crypto runs, because a copy that dies with what it
//!   protects is not a copy;
//! - and nothing is minted at all when the file cannot be written, because
//!   secret storage created and then not written down is worse than none: it
//!   would be sealed by a key nobody holds.
//!
//! Each test runs on an **account of its own**, registered here. The shared
//! `@sensor` account's secret storage is state every other test in this crate
//! inherits, and minting on it would make the result depend on test order.

mod harness;

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use harness::crypto::{make_encrypted_whatsapp_portal, CryptoBot};
use harness::{ensure_stack, poll_until, sensor_env_with, synapse_url, Bus, SensorProc};
use serde_json::{json, Value};

const MESSAGE_SUBJECT: &str = "twalk.inbound.message.received.v1";
const STREAM: &str = "twalk";

/// An account registered for one test, with a crypto identity it can afford to
/// have rewritten. The test homeserver has open registration (its
/// `enable_registration` is test-only, see `deploy/docker-compose/synapse/`).
struct OwnAccount {
    user_id: String,
    password: String,
    token: String,
    http: reqwest::Client,
}

impl OwnAccount {
    async fn register(what_for: &str) -> Result<Self> {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let localpart = format!("recovery_{what_for}_{}_{unique}", std::process::id());
        let password = format!("test-only-password-{localpart}");
        let http = reqwest::Client::new();
        let response = http
            .post(format!("{}/_matrix/client/v3/register", synapse_url()))
            .json(&json!({
                "username": localpart,
                "password": password,
                "auth": { "type": "m.login.dummy" },
                "inhibit_login": false,
            }))
            .send()
            .await?;
        if !response.status().is_success() {
            bail!(
                "the test homeserver refused to register {localpart}: {} {}",
                response.status(),
                response.text().await.unwrap_or_default()
            );
        }
        let body: Value = response.json().await?;
        Ok(Self {
            user_id: format!("@{localpart}:test.twalk"),
            token: body
                .get("access_token")
                .and_then(Value::as_str)
                .context("the registration answered no access_token")?
                .to_owned(),
            password,
            http,
        })
    }

    /// The environment a Sensor runs as this account from.
    fn env(&self, overrides: &[(&str, &str)]) -> Vec<(String, String)> {
        let mut env = sensor_env_with(&[
            ("SENSOR_USER_ID", &self.user_id),
            ("SENSOR_PASSWORD", &self.password),
        ]);
        for (key, value) in overrides {
            if let Some(entry) = env.iter_mut().find(|(existing, _)| existing == key) {
                entry.1 = value.to_string();
            } else {
                env.push((key.to_string(), value.to_string()));
            }
        }
        env
    }

    /// One global account data event, or `None` when the homeserver has none.
    /// A `{}` body counts as none: that is how the spec-less "delete" of an
    /// account data event is spelled.
    async fn account_data(&self, event_type: &str) -> Result<Option<Value>> {
        let response = self
            .http
            .get(format!(
                "{}/_matrix/client/v3/user/{}/account_data/{event_type}",
                synapse_url(),
                self.user_id
            ))
            .bearer_auth(&self.token)
            .send()
            .await?;
        if !response.status().is_success() {
            return Ok(None);
        }
        let body: Value = response.json().await?;
        Ok(body
            .as_object()
            .is_some_and(|map| !map.is_empty())
            .then_some(body))
    }

    /// How many room keys the account's key backup holds, over every version.
    async fn room_keys_backed_up(&self) -> Result<usize> {
        let version = self
            .http
            .get(format!(
                "{}/_matrix/client/v3/room_keys/version",
                synapse_url()
            ))
            .bearer_auth(&self.token)
            .send()
            .await?;
        if !version.status().is_success() {
            return Ok(0);
        }
        let version: Value = version.json().await?;
        let Some(version) = version.get("version").and_then(Value::as_str) else {
            return Ok(0);
        };
        let keys = self
            .http
            .get(format!(
                "{}/_matrix/client/v3/room_keys/keys?version={version}",
                synapse_url()
            ))
            .bearer_auth(&self.token)
            .send()
            .await?;
        if !keys.status().is_success() {
            return Ok(0);
        }
        let keys: Value = keys.json().await?;
        Ok(keys["rooms"]
            .as_object()
            .map(|rooms| {
                rooms
                    .values()
                    .filter_map(|room| room["sessions"].as_object().map(|s| s.len()))
                    .sum()
            })
            .unwrap_or(0))
    }

    /// The account's master cross-signing key as the homeserver has it, which
    /// is what says whether a replacement device rejoined the same identity or
    /// started a new one.
    async fn master_key(&self) -> Result<Option<String>> {
        let response = self
            .http
            .post(format!("{}/_matrix/client/v3/keys/query", synapse_url()))
            .bearer_auth(&self.token)
            .json(&json!({ "device_keys": { &self.user_id: [] } }))
            .send()
            .await?
            .error_for_status()?;
        let body: Value = response.json().await?;
        Ok(body["master_keys"][&self.user_id]["keys"]
            .as_object()
            .and_then(|keys| keys.values().next())
            .and_then(Value::as_str)
            .map(ToOwned::to_owned))
    }
}

/// A path for the minted key, in the system temporary directory and therefore
/// **not** inside any state directory this crate makes there — `fresh_state_dir`
/// names `twalk-sensor-state-*`, and this names something else.
fn key_file(what_for: &str) -> PathBuf {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "twalk-sensor-recovery-key-{what_for}-{}-{unique}",
        std::process::id()
    ))
}

fn state_dir(what_for: &str) -> PathBuf {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "twalk-sensor-state-{what_for}-{}-{unique}",
        std::process::id()
    ))
}

/// Waits until the file exists and holds something, then reads it.
async fn wait_for_key(path: &Path) -> Result<String> {
    poll_until(
        || async {
            let key = std::fs::read_to_string(path).ok()?;
            (!key.trim().is_empty()).then(|| key.trim().to_owned())
        },
        &format!("waiting for the recovery key at {}", path.display()),
    )
    .await
}

async fn wait_for_log(sensor: &SensorProc, needle: &str) -> Result<String> {
    poll_until(
        || async {
            sensor
                .logs()
                .await
                .into_iter()
                .find(|line| line.contains(needle))
        },
        &format!("waiting for a log line containing {needle:?}"),
    )
    .await
}

#[tokio::test]
async fn the_sensor_mints_the_account_key_and_a_replacement_device_rejoins_through_it() -> Result<()>
{
    ensure_stack().await?;
    let _guard = harness::SENSOR_LOCK.lock().await;
    let bus = Bus::connect().await?;
    let account = OwnAccount::register("mint").await?;

    // Before: nothing. This is the state the reference deployment was in, and
    // the one every deployment reaches by just running the Sensor.
    assert!(
        account
            .account_data("m.secret_storage.default_key")
            .await?
            .is_none(),
        "a fresh account has no secret storage"
    );

    let first_store = state_dir("mint");
    let key_path = key_file("mint");
    let sensor = SensorProc::start(&account.env(&[
        ("SENSOR_STATE_DIR", &first_store.to_string_lossy()),
        ("SENSOR_RECOVERY_KEY_OUT", &key_path.to_string_lossy()),
    ]))?;

    // The key, and what the Sensor says about it. The sentence matters as much
    // as the file: a secret written where nobody is told to collect it is a
    // secret that stays on the host it was meant to outlive.
    let recovery_key = wait_for_key(&key_path).await?;
    let minted = wait_for_log(&sensor, "minted this account's recovery key").await?;
    assert!(
        minted.contains("Take it off"),
        "the log must say what the operator has to do with it: {minted}"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&key_path)?.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the key file is readable by its owner only");
    }

    // The account now has what it was missing, on the homeserver.
    let storage = poll_until(
        || async {
            account
                .account_data("m.secret_storage.default_key")
                .await
                .ok()
                .flatten()
        },
        "waiting for secret storage to appear on the account",
    )
    .await?;
    assert!(
        storage["key"].as_str().is_some_and(|id| !id.is_empty()),
        "the default key event names a key: {storage}"
    );
    assert!(
        account.account_data("m.megolm_backup.v1").await?.is_some(),
        "the backup's decryption key is in secret storage, which is the whole \
         point — that is the secret that was only ever in the crypto store"
    );

    // And the backup fills as it observes. One encrypted portal, one message:
    // the Sensor decrypts it, publishes it, and the room key goes up.
    let alpha = CryptoBot::login("bot_alpha").await?;
    let room_id = make_encrypted_whatsapp_portal(&alpha, "minted-key-portal").await?;
    alpha.invite(&room_id, &account.user_id).await?;
    alpha
        .send_message(&room_id, "backed up by a key somebody has")
        .await?;
    let stored = bus
        .wait_for_room_message(STREAM, MESSAGE_SUBJECT, &room_id)
        .await?;
    assert_eq!(
        stored.payload["data"]["body"].as_str(),
        Some("backed up by a key somebody has")
    );
    let backed_up = poll_until(
        || async {
            let count = account.room_keys_backed_up().await.ok()?;
            (count > 0).then_some(count)
        },
        "waiting for a room key to reach the backup",
    )
    .await?;
    assert!(backed_up > 0, "the backup holds {backed_up} room keys");

    let identity_before = account
        .master_key()
        .await?
        .context("the account must have a cross-signing identity by now")?;

    // The catastrophe the backup exists for: the store is gone.
    sensor.stop().await;
    std::fs::remove_dir_all(&first_store).ok();

    // The replacement device. A fresh store, and the minted key as its only
    // link to the account — which is exactly what the operator would have on
    // the morning after losing a volume.
    let second_store = state_dir("replacement");
    let mut replacement = SensorProc::start(&account.env(&[
        ("SENSOR_STATE_DIR", &second_store.to_string_lossy()),
        ("SENSOR_RECOVERY_KEY", &recovery_key),
    ]))?;
    wait_for_log(
        &replacement,
        "recovered the cryptographic identity from the recovery key",
    )
    .await?;

    let identity_after = account
        .master_key()
        .await?
        .context("the replacement device must see an identity")?;
    assert_eq!(
        identity_before, identity_after,
        "the replacement rejoined the same identity through the minted key, \
         rather than bootstrapping a new one and orphaning the backup"
    );

    assert!(replacement.is_running());
    replacement.stop().await;
    std::fs::remove_dir_all(&second_store).ok();
    std::fs::remove_file(&key_path).ok();
    Ok(())
}

#[tokio::test]
async fn a_key_asked_for_inside_the_store_is_refused_before_any_crypto_runs() -> Result<()> {
    ensure_stack().await?;
    let _guard = harness::SENSOR_LOCK.lock().await;
    let account = OwnAccount::register("refused").await?;

    let store = state_dir("refused");
    let inside = store.join("recovery-key");
    let mut sensor = SensorProc::start(&account.env(&[
        ("SENSOR_STATE_DIR", &store.to_string_lossy()),
        ("SENSOR_RECOVERY_KEY_OUT", &inside.to_string_lossy()),
    ]))?;

    let refusal = wait_for_log(&sensor, "is inside SENSOR_STATE_DIR").await?;
    assert!(
        refusal.contains("not a copy"),
        "the refusal says why, not just that: {refusal}"
    );
    // Said before anything was written, and the process does not carry on
    // observing with a misconfigured secret — the posture this crate takes for
    // a configured-but-unusable metrics endpoint.
    assert!(!inside.exists(), "no key was written where it was refused");
    assert!(
        account
            .account_data("m.secret_storage.default_key")
            .await?
            .is_none(),
        "and no secret storage was created either"
    );
    // A plain loop rather than `poll_until`: a `&mut` borrow of the child
    // cannot escape that helper's `FnMut` closure.
    let mut exited = false;
    for _ in 0..60 {
        if !sensor.is_running() {
            exited = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    assert!(exited, "the Sensor exits rather than observing on");

    std::fs::remove_dir_all(&store).ok();
    Ok(())
}

#[tokio::test]
async fn with_nowhere_to_write_it_the_sensor_says_what_the_absence_costs() -> Result<()> {
    ensure_stack().await?;
    let _guard = harness::SENSOR_LOCK.lock().await;
    let account = OwnAccount::register("silent").await?;

    let store = state_dir("silent");
    let mut sensor =
        SensorProc::start(&account.env(&[("SENSOR_STATE_DIR", &store.to_string_lossy())]))?;

    // The deployment that has not been told about this yet — which is every
    // deployment before #451. It keeps working, and it says once, in words,
    // that its key backup is sealed by a secret kept only in the store the
    // backup exists to survive. One line, where before there was nothing.
    let warning = wait_for_log(&sensor, "the key that opens its server-side key backup").await?;
    assert!(
        warning.contains("SENSOR_RECOVERY_KEY_OUT"),
        "the warning names the way out: {warning}"
    );
    assert!(
        account
            .account_data("m.secret_storage.default_key")
            .await?
            .is_none(),
        "and nothing is minted behind the operator's back"
    );
    assert!(sensor.is_running(), "it keeps observing");

    sensor.stop().await;
    std::fs::remove_dir_all(&store).ok();
    Ok(())
}

#[tokio::test]
async fn an_unwritable_file_means_no_key_is_minted_at_all() -> Result<()> {
    ensure_stack().await?;
    let _guard = harness::SENSOR_LOCK.lock().await;
    let account = OwnAccount::register("unwritable").await?;

    let store = state_dir("unwritable");
    // A directory that does not exist, so the write fails for a reason no
    // permission fiddling is needed to stage.
    let unwritable = store
        .with_file_name("twalk-no-such-directory")
        .join("deeper")
        .join("sensor-recovery-key");
    let mut sensor = SensorProc::start(&account.env(&[
        ("SENSOR_STATE_DIR", &store.to_string_lossy()),
        ("SENSOR_RECOVERY_KEY_OUT", &unwritable.to_string_lossy()),
    ]))?;

    let refusal = wait_for_log(&sensor, "cannot be written, so no key was minted").await?;
    assert!(
        refusal.contains("seal its secret storage with something nobody has"),
        "the log says why the order matters: {refusal}"
    );

    // The point of the order: the account is untouched. Were it the other way
    // round — mint, then write — this account would now have secret storage
    // whose key went nowhere, and no way back to it.
    assert!(
        account
            .account_data("m.secret_storage.default_key")
            .await?
            .is_none(),
        "no secret storage was created for a key that could not be written down"
    );
    assert!(
        account.account_data("m.megolm_backup.v1").await?.is_none(),
        "and no backup secret either"
    );
    assert!(sensor.is_running(), "and it keeps observing");

    sensor.stop().await;
    std::fs::remove_dir_all(&store).ok();
    Ok(())
}
