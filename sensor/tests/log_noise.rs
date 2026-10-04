// matrix-sdk crypto futures overflow the default trait-solver depth when
// spawned; matrix-sdk itself sets the same limit.
#![recursion_limit = "256"]

//! Issue #452 — the warning about a backup that must not exist.
//!
//! The Sensor holds two Matrix clients. The owner's own device (ADR 0034)
//! deliberately has no key backup: it posts approved replies and reads no
//! history, so there is nothing for it to back up. matrix-sdk has no such
//! shape — its backup *upload* task is created unconditionally
//! (`encryption/mod.rs:239`, where the *download* task on the next line is
//! gated), and every sync response triggers it (`sync.rs:164`) without
//! consulting `EncryptionSettings` or the backup state. The task finds no
//! backup key, which is right, and says so at WARN.
//!
//! The owner device has to sync — for its own Olm requests and to see
//! invitations — so that arrived about twice a minute, for ever: **16 006
//! lines in five days** on the reference deployment, nearly everything that
//! container logged at WARN. A permanent warning naming a missing key reads as
//! a fault, so it was investigated, and establishing that the one device
//! complaining is the one device that must not back anything up took a full
//! round of measurement.
//!
//! So `Config::log_filter` silences that target below ERROR and the Sensor
//! says, once per start, what its **observing** client's backup state is —
//! which is what the silenced target used to convey, except attributable.
//!
//! These two tests are the pair that matters: the noise is gone, and an
//! operator who wants it back can have it. The second one is not a formality.
//! It decides whether `EnvFilter` really lets a later directive override an
//! earlier one for the same target, which is the whole reason ours goes first.

mod harness;

use anyhow::Result;
use harness::{ensure_stack, fresh_state_dir, poll_until, sensor_env_with, Bot, SensorProc};

const OWNER: &str = "@owner:test.twalk";
const BRIDGE_BOT: &str = "@whatsappbot:test.twalk";

/// The warning this issue is about, as matrix-sdk-crypto words it.
const THE_NOISE: &str = "no backup key was found";
/// What the Sensor says instead, about the client it is actually about.
const THE_STATEMENT: &str = "the observing client's secret storage and key backup";

/// A Sensor that holds a device of the owner's account — the client that emits
/// the warning — with an optional `SENSOR_LOG_LEVEL` of the operator's own.
fn env_with_owner_device(
    test_name: &str,
    access_token: &str,
    device_id: &str,
    log_level: Option<&str>,
) -> Vec<(String, String)> {
    let state_dir = fresh_state_dir(test_name);
    let mut overrides = vec![
        ("SENSOR_OWNER", OWNER.to_owned()),
        ("SENSOR_ALLOWED_INVITERS", BRIDGE_BOT.to_owned()),
        ("SENSOR_BRIDGE_BOTS", BRIDGE_BOT.to_owned()),
        ("SENSOR_STATE_DIR", state_dir.to_string_lossy().into_owned()),
        ("SENSOR_OWNER_DEVICE_ACCESS_TOKEN", access_token.to_owned()),
        ("SENSOR_OWNER_DEVICE_ID", device_id.to_owned()),
    ];
    if let Some(level) = log_level {
        overrides.push(("SENSOR_LOG_LEVEL", level.to_owned()));
    }
    let overrides: Vec<(&str, &str)> = overrides
        .iter()
        .map(|(key, value)| (*key, value.as_str()))
        .collect();
    sensor_env_with(&overrides)
}

/// Waits until the Sensor has gone round its sync loop at least `times`,
/// observed through the SDK's own report of each response. Condition-based
/// rather than a sleep: the warning this test is about followed every sync,
/// so what the assertion needs is syncs, not seconds.
async fn wait_for_syncs(sensor: &SensorProc, times: usize) -> Result<()> {
    poll_until(
        || async {
            let seen = sensor
                .logs()
                .await
                .into_iter()
                .filter(|line| line.contains("Processed a sync response"))
                .count();
            (seen >= times).then_some(())
        },
        &format!("waiting for {times} sync responses"),
    )
    .await
}

/// A log line without its colour escapes. The Sensor writes to a terminal-like
/// pipe, so tracing colours the field names: `recovery=Incomplete` reaches a
/// test as `\x1b[3mrecovery\x1b[0m\x1b[2m=\x1b[0mIncomplete`, and an
/// assertion on `"recovery="` fails on a line that is perfectly correct.
/// Measured, which is why this exists.
fn plain(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            // A CSI sequence is ESC `[` parameters final-byte, the final byte
            // in @–~. The `[` must be consumed *before* scanning for that
            // final byte, because `[` is itself 0x5B and therefore in the
            // range — a version of this that did not left `2m` behind in every
            // line, and the assertion failed on output that was correct.
            if chars.next() == Some('[') {
                for escaped in chars.by_ref() {
                    if ('\u{40}'..='\u{7e}').contains(&escaped) {
                        break;
                    }
                }
            }
        } else {
            out.push(c);
        }
    }
    out
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
async fn the_owner_device_no_longer_warns_about_a_backup_it_must_not_have() -> Result<()> {
    ensure_stack().await?;
    let _guard = harness::SENSOR_LOCK.lock().await;
    let owner = Bot::login("owner").await?;

    let mut sensor = SensorProc::start(&env_with_owner_device(
        "log-noise-silenced",
        owner.access_token(),
        owner.device_id(),
        None,
    ))?;

    // What replaces the noise: one line, about the client it is about.
    let statement = plain(&wait_for_log(&sensor, THE_STATEMENT).await?);
    assert!(
        statement.contains("recovery=") && statement.contains("backup="),
        "it carries both states rather than merely claiming to: {statement}"
    );
    assert!(
        statement.contains("ADR 0034"),
        "and says why the other client has neither: {statement}"
    );

    // Several times round the loop, which is where the warning came from.
    wait_for_syncs(&sensor, 3).await?;

    let noise: Vec<String> = sensor
        .logs()
        .await
        .into_iter()
        .filter(|line| line.contains(THE_NOISE))
        .collect();
    assert!(
        noise.is_empty(),
        "after three syncs the owner device still warns {} times: {:?}",
        noise.len(),
        noise.first()
    );

    assert!(sensor.is_running(), "and it is still observing");
    sensor.stop().await;
    Ok(())
}

#[tokio::test]
async fn an_operator_who_asks_for_those_lines_gets_them_back() -> Result<()> {
    ensure_stack().await?;
    let _guard = harness::SENSOR_LOCK.lock().await;
    let owner = Bot::login("owner").await?;

    // The directive the Sensor puts in front is meant to be overridable: an
    // operator diagnosing a backup writes the target themselves, and theirs
    // comes after ours in the filter string. Whether `EnvFilter` honours that
    // is not something to assume — it is the question this test asks.
    let mut sensor = SensorProc::start(&env_with_owner_device(
        "log-noise-restored",
        owner.access_token(),
        owner.device_id(),
        Some("info,twalk_sensor=debug,matrix_sdk_crypto::backups=warn"),
    ))?;

    let restored = plain(&wait_for_log(&sensor, THE_NOISE).await?);
    assert!(
        restored.contains("WARN"),
        "the SDK's own line, at its own level: {restored}"
    );
    assert!(
        restored.contains("matrix_sdk_crypto::backups"),
        "and from the silenced target itself, not from somewhere else: {restored}"
    );

    assert!(sensor.is_running());
    sensor.stop().await;
    Ok(())
}
