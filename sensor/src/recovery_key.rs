//! Whether this start should mint the Sensor account's own recovery key, and
//! where it may be written (#451).
//!
//! **The problem this exists for.** The Sensor creates a server-side key
//! backup when the account has none (`EncryptionSettings { auto_enable_backups:
//! true, .. }`), so that "room keys survive a device replacement". Measured on
//! the reference deployment, they did not: the account had a live backup with
//! twenty room keys over seven rooms and **no secret storage at all**, so the
//! only copy of the key that opens that backup was inside the crypto store the
//! backup exists to insure. A replacement device starts with an empty store,
//! finds no backup key, and the twenty keys stay sealed for good.
//!
//! `SENSOR_RECOVERY_KEY` was the documented way out — the operator sets it and
//! the Sensor opens secret storage with it at startup — but it is documented as
//! something the operator "kept from provisioning that account", and nothing in
//! provisioning ever produced one. `provision.sh` has no mention of it.
//!
//! **What this decides.** Nothing here does any I/O or any crypto: it maps what
//! the deployment configured and what the homeserver says onto one of six
//! courses, so that each is a case a test can state. The crypto itself is one
//! SDK call at the call site (`Recovery::enable`), which creates the secret
//! storage key and then uploads the secrets this device already holds — the
//! existing backup key among them. Which is why running this once on a
//! deployment like the reference one does not just protect what comes next: it
//! makes the twenty keys already in the backup openable.
//!
//! **Why minting is the operator's decision and not a default.** A key written
//! without anyone asking is a secret nobody knows exists, and this one is
//! worthless unless a human takes it off the host. So the Sensor mints one only
//! when the deployment names a file for it, says in one line what the absence
//! costs when it does not, and refuses outright to write the key **inside the
//! store it insures** — a copy that dies with what it was protecting is not a
//! copy.

use std::path::{Component, Path, PathBuf};

/// What the homeserver and this device say about secret storage, as the
/// decision below needs it. A narrowing of matrix-sdk's `RecoveryState`, kept
/// here so this module — and its tests — need no SDK and no network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageState {
    /// The SDK has not yet learned the state. Decide nothing.
    Unknown,
    /// Secret storage exists and this device holds its secrets.
    Enabled,
    /// No default secret storage key, or it is explicitly disabled.
    Disabled,
    /// Secret storage exists but this device is missing some of its secrets.
    Incomplete,
}

/// What this start should do about the account's recovery key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Plan {
    /// `SENSOR_RECOVERY_KEY` is set: the operator has a key, and the startup
    /// path that opens secret storage with it has already run.
    OperatorHasOne,
    /// Secret storage is set up and this device holds its secrets. Somebody
    /// minted a key; this is not the moment to mint a second.
    AlreadyEnabled,
    /// Secret storage exists but this device lacks some of its secrets. Only
    /// the key can fix that, and this deployment has none to offer.
    IncompleteWithoutTheKey,
    /// Nothing is configured to receive a key, so none is minted. The cost of
    /// that is worth one line in the log.
    NoOutputConfigured,
    /// The file named for the key is inside the store the key insures.
    RefusedInsideTheStore { out: PathBuf, state_dir: PathBuf },
    /// Mint one, and write it here.
    MintInto(PathBuf),
    /// Too early to say.
    TooEarly,
}

/// The whole decision, with no I/O.
///
/// `out` is `SENSOR_RECOVERY_KEY_OUT` and `state_dir` is `SENSOR_STATE_DIR`.
/// A deployment with no state directory keeps no store between starts, so
/// there is nothing for the key to be written *inside* of — and a key matters
/// more there, not less, since every start is a new device and the backup is
/// the only way back to old traffic.
pub fn decide(
    operator_configured_a_key: bool,
    state: StorageState,
    out: Option<&Path>,
    state_dir: Option<&Path>,
) -> Plan {
    if operator_configured_a_key {
        return Plan::OperatorHasOne;
    }
    match state {
        StorageState::Unknown => Plan::TooEarly,
        StorageState::Enabled => Plan::AlreadyEnabled,
        StorageState::Incomplete => Plan::IncompleteWithoutTheKey,
        StorageState::Disabled => match out {
            None => Plan::NoOutputConfigured,
            Some(out) => match state_dir {
                Some(dir) if is_inside(out, dir) => Plan::RefusedInsideTheStore {
                    out: out.to_path_buf(),
                    state_dir: dir.to_path_buf(),
                },
                _ => Plan::MintInto(out.to_path_buf()),
            },
        },
    }
}

/// Whether `path` is `dir` or sits under it, decided **lexically**.
///
/// Neither path need exist — the state directory is created by the Sensor
/// itself on a first start, and the key file by definition does not exist yet —
/// so `canonicalize` is not available and `..` is resolved by hand. A relative
/// path is taken against the working directory, which is the one the Sensor was
/// started in and therefore the one its own relative `SENSOR_STATE_DIR` means.
pub fn is_inside(path: &Path, dir: &Path) -> bool {
    let path = lexically_absolute(path);
    let dir = lexically_absolute(dir);
    path.starts_with(&dir)
}

/// `path` made absolute and cleaned of `.` and `..`, without touching the
/// filesystem. Symlinks are therefore not followed: a key file reached through
/// a symlink out of the store would pass this check, which is the limit of a
/// lexical rule and is stated rather than papered over.
fn lexically_absolute(path: &Path) -> PathBuf {
    let base = if path.is_absolute() {
        PathBuf::new()
    } else {
        std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"))
    };
    let mut out = base;
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => out.push(prefix.as_os_str()),
            Component::RootDir => {
                out.push(Component::RootDir.as_os_str());
            }
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(part) => out.push(part),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "/srv/keys/sensor-recovery-key";
    const STORE: &str = "/srv/sensor-data";

    #[test]
    fn a_configured_key_settles_it_whatever_the_homeserver_says() {
        for state in [
            StorageState::Unknown,
            StorageState::Enabled,
            StorageState::Disabled,
            StorageState::Incomplete,
        ] {
            assert_eq!(
                decide(true, state, Some(Path::new(KEY)), Some(Path::new(STORE))),
                Plan::OperatorHasOne,
                "state {state:?}"
            );
        }
    }

    #[test]
    fn nothing_is_decided_before_the_sdk_knows() {
        assert_eq!(
            decide(
                false,
                StorageState::Unknown,
                Some(Path::new(KEY)),
                Some(Path::new(STORE))
            ),
            Plan::TooEarly
        );
    }

    #[test]
    fn storage_that_exists_is_never_replaced() {
        assert_eq!(
            decide(
                false,
                StorageState::Enabled,
                Some(Path::new(KEY)),
                Some(Path::new(STORE))
            ),
            Plan::AlreadyEnabled,
            "a second key would orphan the first"
        );
    }

    #[test]
    fn incomplete_storage_wants_the_key_nobody_configured() {
        assert_eq!(
            decide(
                false,
                StorageState::Incomplete,
                Some(Path::new(KEY)),
                Some(Path::new(STORE))
            ),
            Plan::IncompleteWithoutTheKey,
            "minting here would write a second key into storage this device \
             cannot fully read"
        );
    }

    #[test]
    fn with_nowhere_to_put_it_no_key_is_minted() {
        assert_eq!(
            decide(false, StorageState::Disabled, None, Some(Path::new(STORE))),
            Plan::NoOutputConfigured
        );
    }

    #[test]
    fn a_key_is_minted_when_a_file_is_named_for_it() {
        assert_eq!(
            decide(
                false,
                StorageState::Disabled,
                Some(Path::new(KEY)),
                Some(Path::new(STORE))
            ),
            Plan::MintInto(PathBuf::from(KEY))
        );
    }

    #[test]
    fn the_key_may_not_be_written_inside_the_store_it_insures() {
        let inside = format!("{STORE}/recovery-key");
        assert_eq!(
            decide(
                false,
                StorageState::Disabled,
                Some(Path::new(&inside)),
                Some(Path::new(STORE))
            ),
            Plan::RefusedInsideTheStore {
                out: PathBuf::from(&inside),
                state_dir: PathBuf::from(STORE),
            },
            "a copy that dies with what it protects is not a copy"
        );
    }

    #[test]
    fn nor_deeper_inside_it_nor_by_way_of_a_detour() {
        for inside in [
            format!("{STORE}/nested/deeper/key"),
            format!("{STORE}/./key"),
            format!("{STORE}/nested/../key"),
            format!("{STORE}/../sensor-data/key"),
        ] {
            assert!(
                matches!(
                    decide(
                        false,
                        StorageState::Disabled,
                        Some(Path::new(&inside)),
                        Some(Path::new(STORE))
                    ),
                    Plan::RefusedInsideTheStore { .. }
                ),
                "{inside} is inside {STORE}"
            );
        }
    }

    #[test]
    fn a_neighbour_of_the_store_is_not_inside_it() {
        // `/srv/sensor-data-keys` starts with the store's path as *text* and is
        // not inside it. Comparing strings rather than path components is the
        // mistake this pins.
        for outside in [
            "/srv/sensor-data-keys/key",
            "/srv/sensor-datakey",
            "/srv/keys/key",
            "/srv/sensor-data2/key",
        ] {
            assert_eq!(
                decide(
                    false,
                    StorageState::Disabled,
                    Some(Path::new(outside)),
                    Some(Path::new(STORE))
                ),
                Plan::MintInto(PathBuf::from(outside)),
                "{outside} is not inside {STORE}"
            );
        }
    }

    #[test]
    fn without_a_state_directory_there_is_no_store_to_be_inside_of() {
        // Nothing survives a restart, so every start is a new device and the
        // backup is the only way back to old traffic: a key matters more here.
        assert_eq!(
            decide(false, StorageState::Disabled, Some(Path::new(KEY)), None),
            Plan::MintInto(PathBuf::from(KEY))
        );
    }

    #[test]
    fn relative_paths_are_compared_against_the_same_directory() {
        assert!(is_inside(
            Path::new("sensor-data/key"),
            Path::new("sensor-data")
        ));
        assert!(!is_inside(Path::new("keys/key"), Path::new("sensor-data")));
        // One side relative and the other absolute still compares, because
        // both are taken against the working directory.
        let cwd = std::env::current_dir().expect("a working directory");
        assert!(is_inside(
            &cwd.join("sensor-data").join("key"),
            Path::new("sensor-data")
        ));
    }
}
