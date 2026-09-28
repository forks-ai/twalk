//! `twalk-collector authorize` at the process boundary (issue #274), against
//! the fake SSO and nothing else — no bus, no Docker: the operator's one
//! interactive step, with what it prints and what it never prints.

use std::os::unix::fs::PermissionsExt;
use std::process::Stdio;

use anyhow::{Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use tokio::process::Command;
use twalk_test_harness::sso::{write_client_secret, CLIENT_ID, CLIENT_SECRET};
use twalk_test_harness::FakeSso;

const OWNER: &str = "michel@example.com";

struct Setup {
    sso: FakeSso,
    dir: tempfile::TempDir,
    /// `COLLECTOR_OWNER_ALIASES`: the other addresses this deployment declares
    /// as the owner's (#322). Empty unless a test is about one.
    aliases: String,
}

impl Setup {
    async fn new(account: &str) -> Result<Self> {
        Self::new_holding(account, "").await
    }

    /// A deployment that declares `aliases` as further addresses of the owner's.
    async fn new_holding(account: &str, aliases: &str) -> Result<Self> {
        let sso = FakeSso::start(account).await?;
        let dir = tempfile::tempdir()?;
        write_client_secret(dir.path())?;
        Ok(Self {
            sso,
            dir,
            aliases: aliases.to_owned(),
        })
    }

    fn grant_path(&self) -> std::path::PathBuf {
        self.dir.path().join("oidc").join("grant.json")
    }

    fn command(&self, renew: bool) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_twalk-collector"));
        command
            .arg("authorize")
            .env("COLLECTOR_STATE_DIR", self.dir.path())
            .env("COLLECTOR_OIDC_ISSUER", self.sso.issuer())
            .env("COLLECTOR_OIDC_CLIENT_ID", CLIENT_ID)
            .env(
                "COLLECTOR_OIDC_CLIENT_SECRET_FILE",
                self.dir.path().join("client-secret"),
            )
            .env("COLLECTOR_OIDC_REDIRECT_URI", "http://localhost:1/callback")
            .env("COLLECTOR_JMAP_SESSION_URL", self.sso.jmap_session_url())
            .env("COLLECTOR_CALDAV_URL", self.sso.caldav_url())
            .env("COLLECTOR_OWNER_EMAIL", OWNER)
            .env("COLLECTOR_OWNER_ALIASES", self.aliases.clone())
            .env("COLLECTOR_MAIL_CONNECTION", "mail-test")
            .env("COLLECTOR_CALENDAR_CONNECTION", "calendar-test")
            .env("COLLECTOR_NATS_URL", "nats://localhost:1")
            .env("COLLECTOR_LOG_LEVEL", "info")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        if renew {
            command.arg("--renew");
        }
        command
    }

    /// Runs `authorize` the way the operator does: reads what it prints until
    /// the link, signs in at the fake SSO, pastes the callback. Returns the
    /// exit status and everything printed, both streams.
    async fn authorize(&self, renew: bool) -> Result<(std::process::ExitStatus, String)> {
        let mut child = self
            .command(renew)
            .spawn()
            .context("failed to start the collector")?;
        let mut stdin = child.stdin.take().expect("stdin is piped");
        let stderr = child.stderr.take().expect("stderr is piped");
        let stdout = child.stdout.take().expect("stdout is piped");
        let mut printed = String::new();
        let mut lines = tokio::io::BufReader::new(stderr).lines();
        let mut pasted = false;
        while let Some(line) = lines.next_line().await? {
            printed.push_str(&line);
            printed.push('\n');
            let trimmed = line.trim();
            if !pasted && trimmed.starts_with(&self.sso.issuer()) {
                let callback = self.sso.sign_in(trimmed)?;
                stdin.write_all(format!("{callback}\n").as_bytes()).await?;
                stdin.flush().await?;
                pasted = true;
            }
        }
        drop(stdin);
        let status = child.wait().await?;
        let mut out = String::new();
        let mut stdout = tokio::io::BufReader::new(stdout).lines();
        while let Some(line) = stdout.next_line().await? {
            out.push_str(&line);
            out.push('\n');
        }
        Ok((status, format!("{printed}{out}")))
    }
}

fn assert_no_token(printed: &str) {
    for line in printed.lines() {
        assert!(
            !line.contains("refresh-")
                && !line.contains("access-")
                && !line.contains(CLIENT_SECRET),
            "a credential was printed: {line}"
        );
    }
}

#[tokio::test]
async fn authorize_prints_the_two_whoamis_and_never_a_token_and_a_second_run_leaves_the_grant_alone(
) -> Result<()> {
    let setup = Setup::new(OWNER).await?;

    let (status, printed) = setup.authorize(false).await?;
    assert!(status.success(), "{printed}");
    assert!(
        printed.contains(&format!("jmap answers as {OWNER}")),
        "{printed}"
    );
    assert!(
        printed.contains(&format!("caldav answers as {OWNER}")),
        "{printed}"
    );
    assert!(printed.contains("The collector can start"), "{printed}");
    assert_no_token(&printed);
    let mode = std::fs::metadata(setup.grant_path())?.permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "{mode:o}");
    let written = std::fs::read_to_string(setup.grant_path())?;
    let requests_after_first = setup.sso.token_requests();

    // The second run: nothing asked of the SSO, the grant untouched.
    let (status, printed) = setup.authorize(false).await?;
    assert!(status.success(), "{printed}");
    assert!(printed.contains("Nothing to do"), "{printed}");
    assert!(printed.contains("--renew"), "{printed}");
    assert_eq!(setup.sso.token_requests(), requests_after_first);
    assert_eq!(std::fs::read_to_string(setup.grant_path())?, written);
    assert_no_token(&printed);
    Ok(())
}

#[tokio::test]
async fn a_grant_for_another_account_is_refused_and_not_kept() -> Result<()> {
    let setup = Setup::new("somebody@example.com").await?;
    let (status, printed) = setup.authorize(false).await?;
    assert!(
        !status.success(),
        "a stranger's grant is not an authorization: {printed}"
    );
    assert!(printed.contains("somebody@example.com"), "{printed}");
    assert!(printed.contains("publish nothing"), "{printed}");
    assert!(
        !setup.grant_path().exists(),
        "a stranger's grant left on disk would be protected by the next run's idempotence"
    );
    assert_no_token(&printed);
    Ok(())
}

/// A grant whose service answers **another address the owner holds** is the
/// owner's, and the line says which address answered (#322).
///
/// This is the run that cost the reference deployment its first production
/// authorization: the mailbox answers `mmaudet@`, the operator had configured the
/// address on their business card, and a grant for one person was refused. The
/// check is still against what the service says — that is the point of #274 — and
/// what changed is that the answer may be any address the operator declared.
#[tokio::test]
async fn a_grant_whose_service_answers_another_address_of_the_owners_is_accepted() -> Result<()> {
    const AT_THE_SERVICE: &str = "mmaudet@example.com";
    let setup = Setup::new_holding(AT_THE_SERVICE, AT_THE_SERVICE).await?;

    let (status, printed) = setup.authorize(false).await?;

    assert!(
        status.success(),
        "the grant is the owner's: they hold that address. {printed}"
    );
    assert!(
        setup.grant_path().exists(),
        "and it is kept: {}",
        setup.grant_path().display()
    );
    assert!(
        printed.contains(&format!("jmap as {AT_THE_SERVICE}")),
        "the line says which address answered, not merely that nothing mismatched: {printed}"
    );
    assert!(
        !printed.contains("publish nothing"),
        "nothing was refused: {printed}"
    );
    assert_no_token(&printed);

    // And undeclared, the same grant is refused exactly as it was — which is what
    // the variable buys and what its absence costs.
    let strict = Setup::new_holding(AT_THE_SERVICE, "").await?;
    let (status, printed) = strict.authorize(false).await?;
    assert!(!status.success(), "{printed}");
    assert!(printed.contains("publish nothing"), "{printed}");
    Ok(())
}

#[tokio::test]
async fn a_service_that_does_not_answer_is_said_and_does_not_pass_for_an_answer() -> Result<()> {
    let setup = Setup::new(OWNER).await?;
    setup.sso.silence("caldav");
    let (status, printed) = setup.authorize(false).await?;
    assert!(
        status.success(),
        "the grant is the owner's as far as anyone answered: {printed}"
    );
    assert!(
        printed.contains(&format!("jmap answers as {OWNER}")),
        "{printed}"
    );
    assert!(
        !printed.contains("Both services answer"),
        "one service did not: {printed}"
    );
    assert!(printed.contains("caldav"), "{printed}");
    assert!(printed.contains("unreachable"), "{printed}");
    assert!(setup.grant_path().exists());
    Ok(())
}

/// #342: `authorize` obtains a grant, and a collector whose credential is
/// a username and a password has none to obtain. It says so and stops,
/// rather than half-running a browser flow whose result nothing would
/// read — the operator's next step is a password file.
#[tokio::test]
async fn authorize_refuses_a_collector_whose_credential_is_not_a_grant() -> Result<()> {
    let run = Setup::new(OWNER).await?;
    let password_file = run.dir.path().join("basic-password");
    std::fs::write(&password_file, "hunter2\n")?;
    let output = run
        .command(false)
        .env("COLLECTOR_CREDENTIAL", "basic")
        .env("COLLECTOR_BASIC_USER", "michel")
        .env("COLLECTOR_BASIC_PASSWORD_FILE", &password_file)
        .env_remove("COLLECTOR_MAIL_CONNECTION")
        .output()
        .await?;
    assert!(!output.status.success(), "authorize is not a start here");
    let printed = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        printed.contains("COLLECTOR_BASIC_PASSWORD_FILE"),
        "the refusal says where the credential lives: {printed}"
    );
    assert!(
        !printed.contains("hunter2"),
        "and never prints it: {printed}"
    );
    Ok(())
}
