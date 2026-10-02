//! Mail triage at the collector's process boundary (#417, #418, ADR 0042):
//! the owner's rules against the fake JMAP server, with a real mail really
//! changing mailbox.
//!
//! The unit tests in `twalk_collector::triage` say which rule matches. This
//! says the rest of it, which is where the defects live: that the move is a
//! **filing** and not a copy, that a mailbox whose *role* is the trash is
//! refused whatever it is called, that a rule the owner never declared a
//! destination for moves nothing, that what moved is **reported** so the owner
//! can read it back, and that an undo really puts the mail where it came from.

mod support;

use anyhow::Result;
use serde_json::{json, Value};
use support::{Run, OWNER};
use twalk_test_harness::jmap_fake::{FakeMail, ARCHIVE_ID, INBOX_ID, TRASH_ID, VEILLE_ID};
use twalk_test_harness::{ensure_stack, Bus};

/// A newsletter: what the frontier drops and what the owner wants filed. The
/// two are different decisions about different things, and triage must act on
/// a mail the bus never hears about.
fn newsletter(subject: &str) -> FakeMail {
    let mut mail = FakeMail::from_person(
        "La lettre",
        "noreply@lettre.example",
        OWNER,
        subject,
        "Les nouvelles de la semaine.",
    );
    mail.headers
        .push(("List-Id".to_owned(), "<ml.lettre.example>".to_owned()));
    mail
}

#[tokio::test]
async fn a_rule_files_a_mail_and_the_move_is_reported() -> Result<()> {
    ensure_stack().await?;
    let bus = Bus::connect().await?;
    let run = Run::prepare("triage").await?;
    run.authorize().await?;
    run.serve_snapshot(&bus, Vec::new()).await?;
    run.sso.set_mail_triage(json!({
        "destinations": ["Veille", "Archive"],
        "rules": [
            { "id": "lettres", "field": "list_id",
              "value": "ml.lettre.example", "destination": "Veille" }
        ]
    }));

    let collector = run.start_with_gateway()?;
    collector
        .wait_logged("mailbox taken as it stands", 1)
        .await?;

    // A newsletter the frontier will drop, and a mail from a person it will
    // publish. Only the first matches a rule.
    let filed = run.sso.deliver(newsletter("Les nouvelles de la semaine"));
    let untouched = run.sso.deliver(FakeMail::from_person(
        "Alice Martin",
        "alice@example.org",
        OWNER,
        "Point hebdo",
        "On se voit lundi ?",
    ));

    collector
        .wait_logged("the owner's rule filed a mail", 1)
        .await?;

    // The move is a **filing**: the mail is in Veille and nowhere else. A
    // patch rather than a whole map would have left it in the inbox too,
    // which is a copy and not a filing.
    assert_eq!(
        run.sso.mailbox_of(&filed),
        Some(VEILLE_ID.to_owned()),
        "the newsletter is filed where the rule said"
    );
    assert_eq!(
        run.sso.mailbox_of(&untouched),
        Some(INBOX_ID.to_owned()),
        "a mail no rule matches is left exactly where it was"
    );

    // And the owner can read back what happened, with the mailbox it came
    // from — which is what makes an undo a second move rather than a
    // recovery (#418).
    let reported = run.sso.reported_moves();
    assert_eq!(reported.len(), 1, "one move, reported once: {reported:#?}");
    let one = &reported[0];
    assert_eq!(one["email_id"], json!(filed));
    assert_eq!(one["rule_id"], json!("lettres"));
    assert_eq!(one["from_mailbox_name"], json!("INBOX"));
    assert_eq!(one["to_mailbox_name"], json!("Veille"));
    assert_eq!(one["undoes"], Value::Null);
    // Nothing a contact wrote is in the record.
    let text = serde_json::to_string(one)?;
    assert!(
        !text.contains("nouvelles") && !text.contains("lettre.example"),
        "the record holds no subject and no sender: {text}"
    );

    collector.stop().await;
    Ok(())
}

/// The role is the authority, not the name. A mailbox the owner called
/// "Vrac" whose JMAP role is `trash` is refused here and nowhere else — the
/// Gateway's name check cannot see a role, and a move to the trash has an
/// expiry date because most servers purge it (ADR 0042).
#[tokio::test]
async fn a_destination_whose_role_is_the_trash_moves_nothing() -> Result<()> {
    ensure_stack().await?;
    let bus = Bus::connect().await?;
    let run = Run::prepare("triage-trash").await?;
    run.authorize().await?;
    run.serve_snapshot(&bus, Vec::new()).await?;
    // A set the Gateway would have refused by name — "Vrac" says nothing —
    // served by a Gateway older than that check, or by one that was fooled.
    run.sso.set_mail_triage(json!({
        "destinations": ["Vrac"],
        "rules": [
            { "id": "dangereuse", "field": "list_id",
              "value": "ml.lettre.example", "destination": "Vrac" }
        ]
    }));

    let collector = run.start_with_gateway()?;
    collector
        .wait_logged("mailbox taken as it stands", 1)
        .await?;
    let mail = run.sso.deliver(newsletter("À ne pas jeter"));

    collector
        .wait_logged("a triage rule matched and could not be applied", 1)
        .await?;
    assert_eq!(
        run.sso.mailbox_of(&mail),
        Some(INBOX_ID.to_owned()),
        "the mail stays in the inbox: the trash is never a destination"
    );
    assert_ne!(run.sso.mailbox_of(&mail), Some(TRASH_ID.to_owned()));
    assert!(
        run.sso.reported_moves().is_empty(),
        "nothing moved, so nothing is reported"
    );

    collector.stop().await;
    Ok(())
}

/// A rule naming a destination the owner's allowlist does not hold moves
/// nothing, even when the server has such a mailbox. The set was written by
/// something older than the check, and a rule nobody declared is not a rule.
#[tokio::test]
async fn a_destination_outside_the_allowlist_moves_nothing() -> Result<()> {
    ensure_stack().await?;
    let bus = Bus::connect().await?;
    let run = Run::prepare("triage-undeclared").await?;
    run.authorize().await?;
    run.serve_snapshot(&bus, Vec::new()).await?;
    run.sso.set_mail_triage(json!({
        "destinations": ["Veille"],
        "rules": [
            { "id": "ailleurs", "field": "list_id",
              "value": "ml.lettre.example", "destination": "Archive" }
        ]
    }));

    let collector = run.start_with_gateway()?;
    collector
        .wait_logged("mailbox taken as it stands", 1)
        .await?;
    let mail = run.sso.deliver(newsletter("Vers nulle part"));

    collector
        .wait_logged("a triage rule matched and could not be applied", 1)
        .await?;
    assert_eq!(run.sso.mailbox_of(&mail), Some(INBOX_ID.to_owned()));
    assert_ne!(run.sso.mailbox_of(&mail), Some(ARCHIVE_ID.to_owned()));

    collector.stop().await;
    Ok(())
}

/// Every deployment ships here: no rules, nothing moved, and not one request
/// about mailboxes.
#[tokio::test]
async fn a_deployment_with_no_rules_moves_nothing() -> Result<()> {
    ensure_stack().await?;
    let bus = Bus::connect().await?;
    let run = Run::prepare("triage-none").await?;
    run.authorize().await?;
    run.serve_snapshot(&bus, Vec::new()).await?;

    let collector = run.start_with_gateway()?;
    collector
        .wait_logged("mailbox taken as it stands", 1)
        .await?;
    let mail = run.sso.deliver(newsletter("Rien ne bouge"));
    collector.wait_logged("mailbox polled", 2).await?;

    assert_eq!(run.sso.mailbox_of(&mail), Some(INBOX_ID.to_owned()));
    assert!(run.sso.reported_moves().is_empty());
    assert_eq!(
        collector
            .count_logged("the owner's rule filed a mail")
            .await,
        0
    );

    collector.stop().await;
    Ok(())
}

/// The undo: the owner asks for a filed mail back, and it goes back to the
/// mailbox it came from — which is why that mailbox is recorded at all. The
/// reverse move is itself reported, pointing at the move it reverses, so the
/// journal answers *what happened* rather than *what somebody last said
/// happened* (#418, ADR 0042).
#[tokio::test]
async fn an_undo_puts_the_mail_back_and_is_itself_a_move() -> Result<()> {
    ensure_stack().await?;
    let bus = Bus::connect().await?;
    let run = Run::prepare("triage-undo").await?;
    run.authorize().await?;
    run.serve_snapshot(&bus, Vec::new()).await?;
    run.sso.set_mail_triage(json!({
        "destinations": ["Veille"],
        "rules": [
            { "id": "lettres", "field": "list_id",
              "value": "ml.lettre.example", "destination": "Veille" }
        ]
    }));

    let collector = run.start_with_gateway()?;
    collector
        .wait_logged("mailbox taken as it stands", 1)
        .await?;
    let mail = run.sso.deliver(newsletter("À remettre"));
    collector
        .wait_logged("the owner's rule filed a mail", 1)
        .await?;
    assert_eq!(run.sso.mailbox_of(&mail), Some(VEILLE_ID.to_owned()));

    // The owner presses "put it back" on their screen; the Gateway records
    // the request and serves it here, because the Gateway holds no mailbox.
    run.sso.set_mail_undos(json!([{
        "sequence": 1,
        "connection": run.mail,
        "email_id": mail,
        "rule_id": "lettres",
        "from_mailbox_id": INBOX_ID,
        "from_mailbox_name": "INBOX",
        "to_mailbox_id": VEILLE_ID,
        "to_mailbox_name": "Veille",
        "occurred_at": "2026-10-02T10:00:00.000Z",
        "undoes": null,
        "undo_requested_at": "2026-10-02T10:05:00.000Z"
    }]));
    // The rules are re-read before each round, so the next one carries it.
    collector
        .wait_logged("the owner's rule filed a mail", 1)
        .await?;
    run.sso.deliver(newsletter("Un autre tour"));

    twalk_test_harness::poll_until(
        || async { (run.sso.mailbox_of(&mail) == Some(INBOX_ID.to_owned())).then_some(()) },
        "the mail to come back to the inbox",
    )
    .await?;

    let reported = run.sso.reported_moves();
    let back = reported
        .iter()
        .find(|one| one["undoes"] == json!(1))
        .expect("the undo is reported as a move of its own");
    assert_eq!(
        back["rule_id"],
        json!("undo"),
        "no rule caused it; the owner did"
    );
    assert_eq!(back["from_mailbox_name"], json!("Veille"));
    assert_eq!(back["to_mailbox_name"], json!("INBOX"));

    collector.stop().await;
    Ok(())
}
