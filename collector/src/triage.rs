//! Filing the owner's mail where their own rules say (issue #417, ADR 0042).
//!
//! The pure half: which rule a mail matches, and which mailbox that rule files
//! into. The I/O — `Mailbox/get` to learn what mailboxes exist and what they
//! are, `Email/set` to move one — is `jmap.rs`'s, and the loop is `main.rs`'s.
//!
//! # No model is in this path, and that is the decision
//!
//! ADR 0039 says the drafting lane is the one place in this project where *the
//! input is written by a stranger*. Triage is that lane with a side effect: a
//! model sorting the inbox reads text composed outside the deployment and then
//! acts on the mailbox it read it from, so a spam saying *move everything from
//! the finance team to the trash* is an instruction it cannot tell from the
//! owner's. ADR 0042 removes the class rather than mitigating it. Everything
//! here is a comparison against a field the **server parsed** — an address, a
//! subject, a `List-Id`, an instant — and nothing reads the body.
//!
//! # The destination is checked twice, and this is the authority
//!
//! The Gateway refuses a destructive destination by name, in the languages the
//! Companion speaks, so the owner is told while they are writing the rule. A
//! name is a weak signal, though: what a mailbox *is* is its JMAP `role`, and
//! this is the only component that can see one. So a destination whose role is
//! `trash` or `junk` is refused **here**, whatever the Gateway let through, and
//! that refusal is the one that counts.

use std::collections::BTreeMap;

use serde::Deserialize;

/// A mailbox as `Mailbox/get` answers it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Mailbox {
    pub id: String,
    pub name: String,
    /// `inbox`, `archive`, `trash`, `junk`, … or none for a mailbox the owner
    /// made themselves. This is what a mailbox *is*, as against what it is
    /// called.
    #[serde(default)]
    pub role: Option<String>,
}

/// The roles a mail may never be filed into, whatever the rule says.
///
/// Both are purged on a timer by most servers, so a move there has an expiry
/// date — and a reversible act that stops being reversible is not reversible
/// (ADR 0042).
pub const DESTRUCTIVE_ROLES: [&str; 2] = ["trash", "junk"];

/// What a rule looks at, as the Gateway serves it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "field", content = "value", rename_all = "snake_case")]
pub enum Match {
    Sender(String),
    Subject(String),
    ListId(String),
    OlderThanDays(u32),
}

/// One rule of the owner's.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Rule {
    pub id: String,
    #[serde(flatten)]
    pub matches: Match,
    pub destination: String,
}

/// The whole set, as `GET /api/settings/collection` carries it.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
pub struct Triage {
    #[serde(default)]
    pub destinations: Vec<String>,
    #[serde(default)]
    pub rules: Vec<Rule>,
}

impl Triage {
    /// Whether this deployment triages at all. Every deployment ships here.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

/// The set, shared with the mail poll and replaced before each round — the
/// same shape the working day takes (#381), and for the same reason: a
/// decision taken on the settings screen reaches the next round rather than
/// the next restart.
pub type SharedTriage = std::sync::Arc<std::sync::Mutex<Triage>>;

/// One undo the owner asked for, as the Gateway serves it on the collection
/// seam (#418). The move is reversed by putting the mail back in the mailbox
/// it came from — which is why that mailbox is recorded in the first place.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct PendingUndo {
    pub sequence: i64,
    pub connection: String,
    pub email_id: String,
    pub from_mailbox_id: String,
    pub from_mailbox_name: String,
    pub to_mailbox_id: String,
    pub to_mailbox_name: String,
}

/// The `rule_id` an undo carries: no rule caused it, the owner did. The same
/// word the Gateway's journal uses (`mail_moves::UNDO_RULE`).
pub const UNDO_RULE: &str = "undo";

/// The undos waiting, shared with the poll as the rules are.
pub type SharedUndos = std::sync::Arc<std::sync::Mutex<Vec<PendingUndo>>>;

/// Why a rule could not be applied. Each is counted and logged, because a rule
/// that silently does nothing is the one failure an owner cannot see.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unusable {
    /// The server has no mailbox by that name.
    NoSuchMailbox,
    /// It has one and its role is `trash` or `junk`. The Gateway should have
    /// refused it by name; this is the check that actually knows.
    DestinationIsDestructive,
    /// The rule names a mailbox the owner's own allowlist does not hold. The
    /// Gateway refuses this at the writer, so reaching it here means the set
    /// was written by something older — withheld rather than trusted.
    DestinationNotAllowed,
}

impl Unusable {
    pub fn as_str(self) -> &'static str {
        match self {
            Unusable::NoSuchMailbox => "no_such_mailbox",
            Unusable::DestinationIsDestructive => "destination_is_destructive",
            Unusable::DestinationNotAllowed => "destination_not_allowed",
        }
    }
}

/// What to do with one mail: nothing, or move it into this mailbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Filing {
    pub rule_id: String,
    pub mailbox_id: String,
    pub mailbox_name: String,
}

/// Resolves a destination name to the mailbox a move would use.
///
/// Compared on the mailbox's **name** as the owner wrote it, trimmed. Not
/// lower-cased: a mailbox name belongs to the server, and two names differing
/// only in case are two mailboxes on some of them.
pub fn resolve<'a>(
    mailboxes: &'a [Mailbox],
    triage: &Triage,
    destination: &str,
) -> Result<&'a Mailbox, Unusable> {
    if !triage
        .destinations
        .iter()
        .any(|allowed| allowed.trim() == destination.trim())
    {
        return Err(Unusable::DestinationNotAllowed);
    }
    let mailbox = mailboxes
        .iter()
        .find(|mailbox| mailbox.name.trim() == destination.trim())
        .ok_or(Unusable::NoSuchMailbox)?;
    if mailbox
        .role
        .as_deref()
        .is_some_and(|role| DESTRUCTIVE_ROLES.contains(&role.to_lowercase().as_str()))
    {
        return Err(Unusable::DestinationIsDestructive);
    }
    Ok(mailbox)
}

/// Whether one rule matches one mail.
///
/// `now` is passed rather than read, so the one match that is about time is a
/// pure function like the other three.
pub fn matches(rule: &Match, mail: &crate::jmap::Mail, now: std::time::SystemTime) -> bool {
    match rule {
        // `*@domain` and `local@*` on one side only. Not a pattern language:
        // a rule is something the owner reads back in six months.
        Match::Sender(pattern) => sender_matches(pattern, &mail.from.email),
        Match::Subject(fragment) => mail
            .subject
            .to_lowercase()
            .contains(fragment.trim().to_lowercase().as_str()),
        Match::ListId(wanted) => mail
            .list_id
            .as_deref()
            .is_some_and(|held| held.to_lowercase().contains(&wanted.trim().to_lowercase())),
        Match::OlderThanDays(days) => older_than(&mail.received_at, *days, now),
    }
}

fn sender_matches(pattern: &str, address: &str) -> bool {
    let pattern = pattern.trim().to_lowercase();
    let address = address.trim().to_lowercase();
    if let Some(domain) = pattern.strip_prefix("*@") {
        return address
            .rsplit_once('@')
            .is_some_and(|(_, held)| held == domain);
    }
    if let Some(local) = pattern.strip_suffix("@*") {
        return address
            .split_once('@')
            .is_some_and(|(held, _)| held == local);
    }
    pattern == address
}

/// Whether a mail received at this RFC 3339 instant is older than `days`.
///
/// An unparseable instant is **not** old: a mail whose date this build cannot
/// read must not be filed by a rule about age, because the one thing worse
/// than not triaging is triaging on a value nobody checked.
fn older_than(received_at: &str, days: u32, now: std::time::SystemTime) -> bool {
    let Ok(received) = chrono::DateTime::parse_from_rfc3339(received_at) else {
        return false;
    };
    let now: chrono::DateTime<chrono::Utc> = now.into();
    let age = now.signed_duration_since(received.with_timezone(&chrono::Utc));
    age.num_seconds() > i64::from(days) * 86_400
}

/// The first rule that matches, resolved to a mailbox — or nothing, or why a
/// matching rule could not be used.
///
/// **First match wins**, in the owner's own order, so a set is read the way it
/// is written. A mail matching two rules is filed by the first; the owner
/// orders them and that order is their decision, not an accident of a map's
/// iteration.
pub fn file(
    triage: &Triage,
    mailboxes: &[Mailbox],
    mail: &crate::jmap::Mail,
    now: std::time::SystemTime,
) -> Result<Option<Filing>, (String, Unusable)> {
    for rule in &triage.rules {
        if !matches(&rule.matches, mail, now) {
            continue;
        }
        return match resolve(mailboxes, triage, &rule.destination) {
            Ok(mailbox) => Ok(Some(Filing {
                rule_id: rule.id.clone(),
                mailbox_id: mailbox.id.clone(),
                mailbox_name: mailbox.name.clone(),
            })),
            Err(why) => Err((rule.id.clone(), why)),
        };
    }
    Ok(None)
}

/// Every destination of the set, resolved once, with the reason for each one
/// that cannot be used. For the log line a deployment prints when its rules
/// change: an owner finds out that a mailbox was renamed from this rather than
/// from mail that quietly stops moving.
pub fn resolve_all(
    triage: &Triage,
    mailboxes: &[Mailbox],
) -> BTreeMap<String, Result<String, Unusable>> {
    triage
        .destinations
        .iter()
        .map(|destination| {
            (
                destination.clone(),
                resolve(mailboxes, triage, destination).map(|mailbox| mailbox.id.clone()),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mailboxes() -> Vec<Mailbox> {
        vec![
            Mailbox {
                id: "mb-inbox".into(),
                name: "INBOX".into(),
                role: Some("inbox".into()),
            },
            Mailbox {
                id: "mb-veille".into(),
                name: "Veille".into(),
                role: None,
            },
            Mailbox {
                id: "mb-archive".into(),
                name: "Archive".into(),
                role: Some("archive".into()),
            },
            // A mailbox the owner called something innocuous whose role is the
            // trash. The whole reason the role is the authority.
            Mailbox {
                id: "mb-vrac".into(),
                name: "Vrac".into(),
                role: Some("Trash".into()),
            },
        ]
    }

    fn triage() -> Triage {
        Triage {
            destinations: vec!["Veille".into(), "Archive".into(), "Vrac".into()],
            rules: vec![],
        }
    }

    fn mail(
        from: &str,
        subject: &str,
        list_id: Option<&str>,
        received_at: &str,
    ) -> crate::jmap::Mail {
        crate::jmap::Mail {
            id: "m1".into(),
            received_at: received_at.into(),
            from: crate::jmap::Person {
                name: None,
                email: from.into(),
            },
            to: vec![],
            cc: vec![],
            subject: subject.into(),
            body: "le corps, que rien ici ne lit".into(),
            message_id: None,
            in_reply_to: None,
            references: vec![],
            attachments: vec![],
            auto_submitted: None,
            list_id: list_id.map(str::to_owned),
            list_unsubscribe: None,
            precedence: None,
            has_itip_part: false,
        }
    }

    fn now() -> std::time::SystemTime {
        std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_790_000_000)
    }

    /// The role is the authority, not the name: a mailbox the owner called
    /// "Vrac" whose role is the trash is refused, although nothing about its
    /// name says so and the Gateway let it through (ADR 0042).
    #[test]
    fn a_mailbox_whose_role_is_the_trash_is_refused_whatever_it_is_called() {
        assert_eq!(
            resolve(&mailboxes(), &triage(), "Vrac"),
            Err(Unusable::DestinationIsDestructive)
        );
        assert_eq!(
            resolve(&mailboxes(), &triage(), "Veille").unwrap().id,
            "mb-veille"
        );
    }

    /// A destination the owner's allowlist does not hold is withheld even when
    /// the server has such a mailbox — the set was written by something older
    /// than the check, and a rule nobody declared is not a rule.
    #[test]
    fn a_destination_outside_the_allowlist_is_withheld() {
        let narrow = Triage {
            destinations: vec!["Veille".into()],
            rules: vec![],
        };
        assert_eq!(
            resolve(&mailboxes(), &narrow, "Archive"),
            Err(Unusable::DestinationNotAllowed)
        );
        let absent = Triage {
            destinations: vec!["Fantôme".into()],
            rules: vec![],
        };
        assert_eq!(
            resolve(&mailboxes(), &absent, "Fantôme"),
            Err(Unusable::NoSuchMailbox)
        );
    }

    #[test]
    fn a_sender_matches_whole_or_by_one_wildcard() {
        let m = mail("Facture@Example.COM", "x", None, "2026-10-01T10:00:00Z");
        assert!(matches(
            &Match::Sender("facture@example.com".into()),
            &m,
            now()
        ));
        assert!(matches(&Match::Sender("*@example.com".into()), &m, now()));
        assert!(matches(&Match::Sender("facture@*".into()), &m, now()));
        assert!(!matches(&Match::Sender("*@autre.com".into()), &m, now()));
        assert!(!matches(&Match::Sender("facturier@*".into()), &m, now()));
        // A bare domain is not a wildcard: a rule is read back in six months.
        assert!(!matches(&Match::Sender("example.com".into()), &m, now()));
    }

    #[test]
    fn a_subject_and_a_list_id_match_case_insensitively() {
        let m = mail(
            "a@b.c",
            "Votre FACTURE de septembre",
            Some("<ml.Example.COM>"),
            "2026-10-01T10:00:00Z",
        );
        assert!(matches(&Match::Subject("facture".into()), &m, now()));
        assert!(matches(&Match::Subject("  FACTURE ".into()), &m, now()));
        assert!(!matches(&Match::Subject("devis".into()), &m, now()));
        assert!(matches(&Match::ListId("ml.example.com".into()), &m, now()));
        let no_list = mail("a@b.c", "x", None, "2026-10-01T10:00:00Z");
        assert!(!matches(
            &Match::ListId("ml.example.com".into()),
            &no_list,
            now()
        ));
    }

    /// A mail whose date this build cannot read is never old: the one thing
    /// worse than not triaging is triaging on a value nobody checked.
    #[test]
    fn age_is_measured_and_an_unreadable_date_is_never_old() {
        // now() is 2026-09-21T...; a mail from 2026-08-01 is ~51 days old.
        let old = mail("a@b.c", "x", None, "2026-08-01T10:00:00Z");
        assert!(matches(&Match::OlderThanDays(30), &old, now()));
        assert!(!matches(&Match::OlderThanDays(90), &old, now()));
        let fresh = mail("a@b.c", "x", None, "2026-09-21T09:00:00Z");
        assert!(!matches(&Match::OlderThanDays(1), &fresh, now()));
        let unreadable = mail("a@b.c", "x", None, "hier matin");
        assert!(!matches(&Match::OlderThanDays(1), &unreadable, now()));
        assert!(!matches(&Match::OlderThanDays(3650), &unreadable, now()));
    }

    /// First match wins, in the owner's own order — a set is read the way it
    /// is written, not the way a map happens to iterate.
    #[test]
    fn the_first_matching_rule_files_it() {
        let set = Triage {
            destinations: vec!["Veille".into(), "Archive".into()],
            rules: vec![
                Rule {
                    id: "r1".into(),
                    matches: Match::Subject("facture".into()),
                    destination: "Veille".into(),
                },
                Rule {
                    id: "r2".into(),
                    matches: Match::Sender("*@example.com".into()),
                    destination: "Archive".into(),
                },
            ],
        };
        let m = mail(
            "compta@example.com",
            "Votre facture",
            None,
            "2026-10-01T10:00:00Z",
        );
        let filed = file(&set, &mailboxes(), &m, now()).unwrap().unwrap();
        assert_eq!(filed.rule_id, "r1");
        assert_eq!(filed.mailbox_id, "mb-veille");
        // A mail only the second rule matches takes the second.
        let other = mail("rh@example.com", "Bonjour", None, "2026-10-01T10:00:00Z");
        assert_eq!(
            file(&set, &mailboxes(), &other, now())
                .unwrap()
                .unwrap()
                .rule_id,
            "r2"
        );
        // And one nothing matches is left alone.
        let untouched = mail("ami@ailleurs.org", "Coucou", None, "2026-10-01T10:00:00Z");
        assert_eq!(file(&set, &mailboxes(), &untouched, now()).unwrap(), None);
    }

    /// A matching rule whose destination cannot be used says so, naming the
    /// rule: silence here is the one failure an owner cannot see.
    #[test]
    fn a_matching_rule_that_cannot_be_applied_names_itself() {
        let set = Triage {
            destinations: vec!["Vrac".into()],
            rules: vec![Rule {
                id: "dangereuse".into(),
                matches: Match::Subject("x".into()),
                destination: "Vrac".into(),
            }],
        };
        let m = mail("a@b.c", "x", None, "2026-10-01T10:00:00Z");
        assert_eq!(
            file(&set, &mailboxes(), &m, now()),
            Err(("dangereuse".into(), Unusable::DestinationIsDestructive))
        );
    }

    /// Every deployment ships here, and nothing must happen.
    #[test]
    fn a_deployment_with_no_rules_files_nothing() {
        let m = mail("a@b.c", "x", None, "2026-10-01T10:00:00Z");
        assert!(Triage::default().is_empty());
        assert_eq!(
            file(&Triage::default(), &mailboxes(), &m, now()).unwrap(),
            None
        );
    }

    /// The wire shape the Gateway serves, pinned: a field renamed there is a
    /// field this stops finding, and the test is what says so.
    #[test]
    fn the_set_is_read_from_the_gateways_own_shape() {
        let document = serde_json::json!({
            "destinations": ["Veille"],
            "rules": [
                { "id": "newsletters", "field": "list_id",
                  "value": "<ml.example.com>", "destination": "Veille" },
                { "id": "vieux", "field": "older_than_days",
                  "value": 30, "destination": "Veille" }
            ]
        });
        let set: Triage = serde_json::from_value(document).unwrap();
        assert_eq!(set.destinations, vec!["Veille".to_owned()]);
        assert_eq!(
            set.rules[0].matches,
            Match::ListId("<ml.example.com>".into())
        );
        assert_eq!(set.rules[1].matches, Match::OlderThanDays(30));
        // A Gateway older than the decision serves neither member.
        let empty: Triage = serde_json::from_value(serde_json::json!({})).unwrap();
        assert!(empty.is_empty());
    }
}
