//! Who the owner is, which is **every address they hold** and not the one
//! address the collector was configured with (issue #322).
//!
//! # What one address cost
//!
//! Found by #279's first production run. The reference deployment's owner is
//! `mmaudet@linagora.com` at their mailbox and `michel.maudet@linagora.com` on
//! their business card; both are theirs, and every part of the collector that
//! asked "is this the owner?" compared one string.
//!
//! So an alias read as somebody else, everywhere it mattered. A mail the owner
//! sent from their other address — to themselves, back from a list, from a phone
//! configured with the alias — passed the frontier that exists to drop the
//! owner's own traffic (ADR 0021), became `inbound.message.received.v1`, and put
//! the owner in their own Companion as a `pending` contact to decide about, which
//! is ADR 0018's whole point inverted. A decision about that address would have
//! been recorded like a contact's, because the consent cache is told the owner's
//! identities and was told one. An event the alias attended would have had the
//! owner withheld or counted as a third party by the calendar reduction (#280).
//! And the reply path picks the sending identity whose address is the owner's, so
//! an owner whose mailbox sends as the alias had no identity at all and every
//! approved reply failed permanently with a clear and puzzling message.
//!
//! # Why configuration and not the service
//!
//! The obvious alternative is to ask: TMail's `Identity/get` lists the addresses
//! an account may send as, OpenPaaS's `/api/user` carries `emails[]`. It is
//! rejected here for two reasons that are about identity and not about effort.
//! **The collector would be trusting a service for the owner's own identity** —
//! and the check it does at `authorize` time, that a grant belongs to the owner,
//! is precisely a check *against* what the service says; deriving the answer from
//! the same source would make that check tautological. And **an address the
//! mailbox does not know is still the owner's**: a list posts as
//! `michel.maudet@`, an old address forwards, a second organisation's mailbox is
//! read by the same person. The operator declares who they are, as they already
//! declare their primary address; a service's list would be a convenience that
//! silently narrows the answer.
//!
//! # One concept, and the word for it
//!
//! What this module holds is the collector's half of `CONTEXT.md`'s **owner
//! identity**: the set of identities the owner's own traffic arrives under,
//! confirmed by the deployment because it cannot be derived from a service. On
//! the Sensor's side those are Matrix IDs (network ghosts); here they are the
//! addresses of a mailbox, which is why the type speaks of addresses and the
//! variable an operator sets is named for what they would call them. The rule is
//! the same on either side: an identity the deployment has not confirmed stays a
//! contact, because unknown is not the owner.
//!
//! Nothing here reads a mailbox or a calendar. It is one question — *is this
//! address the owner's?* — asked in five places that used to each lowercase a
//! string and compare it.

/// The owner's addresses: the one they are named by, and the others they hold.
///
/// Every address is trimmed and lowercased once, here, so that no caller has to
/// remember to: an address that differed only in case was the same defect as an
/// address that differed entirely, and it was written out four times.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Owner {
    /// `COLLECTOR_OWNER_EMAIL`: the address the owner is named by, which is what
    /// a refusal names, what the reply path prefers to send as, and what the
    /// consent cache knows them by.
    primary: String,
    /// `COLLECTOR_OWNER_ALIASES`: every other address that is theirs — each one an
    /// **owner identity** in `CONTEXT.md`'s terms, spelled as an address because
    /// that is what a mailbox compares. Never contains `primary`, never empty
    /// strings, and holds no duplicates.
    aliases: Vec<String>,
}

impl Owner {
    /// The owner named by `primary`, who also holds `aliases`.
    ///
    /// An alias equal to the primary address, or blank, is dropped rather than
    /// refused: a comma-separated variable ending in a comma is not a
    /// configuration error worth refusing to start over, and an operator who
    /// repeats their primary address has said nothing new.
    pub fn new<I, S>(primary: &str, aliases: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let primary = normalise(primary);
        let mut held: Vec<String> = Vec::new();
        for alias in aliases {
            let alias = normalise(alias.as_ref());
            if alias.is_empty() || alias == primary || held.contains(&alias) {
                continue;
            }
            held.push(alias);
        }
        Self {
            primary,
            aliases: held,
        }
    }

    /// The address the owner is named by.
    pub fn primary(&self) -> &str {
        &self.primary
    }

    /// The other addresses they hold, in the order they were declared.
    pub fn aliases(&self) -> &[String] {
        &self.aliases
    }

    /// Whether this address is the owner's. The one question this module exists
    /// for; case and surrounding space are not a difference.
    pub fn holds(&self, email: &str) -> bool {
        let email = normalise(email);
        !email.is_empty() && (email == self.primary || self.aliases.contains(&email))
    }

    /// Every address they hold, the primary one first.
    pub fn addresses(&self) -> impl Iterator<Item = &str> {
        std::iter::once(self.primary.as_str()).chain(self.aliases.iter().map(String::as_str))
    }

    /// The `mailto:` subject each address makes, the primary one first: how the
    /// consent cache is told who the owner is, since the collector has no Matrix
    /// ID to name them by (ADR 0021).
    pub fn mailtos(&self) -> impl Iterator<Item = String> + '_ {
        self.addresses().map(crate::side::owner_mailto)
    }

    /// Whether this **subject** is the owner's: `holds`, for the places that hold
    /// a `mailto:` rather than an address — an event's organizer and its
    /// participants. Here rather than at the caller, so that the one question is
    /// asked in one place whichever spelling it arrives in.
    pub fn holds_mailto(&self, subject: &str) -> bool {
        self.mailtos()
            .any(|mine| mine == crate::side::owner_mailto(subject))
    }

    /// The owner named by one address and holding no other: what a test that is
    /// not about this type wants, in one place rather than in each test module.
    #[cfg(test)]
    pub fn named(email: &str) -> Self {
        Self::new(email, Vec::<String>::new())
    }
}

/// One address, as every comparison here wants it.
fn normalise(email: &str) -> String {
    email.trim().to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRIMARY: &str = "mmaudet@linagora.com";
    const ALIAS: &str = "michel.maudet@linagora.com";

    #[test]
    fn the_owner_is_every_address_they_hold() {
        let owner = Owner::new(PRIMARY, [ALIAS]);

        assert_eq!(owner.primary(), PRIMARY);
        assert!(owner.holds(PRIMARY));
        assert!(
            owner.holds(ALIAS),
            "the address on their business card is theirs: the defect #322 names is that it was not"
        );
        assert!(!owner.holds("someone@example.com"));

        // Case and space are not a difference. A mailbox spells an address back
        // however it likes, and four places used to lowercase it each.
        assert!(owner.holds("  MMaudet@Linagora.COM "));
        assert!(owner.holds("MICHEL.MAUDET@linagora.com"));

        // Nothing is not somebody: an empty `from` is not the owner, which would
        // otherwise drop every mail whose sender could not be read.
        assert!(!owner.holds(""));
        assert!(!owner.holds("   "));
    }

    #[test]
    fn a_declaration_is_read_the_way_an_operator_writes_one() {
        // A trailing comma, a repeat of the primary address, the same alias
        // twice, and a stray space: none of them is a reason to refuse to start,
        // and none of them says anything new.
        let owner = Owner::new(
            &format!("  {PRIMARY} "),
            [
                "",
                " ",
                ALIAS,
                PRIMARY,
                &ALIAS.to_uppercase(),
                "me@work.example",
            ],
        );

        assert_eq!(owner.primary(), PRIMARY);
        assert_eq!(owner.aliases(), [ALIAS, "me@work.example"]);
        assert_eq!(
            owner.addresses().collect::<Vec<_>>(),
            [PRIMARY, ALIAS, "me@work.example"],
            "the primary address comes first: it is the one a refusal names and the one the reply \
             path prefers"
        );
    }

    #[test]
    fn an_owner_with_no_alias_is_exactly_what_it_was() {
        // The deployment that declares nothing must behave as it did, because
        // this ticket is a fix and not a change of policy.
        let owner = Owner::named(PRIMARY);

        assert!(owner.aliases().is_empty());
        assert!(owner.holds(PRIMARY));
        assert!(!owner.holds(ALIAS));
        assert_eq!(owner.addresses().collect::<Vec<_>>(), [PRIMARY]);
    }

    #[test]
    fn the_consent_cache_is_told_every_address_as_a_mailto() {
        // ADR 0021: the owner has no consent state, and the cache enforces that
        // from the identities it is given. Given one, a decision about an alias
        // would be recorded like a contact's.
        let owner = Owner::new(PRIMARY, [ALIAS]);

        assert_eq!(
            owner.mailtos().collect::<Vec<_>>(),
            [format!("mailto:{PRIMARY}"), format!("mailto:{ALIAS}")]
        );
    }
}
