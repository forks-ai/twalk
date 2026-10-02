//! What the owner's triage rules actually moved, and putting one back
//! (issue #418, ADR 0042).
//!
//! The collector does the moving — it is the only component holding the
//! mailbox — and reports each move here. This Gateway keeps the record and
//! serves it to the owner, and takes their request to put one back.
//!
//! # An undo is a move, not an erasure
//!
//! The Gateway cannot move a mail, so "undo" is not an act it can perform. It
//! records that the owner asked; the collector reads the request on the seam
//! it already fetches, performs the reverse move, and reports *that* as a move
//! of its own, pointing at the one it reverses. The journal therefore answers
//! *what happened* rather than *what somebody last said happened*, which is
//! the whole reason it is append-only.
//!
//! # What is not kept
//!
//! No subject, no sender, no body. The mail's id, the two mailboxes, the rule
//! and the instant. A contact's words have no business in a record about where
//! a message is filed.

use serde::{Deserialize, Serialize};

/// One move, as the collector reports it and as the journal holds it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Move {
    pub connection: String,
    pub email_id: String,
    /// The rule that caused it, or [`UNDO_RULE`] when this move is an undo.
    pub rule_id: String,
    pub from_mailbox_id: String,
    pub from_mailbox_name: String,
    pub to_mailbox_id: String,
    pub to_mailbox_name: String,
    pub occurred_at: String,
    /// The `sequence` of the move this one reverses, when it is an undo.
    #[serde(default)]
    pub undoes: Option<i64>,
}

/// The `rule_id` an undo carries: no rule caused it, the owner did.
pub const UNDO_RULE: &str = "undo";

/// A move as the journal answers it: the move, its position, and whether an
/// undo has been asked for and not yet done.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Recorded {
    pub sequence: i64,
    #[serde(flatten)]
    pub moved: Move,
    pub undo_requested_at: Option<String>,
}

/// How many moves one read answers with. A bound rather than a limit anybody
/// meets: the screen shows a page. No `MAX_LIMIT` beside it, because this
/// route takes no `limit` — one would be surface nobody asked for.
pub const DEFAULT_LIMIT: usize = 50;
