/**
 * The owner's mail triage rules, as the screen works with them (#419,
 * ADR 0042).
 *
 * The wire shape is a set — an allowlist of destinations and a list of rules —
 * and the screen edits it whole, because a rule is only valid against the
 * allowlist it was written for. This module is the part of that editing worth
 * testing without a browser: what the form holds, what a draft rule becomes on
 * the wire, which rules a destination's removal would break, and the sentence
 * key for a refusal the Gateway sent back.
 */

import type { components } from '$lib/api/schema';
import type { MessageKey } from '$lib/i18n';

export type Triage = components['schemas']['MailTriage'];
export type Rule = components['schemas']['MailRule'];
export type MailMove = components['schemas']['MailMove'];

/** The fields a rule may look at, in the order the screen offers them. */
export const FIELDS = ['sender', 'subject', 'list_id', 'older_than_days'] as const;
export type Field = (typeof FIELDS)[number];

/** What the form holds while the owner is typing. */
export interface Draft {
	id: string;
	field: Field;
	value: string;
	destination: string;
}

/** An empty draft, filing into the first destination the owner declared. */
export function emptyDraft(triage: Triage): Draft {
	return { id: '', field: 'list_id', value: '', destination: triage.destinations[0] ?? '' };
}

/**
 * A draft as the wire wants it, or `null` when it is not yet a rule.
 *
 * Nothing is repaired on the way out. An empty value is not a rule, and
 * `older_than_days` that is not a positive whole number is not a rule — the
 * Gateway would refuse both, and a form that quietly sent something else would
 * be deciding on the owner's behalf.
 */
export function toRule(draft: Draft): Rule | null {
	const id = draft.id.trim();
	const destination = draft.destination.trim();
	if (id === '' || destination === '') return null;
	if (draft.field === 'older_than_days') {
		const days = Number(draft.value.trim());
		if (!Number.isInteger(days) || days < 1 || days > 3650) return null;
		return { id, field: draft.field, value: days, destination };
	}
	const value = draft.value.trim();
	if (value === '') return null;
	return { id, field: draft.field, value, destination };
}

/**
 * The rules a destination's removal would leave filing nowhere.
 *
 * Shown before the removal rather than after: the Gateway refuses the whole
 * set, so an owner who removed a destination used by a rule would otherwise
 * get one `422` about a rule they were not thinking about.
 */
export function orphanedBy(triage: Triage, destination: string): Rule[] {
	return triage.rules.filter((rule) => rule.destination.trim() === destination.trim());
}

/** Whether this id is already taken — two rules cannot share one. */
export function idIsTaken(triage: Triage, id: string, except?: string): boolean {
	const wanted = id.trim();
	return triage.rules.some((rule) => rule.id === wanted && rule.id !== except);
}

/**
 * The sentence for a refusal the Gateway sent back, by its code.
 *
 * Every code the Gateway can answer has one, and the test below holds the two
 * lists together: a code with no sentence would reach the owner as an English
 * word in the middle of their own language.
 */
export function refusalKey(code: string): MessageKey {
	return `settings.triage.refused.${code}` as MessageKey;
}

/** Every code `PUT /api/settings/mail-triage` can answer with. */
export const REFUSAL_CODES = [
	'destination_not_allowed',
	'destination_is_destructive',
	'destination_is_empty',
	'destination_too_long',
	'match_is_empty',
	'match_too_long',
	'match_out_of_range',
	'too_many_rules',
	'duplicate_rule_id',
	'rule_id_is_empty',
	'rule_id_too_long',
	'malformed_request'
] as const;

/**
 * A move as the screen lists it: newest first, and an undo shown as what it
 * is rather than as a move of its own kind.
 */
export function movesForScreen(moves: MailMove[]): MailMove[] {
	return [...moves].sort((a, b) => b.sequence - a.sequence);
}

/** Whether this move can still be put back. */
export function isUndoable(move: MailMove): boolean {
	return move.undoes === null && move.undoes === undefined ? true : !move.undoes;
}
