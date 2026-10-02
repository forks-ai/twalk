import { describe, expect, it } from 'vitest';
import en from '$lib/i18n/en.json';
import {
	emptyDraft,
	idIsTaken,
	isUndoable,
	movesForScreen,
	orphanedBy,
	REFUSAL_CODES,
	refusalKey,
	toRule,
	type Triage
} from './triage';

const triage = (): Triage => ({
	destinations: ['Veille', 'Archive'],
	rules: [
		{ id: 'newsletters', field: 'list_id', value: '<ml.example.com>', destination: 'Veille' },
		{ id: 'vieux', field: 'older_than_days', value: 30, destination: 'Archive' }
	]
});

describe('the owner writes their triage rules (#419)', () => {
	it('turns a draft into a rule, and refuses to invent one', () => {
		expect(
			toRule({ id: 'factures', field: 'subject', value: ' facture ', destination: ' Veille ' })
		).toEqual({ id: 'factures', field: 'subject', value: 'facture', destination: 'Veille' });

		// Not yet a rule: nothing is repaired on the way out, because a form
		// that quietly sent something else would decide for the owner.
		expect(toRule({ id: '', field: 'subject', value: 'x', destination: 'Veille' })).toBeNull();
		expect(toRule({ id: 'r', field: 'subject', value: '  ', destination: 'Veille' })).toBeNull();
		expect(toRule({ id: 'r', field: 'subject', value: 'x', destination: '' })).toBeNull();
	});

	it('takes an age as a whole number of days and nothing else', () => {
		const draft = { id: 'r', field: 'older_than_days' as const, destination: 'Veille' };
		expect(toRule({ ...draft, value: '30' })).toEqual({
			id: 'r',
			field: 'older_than_days',
			value: 30,
			destination: 'Veille'
		});
		for (const value of ['0', '-1', '3651', '7.5', 'sept', '']) {
			expect(toRule({ ...draft, value }), value).toBeNull();
		}
	});

	it('says which rules a destination’s removal would break, before the removal', () => {
		expect(orphanedBy(triage(), 'Veille').map((rule) => rule.id)).toEqual(['newsletters']);
		expect(orphanedBy(triage(), ' Archive ').map((rule) => rule.id)).toEqual(['vieux']);
		expect(orphanedBy(triage(), 'Jamais')).toEqual([]);
	});

	it('knows an id is already taken, and lets a rule keep its own', () => {
		expect(idIsTaken(triage(), 'newsletters')).toBe(true);
		expect(idIsTaken(triage(), ' newsletters ')).toBe(true);
		expect(idIsTaken(triage(), 'newsletters', 'newsletters')).toBe(false);
		expect(idIsTaken(triage(), 'nouveau')).toBe(false);
	});

	it('opens an empty draft on a destination the owner already declared', () => {
		expect(emptyDraft(triage()).destination).toBe('Veille');
		// And on none at all when they have declared none: the screen then
		// asks for a destination first, which is the honest order.
		expect(emptyDraft({ destinations: [], rules: [] }).destination).toBe('');
	});

	/**
	 * Every refusal the Gateway can send has a sentence. A code with none
	 * would reach the owner as an English word in the middle of their own
	 * language — which is the defect this holds shut.
	 */
	it('has a sentence for every refusal the Gateway can answer', () => {
		const catalogue = en as Record<string, string>;
		for (const code of REFUSAL_CODES) {
			const key = refusalKey(code);
			expect(catalogue[key], key).toBeTruthy();
		}
	});

	it('lists moves newest first and knows which can be put back', () => {
		const move = (sequence: number, undoes: number | null = null) => ({
			sequence,
			connection: 'mail',
			email_id: `m${sequence}`,
			rule_id: undoes ? 'undo' : 'newsletters',
			from_mailbox_id: 'a',
			from_mailbox_name: 'INBOX',
			to_mailbox_id: 'b',
			to_mailbox_name: 'Veille',
			occurred_at: '2026-10-02T10:00:00.000Z',
			undoes,
			undo_requested_at: null
		});
		expect(movesForScreen([move(1), move(3), move(2)]).map((m) => m.sequence)).toEqual([3, 2, 1]);
		expect(isUndoable(move(1))).toBe(true);
		// An undo cannot be undone: asking for that is asking for the first
		// move again, which the owner does by asking for the first move again.
		expect(isUndoable(move(4, 1))).toBe(false);
	});
});
