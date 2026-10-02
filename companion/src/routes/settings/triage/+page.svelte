<!--
	Mail triage (#419, ADR 0042): where the owner writes the rules that file
	their own mailbox.

	Three things this screen must say, and says on the screen rather than only
	in a commit message:

	  - **no model decides anything here.** The rules are applied by the
	    collector, deterministically, against envelope fields. A screen that
	    let the owner believe an agent was reading their mail and judging it
	    would be describing a system this project deliberately did not build
	    (ADR 0039, ADR 0042);
	  - **the trash can never be a destination**, and the reason is not
	    squeamishness: most servers purge it on a timer, so a move there has an
	    expiry date and the undo below would stop working;
	  - **the first matching rule wins**, in the owner's own order. That makes
	    the order a decision, so the screen states it instead of leaving it to
	    be discovered.

	The set is saved whole. A rule is only valid against the allowlist it was
	written for, so the Gateway refuses or accepts all of it — and this screen
	warns *before* a removal which rules it would leave filing nowhere, rather
	than relaying a 422 about a rule the owner was not thinking about.
-->
<script lang="ts">
	import { onMount } from 'svelte';
	import { t } from '$lib/i18n';
	import {
		loadMoves,
		loadTriage,
		saveTriage,
		undoMove,
		type MovesAnswer,
		type TriageAnswer
	} from '$lib/settings/api';
	import {
		emptyDraft,
		FIELDS,
		idIsTaken,
		isUndoable,
		movesForScreen,
		orphanedBy,
		refusalKey,
		toRule,
		type Draft,
		type MailMove,
		type Triage
	} from '$lib/settings/triage';

	let triage: Triage = $state({ destinations: [], rules: [] });
	let moves: MailMove[] = $state([]);
	let draft: Draft = $state({ id: '', field: 'list_id', value: '', destination: '' });
	let newDestination = $state('');
	let trouble: string | null = $state(null);
	let saving = $state(false);
	let loaded = $state(false);

	onMount(async () => {
		await refresh();
		draft = emptyDraft(triage);
		loaded = true;
	});

	async function refresh() {
		const answer: TriageAnswer = await loadTriage();
		if (answer.ok) triage = answer.triage;
		const seen: MovesAnswer = await loadMoves();
		if (seen.ok) moves = movesForScreen(seen.moves);
	}

	/** Saves the whole set, and keeps the Gateway's own refusal when it has one. */
	async function save(next: Triage) {
		saving = true;
		trouble = null;
		const answer = await saveTriage(next);
		saving = false;
		if (answer.ok) {
			triage = answer.triage;
			draft = emptyDraft(triage);
			return true;
		}
		trouble = answer.code ? $t(refusalKey(answer.code)) : (answer.detail ?? $t('settings.triage.trouble'));
		return false;
	}

	async function addDestination() {
		const name = newDestination.trim();
		if (name === '') return;
		if (await save({ ...triage, destinations: [...triage.destinations, name] })) {
			newDestination = '';
		}
	}

	async function removeDestination(name: string) {
		await save({
			...triage,
			destinations: triage.destinations.filter((held) => held !== name)
		});
	}

	async function addRule() {
		const rule = toRule(draft);
		if (rule === null) return;
		await save({ ...triage, rules: [...triage.rules, rule] });
	}

	async function removeRule(id: string) {
		await save({ ...triage, rules: triage.rules.filter((rule) => rule.id !== id) });
	}

	/** Moves a rule up, because the first match wins and the order is a decision. */
	async function raise(index: number) {
		if (index === 0) return;
		const rules = [...triage.rules];
		[rules[index - 1], rules[index]] = [rules[index], rules[index - 1]];
		await save({ ...triage, rules });
	}

	async function putBack(sequence: number) {
		const answer = await undoMove(sequence);
		if (answer.ok) await refresh();
		else trouble = answer.detail ?? $t('settings.triage.trouble');
	}

	const draftIsRule = $derived(toRule(draft) !== null && !idIsTaken(triage, draft.id));
</script>

<svelte:head><title>{$t('settings.triage.title')}</title></svelte:head>

<h1>{$t('settings.triage.title')}</h1>
<p class="lead">{$t('settings.triage.lead')}</p>

{#if trouble}
	<p class="card card--warning" role="alert" data-testid="triage-trouble">{trouble}</p>
{/if}

<section class="card">
	<h2>{$t('settings.triage.destinations.title')}</h2>
	<p class="small muted">{$t('settings.triage.destinations.lead')}</p>
	<p class="small muted">{$t('settings.triage.destinations.never')}</p>
	<ul data-testid="destinations">
		{#each triage.destinations as destination (destination)}
			<li>
				<span>{destination}</span>
				{#if orphanedBy(triage, destination).length > 0}
					<span class="small muted">
						{$t('settings.triage.orphaned', {
							rules: orphanedBy(triage, destination)
								.map((rule) => rule.id)
								.join(', ')
						})}
					</span>
				{/if}
				<button type="button" onclick={() => removeDestination(destination)} disabled={saving}>
					{$t('settings.triage.remove')}
				</button>
			</li>
		{/each}
	</ul>
	<label class="field">
		<span class="label">{$t('settings.triage.destinations.title')}</span>
		<input bind:value={newDestination} disabled={saving} data-testid="new-destination" />
	</label>
	<button type="button" onclick={addDestination} disabled={saving || newDestination.trim() === ''}>
		{$t('settings.triage.add')}
	</button>
</section>

<section class="card">
	<h2>{$t('settings.triage.rules.title')}</h2>
	<p class="small muted">{$t('settings.triage.rules.order')}</p>
	<p class="small muted">{$t('settings.triage.body.never')}</p>
	{#if triage.rules.length === 0}
		<p class="muted" data-testid="no-rules">{$t('settings.triage.rules.empty')}</p>
	{:else}
		<ol data-testid="rules">
			{#each triage.rules as rule, index (rule.id)}
				<li>
					<strong>{rule.id}</strong>
					<span class="small">{$t(`settings.triage.field.${rule.field}`)}: {rule.value}</span>
					<span class="small muted">→ {rule.destination}</span>
					<button type="button" onclick={() => raise(index)} disabled={saving || index === 0}>
						↑
					</button>
					<button type="button" onclick={() => removeRule(rule.id)} disabled={saving}>
						{$t('settings.triage.remove')}
					</button>
				</li>
			{/each}
		</ol>
	{/if}

	<label class="field">
		<span class="label">{$t('settings.triage.rules.title')}</span>
		<input bind:value={draft.id} placeholder="newsletters" disabled={saving} data-testid="rule-id" />
	</label>
	<label class="field">
		<select bind:value={draft.field} disabled={saving} data-testid="rule-field">
			{#each FIELDS as field (field)}
				<option value={field}>{$t(`settings.triage.field.${field}`)}</option>
			{/each}
		</select>
	</label>
	<label class="field">
		<input bind:value={draft.value} disabled={saving} data-testid="rule-value" />
	</label>
	<label class="field">
		<select bind:value={draft.destination} disabled={saving} data-testid="rule-destination">
			{#each triage.destinations as destination (destination)}
				<option value={destination}>{destination}</option>
			{/each}
		</select>
	</label>
	<button type="button" onclick={addRule} disabled={saving || !draftIsRule} data-testid="add-rule">
		{$t('settings.triage.add')}
	</button>
</section>

<section class="card">
	<h2>{$t('settings.triage.moves.title')}</h2>
	{#if loaded && moves.length === 0}
		<p class="muted" data-testid="no-moves">{$t('settings.triage.moves.empty')}</p>
	{:else}
		<ul data-testid="moves">
			{#each moves as move (move.sequence)}
				<li>
					<span class="small">{move.from_mailbox_name} → {move.to_mailbox_name}</span>
					<span class="small muted">{move.rule_id}</span>
					{#if move.undoes}
						<span class="small muted">{$t('settings.triage.moves.isUndo')}</span>
					{:else if move.undo_requested_at}
						<span class="small muted">{$t('settings.triage.moves.undoRequested')}</span>
					{:else if isUndoable(move)}
						<button type="button" onclick={() => putBack(move.sequence)}>
							{$t('settings.triage.moves.undo')}
						</button>
					{/if}
				</li>
			{/each}
		</ul>
	{/if}
</section>
