import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

/**
 * The recovery screen offers a way past itself — approvals, settings and mail
 * triage work without the crypto store, and saying so is the whole of #433's
 * second half. That offer is only true while the landing page is the one
 * screen that asks whether the store exists.
 *
 * It was not obvious. Before this test, the owner of the reference deployment
 * met the recovery screen, had no key, and concluded Twalk was unusable until
 * they reset their identity and lost their history. Both halves were wrong:
 * the history was never this client's to lose, and five of six screens were
 * working the whole time.
 *
 * So if a screen starts needing the keys, it has to be a decision somebody
 * takes on purpose — and then `recover.carryOn` has to stop promising what it
 * no longer delivers.
 */
describe('the crypto store', () => {
	const routes = join(import.meta.dirname ?? 'src/routes');

	/** Every `+page.svelte` under `src/routes`, by its route path. */
	function screens(
		dir: string,
		route = '/',
	): { route: string; source: string }[] {
		const found: { route: string; source: string }[] = [];
		for (const entry of readdirSync(dir, { withFileTypes: true })) {
			const path = join(dir, entry.name);
			if (entry.isDirectory()) {
				found.push(
					...screens(
						path,
						route === '/' ? `/${entry.name}` : `${route}/${entry.name}`,
					),
				);
			} else if (entry.name === '+page.svelte') {
				found.push({ route, source: readFileSync(path, 'utf8') });
			}
		}
		return found;
	}

	it('is read by the landing page and by no other screen', () => {
		const asking = screens(routes)
			.filter(
				({ source }) =>
					source.includes('crypto/store') || source.includes('hasCryptoStore'),
			)
			.map(({ route }) => route)
			.sort();

		expect(asking).toEqual(['/']);
	});
});
