// What the screen says when something other than a homeserver answers at the
// address the deployment gave this browser (#450).
//
// This needs no stack and no homeserver: the point is a deployment where the
// homeserver is *not* what answers, and `page.route` can be that more honestly
// than any stack could. The shape staged here is the one the owner met on
// 2026-10-04 — an SSO in front of the Matrix API, which no Matrix client can
// pass because none sends cookies (#448) — and what it used to produce was
// `failed: the login response was not a session`: true, and no help to anyone.

import { expect, test } from '@playwright/test';

/** A domain whose Matrix API is answered by a sign-in page, not a homeserver. */
const GATED = 'gate.example';

test.describe('the screen says what answered', () => {
	test('names a gate instead of blaming the login response', async ({ page }) => {
		// Everything about this origin is staged except the browser's own
		// reading of it: discovery succeeds, so the screen gets as far as the
		// password — which is exactly how this misconfiguration hides.
		// `/_matrix/client/versions` is usually the first route an operator
		// exempts from their SSO, so it answers while the login does not.
		await page.route(`https://${GATED}/**`, async (route) => {
			const path = new URL(route.request().url()).pathname;
			if (path === '/_matrix/client/versions') {
				await route.fulfill({ json: { versions: ['v1.11'] } });
				return;
			}
			if (path === '/_matrix/client/v3/login') {
				await route.fulfill({
					status: 200,
					contentType: 'text/html; charset=utf-8',
					body: '<!doctype html><title>Sign in</title><form>…</form>'
				});
				return;
			}
			await route.fulfill({ status: 404, json: { errcode: 'M_NOT_FOUND' } });
		});

		await page.goto('/recover');
		await expect(page.getByTestId('screen-recover')).toBeVisible();

		await page.getByLabel('Your Twalk domain').fill(GATED);
		await page.getByLabel('Username').fill('michel');
		await page.getByLabel('Password', { exact: true }).fill('a-password-that-never-arrives');

		// The reset path, because it needs no recovery key to reach the login —
		// and it is the path a user with no key is told to take.
		const noKey = page.getByTestId('recover-no-key-action');
		await expect(noKey).toBeEnabled();
		await noKey.click();

		const error = page.getByTestId('recover-error');
		await expect(error).toBeVisible({ timeout: 30_000 });

		// The cause is named, not described as a bad response body.
		await expect(error).toHaveAttribute('data-kind', 'not-a-homeserver');
		// It says which address answered, which is the half the operator needs.
		await expect(error).toContainText(GATED);
		// It says the password reached whatever is there — the one thing a user
		// would want to know and the screen used not to say.
		await expect(error).toContainText(/password was sent/i);
		// And the remedy, in the words the operator has to act on.
		await expect(error).toContainText('/_matrix/');
		// The sentence this replaces is gone.
		await expect(error).not.toContainText('was not a session');
	});

	test('still blames the password when the homeserver is the one refusing', async ({ page }) => {
		// The other half of the contract: classification must not turn a real
		// refusal into a misconfiguration. A homeserver answering in Matrix's
		// own vocabulary is a homeserver, whatever its status code.
		await page.route(`https://${GATED}/**`, async (route) => {
			const path = new URL(route.request().url()).pathname;
			if (path === '/_matrix/client/versions') {
				await route.fulfill({ json: { versions: ['v1.11'] } });
				return;
			}
			if (path === '/_matrix/client/v3/login') {
				await route.fulfill({
					status: 403,
					json: { errcode: 'M_FORBIDDEN', error: 'Invalid username or password' }
				});
				return;
			}
			await route.fulfill({ status: 404, json: { errcode: 'M_NOT_FOUND' } });
		});

		await page.goto('/recover');
		await page.getByLabel('Your Twalk domain').fill(GATED);
		await page.getByLabel('Username').fill('michel');
		await page.getByLabel('Password', { exact: true }).fill('the-wrong-one');
		await page.getByTestId('recover-no-key-action').click();

		const error = page.getByTestId('recover-error');
		await expect(error).toBeVisible({ timeout: 30_000 });
		await expect(error).toHaveAttribute('data-kind', 'wrong-password');
	});
});
