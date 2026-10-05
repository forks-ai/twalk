import { describe as group, expect, it } from 'vitest';

import { describe, whatAnswered, type Answer } from './answered';

/** A response, as `whatAnswered` needs one. */
function answer(partial: Partial<Answer> & { contentType?: string }): Answer {
	const contentType = partial.contentType ?? 'application/json';
	return {
		status: partial.status ?? 200,
		redirected: partial.redirected ?? false,
		url: partial.url ?? 'https://twalk.example/_matrix/client/v3/login',
		headers: { get: (name) => (name.toLowerCase() === 'content-type' ? contentType : null) }
	};
}

group('what answered at the homeserver address', () => {
	it('is the homeserver when the body speaks Matrix', () => {
		expect(whatAnswered(answer({ status: 200 }), { access_token: 'syt_…' })).toEqual({
			kind: 'homeserver'
		});
		expect(
			whatAnswered(answer({ status: 403 }), {
				errcode: 'M_FORBIDDEN',
				error: 'Invalid username or password'
			})
		).toEqual({ kind: 'homeserver' });
	});

	it('is still the homeserver when a redirect led to it', () => {
		// A deployment may legitimately redirect on the way: http to https, a
		// trailing slash. Asking about Matrix's vocabulary first is what keeps a
		// working deployment from being called broken.
		expect(
			whatAnswered(
				answer({
					status: 403,
					redirected: true,
					url: 'https://twalk.example/_matrix/client/v3/login'
				}),
				{ errcode: 'M_FORBIDDEN' }
			)
		).toEqual({ kind: 'homeserver' });
	});

	it('is a gate when the request was taken somewhere else', () => {
		// #448, as the owner met it: the SSO's 302, followed by `fetch`, ending
		// at a sign-in page. Matrix never redirects /login.
		const answered = whatAnswered(
			answer({
				status: 200,
				redirected: true,
				contentType: 'text/html; charset=utf-8',
				url: 'https://auth.twake-dev.example/oauth2/authorize?client_id=twalk-companion'
			}),
			{}
		);
		expect(answered).toEqual({ kind: 'gate', at: 'https://auth.twake-dev.example' });
		expect(describe(answered)).toContain('sign-in page');
		expect(describe(answered)).toContain('https://auth.twake-dev.example');
	});

	it('is a gate when HTML answers without any redirect', () => {
		// The same misconfiguration behind a proxy that rewrites rather than
		// redirects: no hop to notice, a page where a session should be.
		expect(
			whatAnswered(answer({ status: 200, contentType: 'text/html' }), {})
		).toEqual({ kind: 'gate', at: 'https://twalk.example' });
	});

	it('names what it found when it is neither', () => {
		// Reported as measured rather than guessed at: a 502 of plain text is
		// not a sign-in page and not a homeserver, and saying either would be
		// inventing.
		expect(
			whatAnswered(answer({ status: 502, contentType: 'text/plain' }), 'upstream gone')
		).toEqual({ kind: 'something-else', status: 502, contentType: 'text/plain' });
		expect(
			whatAnswered(answer({ status: 418, contentType: '' }), {})
		).toEqual({ kind: 'something-else', status: 418, contentType: 'no content type' });
	});

	it('does not take any JSON for Matrix', () => {
		// A gate can answer JSON — oauth2-proxy does on its API routes — so the
		// test is Matrix's own vocabulary, not the content type.
		expect(whatAnswered(answer({ status: 401 }), { error: 'unauthorized' })).toEqual({
			kind: 'something-else',
			status: 401,
			contentType: 'application/json'
		});
	});

	it('survives a URL it cannot parse', () => {
		const answered = whatAnswered(
			answer({ status: 200, redirected: true, contentType: 'text/html', url: 'not a url' }),
			{}
		);
		expect(answered).toEqual({ kind: 'gate', at: 'not a url' });
	});
});
