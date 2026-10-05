/**
 * What answered at the address a deployment told this browser to call (#450).
 *
 * **Why this exists.** Twice, a deployment was published in a shape where the
 * browser could not reach a homeserver, and both times the only thing that said
 * so was the owner reading an error that named the wrong culprit:
 *
 * - **#323** — the Companion derived the homeserver's address from the server
 *   name, and a browser resolved `twalk.localhost` to its own machine.
 * - **#448** — the address was right, but an SSO stood in front of the Matrix
 *   API, and no Matrix client sends cookies. `POST /login` answered 302, `fetch`
 *   followed it, and the browser read a 200 of HTML.
 *
 * In both cases the recovery screen said `the login response was not a session`
 * — true, useless, and read by its own author as a homeserver bug for an hour.
 * `RestoreProblem`'s doc already states the principle this breaks: *a failure
 * the homeserver never saw must not be reported as a refusal it made.* A 200 of
 * HTML is not a refusal the homeserver made. It is something else answering.
 *
 * So the browser classifies what answered, and the screen can say it. The
 * browser is the only place that can: a check from inside the deployment
 * measures a different vantage point, which is precisely the assumption #323
 * was.
 */

/** What was at the other end, as far as one response can tell. */
export type Answered =
	/** A Matrix homeserver: it answered in Matrix's own vocabulary. */
	| { kind: 'homeserver' }
	/**
	 * Something that authenticates people — an SSO, a basic-auth gate, a portal.
	 * `at` is the origin that finally answered, which is the useful half: it is
	 * the thing the operator has to exempt `/_matrix/` from.
	 */
	| { kind: 'gate'; at: string }
	/** Reached, answering, and not a homeserver. Reported as measured. */
	| { kind: 'something-else'; status: number; contentType: string };

/** The part of a `Response` this needs. Narrow, so a test can state a case. */
export interface Answer {
	status: number;
	/** Whether `fetch` followed a redirect to get here. */
	redirected: boolean;
	/** The URL that finally answered. */
	url: string;
	headers: { get(name: string): string | null };
}

/**
 * Decides what answered, from one response and its parsed body.
 *
 * The order of the rules is the whole content:
 *
 * 1. **Matrix's vocabulary settles it, redirect or not.** A body carrying
 *    `errcode` or `access_token` came from a homeserver, and a deployment may
 *    legitimately redirect — `http` to `https`, a trailing slash — on the way
 *    to it. Asking this first is what keeps a working deployment from being
 *    called broken.
 * 2. **A redirect that did not end at a homeserver is a gate.** Matrix never
 *    redirects `/login`; something took the request somewhere else.
 * 3. **HTML is a gate**, redirect or no redirect: a sign-in page answered.
 * 4. Anything else is reported as what it was, because guessing further would
 *    be inventing.
 */
export function whatAnswered(answer: Answer, body: unknown): Answered {
	if (speaksMatrix(body)) {
		return { kind: 'homeserver' };
	}
	const contentType = answer.headers.get('content-type') ?? '';
	if (answer.redirected) {
		return { kind: 'gate', at: originOf(answer.url) };
	}
	if (contentType.includes('text/html')) {
		return { kind: 'gate', at: originOf(answer.url) };
	}
	return {
		kind: 'something-else',
		status: answer.status,
		contentType: contentType === '' ? 'no content type' : contentType
	};
}

/**
 * Whether the body is in Matrix's vocabulary. `errcode` for a refusal,
 * `access_token` for a session: the two shapes `/login` can answer with.
 *
 * Deliberately not "is it JSON": a gate can answer JSON (oauth2-proxy's
 * `/api` routes do), and a homeserver's own errors are the thing to recognise.
 */
function speaksMatrix(body: unknown): boolean {
	if (typeof body !== 'object' || body === null) {
		return false;
	}
	const fields = body as { errcode?: unknown; access_token?: unknown };
	return typeof fields.errcode === 'string' || typeof fields.access_token === 'string';
}

/** The origin of a URL, or the URL itself when it will not parse. */
function originOf(url: string): string {
	try {
		return new URL(url).origin;
	} catch {
		return url;
	}
}

/**
 * The sentence `RestoreError`'s `detail` carries, for a screen that only has
 * `detail` to show. Kept beside the classification so the two cannot drift.
 */
export function describe(answered: Answered): string {
	switch (answered.kind) {
		case 'homeserver':
			return 'a homeserver answered';
		case 'gate':
			return `${answered.at} answered with a sign-in page, not a homeserver`;
		case 'something-else':
			return `the address answered ${answered.status} ${answered.contentType}, which is not a homeserver`;
	}
}
