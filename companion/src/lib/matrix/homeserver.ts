// The three things every module that speaks to the owner's homeserver over plain
// HTTP needs, in one place: one request, one refusal's words, one deadline.
//
// `$lib/matrix/handover.ts` and `$lib/matrix/credential.ts` each had a copy, down
// to the comments, which is one fact in two homes and the shape of drift: the
// second copy of `call` is the one that would forget to leave `content-type` off a
// GET, and the second copy of `waitFor` is the one that would start throwing on a
// deadline. Neither is a matrix-js-sdk call — both modules deliberately speak the
// client-server API directly, because what they do (create a room, mint a device,
// read one state event) needs no crypto stack and no sync loop.

/** What the homeserver answered: its status, and its body when that is JSON. */
export interface Answer {
	status: number;
	document: Record<string, unknown>;
}

/** One request, as [`call`] makes it. */
export type Call = (method: string, path: string, body?: unknown) => Promise<Answer>;

/**
 * Makes requests to one homeserver as one account.
 *
 * `token` is `null` for the calls that authenticate otherwise — a password login
 * is the one here that does.
 */
export function homeserverCalls(
	doFetch: typeof fetch,
	baseUrl: string,
	token: string | null
): Call {
	return async (method: string, path: string, body?: unknown): Promise<Answer> => {
		const response = await doFetch(`${baseUrl}${path}`, {
			method,
			headers: {
				...(token === null ? {} : { authorization: `Bearer ${token}` }),
				...(body === undefined ? {} : { 'content-type': 'application/json' })
			},
			...(body === undefined ? {} : { body: JSON.stringify(body) })
		});
		let document: Record<string, unknown> = {};
		try {
			const parsed: unknown = await response.json();
			if (parsed !== null && typeof parsed === 'object') {
				document = parsed as Record<string, unknown>;
			}
		} catch {
			// A body that is not JSON leaves `document` empty; the status is what the
			// callers decide on.
		}
		return { status: response.status, document };
	};
}

/**
 * The homeserver's own words about a refusal, for a screen to show: the status,
 * the `errcode` and the `error`, whichever of them there are.
 */
export function refusalOf(answer: Answer): string {
	const errcode = typeof answer.document['errcode'] === 'string' ? answer.document['errcode'] : '';
	const error = typeof answer.document['error'] === 'string' ? answer.document['error'] : '';
	return [String(answer.status), errcode, error].filter((part) => part !== '').join(' ');
}

/**
 * Polls `condition` until it holds or the deadline passes. Answers whether it
 * held — a deadline is an answer about the system, never an exception.
 */
export async function waitFor(
	condition: () => Promise<boolean>,
	deadlineMs: number,
	intervalMs: number
): Promise<boolean> {
	const deadline = Date.now() + deadlineMs;
	for (;;) {
		if (await condition()) {
			return true;
		}
		if (Date.now() >= deadline) {
			return false;
		}
		await new Promise((resolve) => setTimeout(resolve, intervalMs));
	}
}
