// The **handover itself**: the device Twalk acts through is created in this
// browser and its credential reaches the Sensor Olm-encrypted, over the room
// `$lib/matrix/handover.ts` built for it (ADR 0034, ticket #228).
//
// # What is created, and why here
//
// ADR 0025 needs a device of the *user's own* account: a mautrix bridge relays
// to its network only what the logged-in user's own Matrix account sends, so a
// reply posted by `@sensor:` reaches the contact's phone not at all. ADR 0034
// decided that device is created **in the browser**, as an ordinary password
// login named [`ACTING_DEVICE_NAME`], and that its access token goes from here to
// the Sensor's own device without the Companion Gateway ever holding it — ADR
// 0011 says the Gateway stores no Matrix access token, and this route means it
// never receives one either. What transits the Gateway today is a token the
// browser already had and the Gateway drops within one call; a long-lived
// credential of the user's account relayed through it would sit in request
// bodies and logs for the life of the deployment.
//
// The device appears in the user's own device list under a name they will
// recognise, and revoking it from any Matrix client stops Twalk replying as them
// without touching anything else. That is ADR 0025's whole mitigation for a
// long-lived token at rest, and it is the sentence the screen makes before this
// runs.
//
// # The three things this module refuses to assume
//
// **That a send means an arrival.** `encryptToDeviceMessages` skips a device the
// Olm machine does not know with a `logger.warn`, and matrix-js-sdk's own comment
// concedes that its batch mechanism "removes all possibility to get error
// feedbacks". So the batch's own length is checked against the devices asked for
// — an empty or short batch is a failure here and not a mystery later — and, more
// importantly, success is **only** the Sensor's acknowledgement: a state event it
// writes in the handover room naming the device it now holds. Without that, every
// variant of the same mistake (no room, a room nobody synced, a device that never
// uploaded keys) would look identical to success, and a deployment would report a
// device it does not have.
//
// **That the Sensor knows which device to trust.** It refuses a credential from a
// device the deployment does not expect, and nothing could have configured that
// beforehand: the device below is minted by a login performed seconds ago. So the
// **offer** is written first — a state event in the handover room, which only the
// owner's account can write there — and the Sensor reads the expected device from
// it. It goes up before the credential, in its own request, so that the order is
// the homeserver's and not a hope about timing.
//
// **That the credential may travel in the clear.** The offer and the
// acknowledgement do: a device id is not a secret, and a state event both ends can
// read with one request beats a second encrypted channel whose failure would be
// indistinguishable from the first's. The credential never does.

import { HANDOVER_HELD_TYPE, HANDOVER_OFFER_TYPE, localpartOf } from './handover';

/** The device name the user will see in their own device list. */
export const ACTING_DEVICE_NAME = 'twalk';

/** The to-device event the credential travels in. Olm-encrypted, always. */
export const HANDOVER_EVENT_TYPE = 'fr.linagora.twalk.owner_device.handover';

/** What the crypto machine has to do for the handover, and nothing more. */
export interface CredentialCrypto {
	/** This browser's own device id: what the offer names. */
	deviceId(): string | null;
	/**
	 * The Sensor's devices **as the machine's own store holds them** — never a
	 * plain `/keys/query` the machine never saw, which is the answer that would
	 * make a send that goes out empty look ready.
	 */
	sensorDevices(userId: string): Promise<string[]>;
	/**
	 * Olm-encrypts `content` for those devices and sends it. Answers how many
	 * devices the encrypted batch actually held, because a batch shorter than the
	 * list is the silent no-op this whole design exists to make visible.
	 */
	sendEncrypted(
		userId: string,
		deviceIds: string[],
		eventType: string,
		content: Record<string, unknown>
	): Promise<number>;
}

/** How the handover of the credential ended. Every outcome is a fact. */
export type CredentialOutcome =
	/**
	 * The Sensor says it holds the credential. The only outcome that means
	 * onboarding did what it set out to do.
	 */
	| { kind: 'held'; deviceId: string }
	/**
	 * The device exists on the user's account and the Sensor never said it holds
	 * it. Reported as a failure, never as a success: the device is in their device
	 * list and Twalk cannot act through it, so the name is what they need to
	 * revoke it.
	 */
	| { kind: 'not-acknowledged'; deviceId: string }
	/**
	 * This browser's crypto machine knows no device of the Sensor's, so there is
	 * nothing to encrypt to. `ensureHandoverRoom` is what normally establishes
	 * this, and this is what its absence looks like at the moment of the send.
	 */
	| { kind: 'sensor-untracked' }
	/**
	 * The batch left this browser with fewer devices in it than were asked for:
	 * the machine skipped one it does not know. No credential was created, or the
	 * one created was never sent.
	 */
	| { kind: 'not-encrypted-to'; missing: number; deviceId?: string }
	/** Something the homeserver or the browser refused. `detail` is its words. */
	| { kind: 'failed'; detail: string };

export interface CredentialOptions {
	/** The homeserver's base URL, as `$lib/matrix/discovery.ts` resolved it. */
	baseUrl: string;
	/** The owner's own Matrix ID. */
	userId: string;
	/**
	 * The owner's password, which this browser holds because they have just typed
	 * it. Used for one login and never stored: a new device is what a password
	 * buys, and there is no other way to mint one without asking them again.
	 */
	password: string;
	/** The owner's current access token: what writes the offer in the room. */
	accessToken: string;
	/** `GATEWAY_SENSOR_USER_ID`, as `GET /api/session` states it. */
	sensorUserId: string;
	/** The handover room, as `ensureHandoverRoom` answered with it. */
	roomId: string;
	crypto: CredentialCrypto;
	fetchImpl?: typeof fetch;
	/** How long to wait for the Sensor's acknowledgement. */
	ackDeadlineMs?: number;
	/** Between polls. A parameter so a test does not wait in real time. */
	pollIntervalMs?: number;
}

/**
 * Creates the device, hands its credential to the Sensor, and answers what the
 * Sensor said about it.
 *
 * Never throws: every way this can end is a [`CredentialOutcome`] the screen can
 * state, because onboarding must not lose an account over it — and must never
 * report a device the deployment does not have.
 */
export async function handOverTheDevice(
	options: CredentialOptions
): Promise<CredentialOutcome> {
	const {
		baseUrl,
		userId,
		password,
		accessToken,
		sensorUserId,
		roomId,
		crypto,
		ackDeadlineMs = 60_000,
		pollIntervalMs = 1_000
	} = options;
	const doFetch = options.fetchImpl ?? globalThis.fetch.bind(globalThis);

	const offeringDevice = crypto.deviceId();
	if (offeringDevice === null || offeringDevice === '') {
		return { kind: 'failed', detail: 'this browser has no device of its own yet' };
	}
	const localpart = localpartOf(userId);
	if (localpart === null) {
		return { kind: 'failed', detail: `${userId} is not a Matrix user ID` };
	}

	let deviceId: string | undefined;
	try {
		// Asked before the device is created, so a deployment whose Sensor this
		// browser cannot encrypt to does not leave a device behind for nothing.
		const sensorDevices = await crypto.sensorDevices(sensorUserId);
		if (sensorDevices.length === 0) {
			return { kind: 'sensor-untracked' };
		}

		// The offer, before the credential: what the Sensor reads to know which
		// device may hand one over.
		const offered = await call(doFetch, baseUrl, accessToken, {
			method: 'PUT',
			path: `/_matrix/client/v3/rooms/${encodeURIComponent(roomId)}/state/${HANDOVER_OFFER_TYPE}/`,
			body: { device_id: offeringDevice }
		});
		if (offered.status !== 200) {
			return { kind: 'failed', detail: errorOf(offered) };
		}

		// The device. A password login is what mints one, which is why the password
		// is still in memory at this point in onboarding and nowhere else.
		const login = await call(doFetch, baseUrl, null, {
			method: 'POST',
			path: '/_matrix/client/v3/login',
			body: {
				type: 'm.login.password',
				identifier: { type: 'm.id.user', user: localpart },
				password,
				initial_device_display_name: ACTING_DEVICE_NAME
			}
		});
		const credential = {
			user_id: asString(login.document['user_id']),
			device_id: asString(login.document['device_id']),
			access_token: asString(login.document['access_token'])
		};
		if (
			login.status !== 200 ||
			credential.user_id === null ||
			credential.device_id === null ||
			credential.access_token === null
		) {
			return { kind: 'failed', detail: errorOf(login) };
		}
		deviceId = credential.device_id;

		const encryptedTo = await crypto.sendEncrypted(
			sensorUserId,
			sensorDevices,
			HANDOVER_EVENT_TYPE,
			credential
		);
		if (encryptedTo < sensorDevices.length) {
			return {
				kind: 'not-encrypted-to',
				missing: sensorDevices.length - encryptedTo,
				deviceId
			};
		}
	} catch (cause) {
		return {
			kind: 'failed',
			detail: cause instanceof Error ? cause.message : String(cause)
		};
	}

	// And the only answer that counts. The read is of the room's state and not of
	// anything this browser remembers: the Sensor wrote it or it did not.
	const acknowledged = await waitFor(
		async () => {
			const held = await call(doFetch, baseUrl, accessToken, {
				method: 'GET',
				path: `/_matrix/client/v3/rooms/${encodeURIComponent(roomId)}/state/${HANDOVER_HELD_TYPE}/`
			});
			return held.status === 200 && asString(held.document['device_id']) === deviceId;
		},
		ackDeadlineMs,
		pollIntervalMs
	);
	return acknowledged
		? { kind: 'held', deviceId: deviceId as string }
		: { kind: 'not-acknowledged', deviceId: deviceId as string };
}

interface Answer {
	status: number;
	document: Record<string, unknown>;
}

/**
 * One request to the homeserver. `token` is `null` for the login, which is the
 * one call here that authenticates with the password instead.
 */
async function call(
	doFetch: typeof fetch,
	baseUrl: string,
	token: string | null,
	request: { method: string; path: string; body?: unknown }
): Promise<Answer> {
	const response = await doFetch(`${baseUrl}${request.path}`, {
		method: request.method,
		headers: {
			...(token === null ? {} : { authorization: `Bearer ${token}` }),
			...(request.body === undefined ? {} : { 'content-type': 'application/json' })
		},
		...(request.body === undefined ? {} : { body: JSON.stringify(request.body) })
	});
	let document: Record<string, unknown> = {};
	try {
		const parsed: unknown = await response.json();
		if (parsed !== null && typeof parsed === 'object') {
			document = parsed as Record<string, unknown>;
		}
	} catch {
		// A body that is not JSON leaves `document` empty; the status decides.
	}
	return { status: response.status, document };
}

function asString(value: unknown): string | null {
	return typeof value === 'string' && value !== '' ? value : null;
}

/** The homeserver's own words about a refusal, for a screen to show. */
function errorOf(answer: Answer): string {
	const errcode = asString(answer.document['errcode']) ?? '';
	const error = asString(answer.document['error']) ?? '';
	return [String(answer.status), errcode, error].filter((part) => part !== '').join(' ');
}

/**
 * Polls `condition` until it holds or the deadline passes. Answers whether it
 * held — a deadline is an answer about the system, never an exception.
 */
async function waitFor(
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
