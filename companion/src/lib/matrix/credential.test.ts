// The handover of the credential, asserted the way #228 states its criteria
// (ADR 0034).
//
// The homeserver and the crypto machine are both recorded fakes, so every request
// the module makes and everything it hands the machine is visible here. That is
// what lets a test say what this module's promise needs: the credential is in the
// encrypted payload and in **no** request body, success is the Sensor's word and
// never the send's, and a deployment this browser cannot encrypt to is told so
// before a device is created for nothing.

import { describe, expect, it } from 'vitest';

import {
	ACTING_DEVICE_NAME,
	HANDOVER_EVENT_TYPE,
	handOverTheDevice,
	type CredentialCrypto
} from './credential';
import { HANDOVER_HELD_TYPE, HANDOVER_OFFER_TYPE } from './handover';

const OWNER = '@you:example.com';
const SENSOR = '@sensor:example.com';
const ROOM = '!handover:example.com';
const BASE = 'https://home.example.com';
const BROWSER_DEVICE = 'BROWSERDEV';
const CREATED_DEVICE = 'TWALKDEVICE';
const CREATED_TOKEN = 'syt_the-device-twalk-acts-through';
const PASSWORD = 'the one they just typed';

/** One request the module made, as the assertions need to read it. */
interface Made {
	method: string;
	path: string;
	body: Record<string, unknown> | null;
	authorization: string | null;
}

/**
 * A homeserver that mints a device on a password login and answers the
 * acknowledgement the Sensor is supposed to have written.
 *
 * `acknowledges` is what the Sensor said: the device it holds, or `null` for a
 * Sensor that said nothing at all.
 */
function homeserver(
	options: { acknowledges?: string | null; loginRefusal?: Record<string, unknown> } = {}
) {
	const acknowledges = options.acknowledges === undefined ? CREATED_DEVICE : options.acknowledges;
	const made: Made[] = [];

	const fetchImpl = (async (url: string | URL, init?: RequestInit) => {
		const path = String(url).replace(BASE, '');
		const method = init?.method ?? 'GET';
		const body =
			typeof init?.body === 'string' ? (JSON.parse(init.body) as Record<string, unknown>) : null;
		const headers = (init?.headers ?? {}) as Record<string, string>;
		made.push({ method, path, body, authorization: headers['authorization'] ?? null });

		const answer = (status: number, document: unknown): Response =>
			({ status, json: async () => document }) as unknown as Response;

		if (path === '/_matrix/client/v3/login') {
			if (options.loginRefusal !== undefined) {
				return answer(403, options.loginRefusal);
			}
			return answer(200, {
				user_id: OWNER,
				device_id: CREATED_DEVICE,
				access_token: CREATED_TOKEN
			});
		}
		if (path.includes(`/state/${HANDOVER_OFFER_TYPE}/`)) {
			return answer(200, { event_id: '$offer' });
		}
		if (path.includes(`/state/${HANDOVER_HELD_TYPE}/`)) {
			return acknowledges === null
				? answer(404, { errcode: 'M_NOT_FOUND', error: 'Event not found.' })
				: answer(200, { user_id: OWNER, device_id: acknowledges, offered_by: BROWSER_DEVICE });
		}
		throw new Error(`the module made a request nothing expected: ${method} ${path}`);
	}) as unknown as typeof fetch;

	return { fetchImpl, made };
}

/** A crypto machine that knows `devices` of the Sensor's, and records the send. */
function machine(options: { devices?: string[]; encryptsTo?: number } = {}) {
	const devices = options.devices ?? ['SENSORDEV'];
	const sent: { userId: string; deviceIds: string[]; eventType: string; content: unknown }[] = [];
	const crypto: CredentialCrypto = {
		deviceId: () => BROWSER_DEVICE,
		sensorDevices: async () => devices,
		sendEncrypted: async (userId, deviceIds, eventType, content) => {
			sent.push({ userId, deviceIds, eventType, content });
			return options.encryptsTo ?? deviceIds.length;
		}
	};
	return { crypto, sent };
}

function hand(
	server: ReturnType<typeof homeserver>,
	machinery: ReturnType<typeof machine>,
	overrides: Partial<Parameters<typeof handOverTheDevice>[0]> = {}
) {
	return handOverTheDevice({
		baseUrl: BASE,
		userId: OWNER,
		password: PASSWORD,
		accessToken: 'syt_the-browsers-own-session',
		sensorUserId: SENSOR,
		roomId: ROOM,
		crypto: machinery.crypto,
		fetchImpl: server.fetchImpl,
		ackDeadlineMs: 0,
		pollIntervalMs: 0,
		...overrides
	});
}

describe('handing the device over', () => {
	it('creates a device named twalk, offers it, and is held when the Sensor says so', async () => {
		const server = homeserver();
		const machinery = machine();

		const outcome = await hand(server, machinery);

		expect(outcome).toEqual({ kind: 'held', deviceId: CREATED_DEVICE });

		// The device is one the user will recognise in their own device list, which
		// is what makes ADR 0025's mitigation — revoke it from any client — usable.
		const login = server.made.find((request) => request.path === '/_matrix/client/v3/login');
		expect(login?.body).toMatchObject({
			type: 'm.login.password',
			identifier: { type: 'm.id.user', user: 'you' },
			initial_device_display_name: ACTING_DEVICE_NAME
		});

		// The offer goes up **before** the login that mints the device, so the
		// Sensor can never receive a credential it has no offer for.
		const order = server.made.map((request) => request.path);
		const offer = order.findIndex((path) => path.includes(HANDOVER_OFFER_TYPE));
		expect(offer).toBeGreaterThanOrEqual(0);
		expect(offer).toBeLessThan(order.indexOf('/_matrix/client/v3/login'));
		expect(
			server.made.find((request) => request.path.includes(HANDOVER_OFFER_TYPE))?.body
		).toEqual({ device_id: BROWSER_DEVICE });

		// The credential reached the Sensor's devices, Olm-encrypted, as the
		// handover event and nothing else.
		expect(machinery.sent).toEqual([
			{
				userId: SENSOR,
				deviceIds: ['SENSORDEV'],
				eventType: HANDOVER_EVENT_TYPE,
				content: {
					user_id: OWNER,
					device_id: CREATED_DEVICE,
					access_token: CREATED_TOKEN
				}
			}
		]);
	});

	it('puts the credential in no request body, and in no authorization header', async () => {
		const server = homeserver();
		const outcome = await hand(server, machine());

		expect(outcome.kind).toBe('held');
		// The whole point of ADR 0034: the token this browser minted travels
		// Olm-encrypted to one device and is written nowhere else. Asserted over
		// every request the module made, the way the Gateway's own suite asserts it
		// for the registration secret.
		for (const request of server.made) {
			expect(JSON.stringify(request.body ?? {})).not.toContain(CREATED_TOKEN);
			expect(request.authorization ?? '').not.toContain(CREATED_TOKEN);
			// And the password, which bought the device, is in the login and
			// nowhere else.
			if (request.path !== '/_matrix/client/v3/login') {
				expect(JSON.stringify(request.body ?? {})).not.toContain(PASSWORD);
			}
		}
	});

	it('is not held when the Sensor said nothing', async () => {
		const outcome = await hand(homeserver({ acknowledges: null }), machine());

		// A device exists on the account and Twalk cannot act through it. Reported
		// as a failure naming the device, because the name is what they revoke.
		expect(outcome).toEqual({ kind: 'not-acknowledged', deviceId: CREATED_DEVICE });
	});

	it("is not held by an earlier onboarding's acknowledgement", async () => {
		const outcome = await hand(homeserver({ acknowledges: 'ADEVICEFROMLASTWEEK' }), machine());

		// The room keeps one acknowledgement, and re-onboarding must not read the
		// previous one as an answer about this handover.
		expect(outcome).toEqual({ kind: 'not-acknowledged', deviceId: CREATED_DEVICE });
	});

	it('creates no device at all when this browser cannot encrypt to the Sensor', async () => {
		const server = homeserver();
		const machinery = machine({ devices: [] });

		const outcome = await hand(server, machinery);

		expect(outcome).toEqual({ kind: 'sensor-untracked' });
		// Nothing was minted and nothing was written: a browser whose machine
		// tracks no device of the Sensor's would send an empty batch and resolve
		// successfully, and the cost of finding that out later is a `twalk` device
		// in the user's list that never worked.
		expect(server.made).toEqual([]);
		expect(machinery.sent).toEqual([]);
	});

	it('says how many devices the batch missed rather than waiting for an answer', async () => {
		const outcome = await hand(homeserver(), machine({ devices: ['ONE', 'TWO'], encryptsTo: 1 }));

		expect(outcome).toEqual({ kind: 'not-encrypted-to', missing: 1, deviceId: CREATED_DEVICE });
	});

	it("answers with the homeserver's own words when the login is refused", async () => {
		const server = homeserver({
			loginRefusal: { errcode: 'M_FORBIDDEN', error: 'Invalid password' }
		});

		const outcome = await hand(server, machine());

		expect(outcome).toEqual({
			kind: 'failed',
			detail: '403 M_FORBIDDEN Invalid password'
		});
		// And nothing was asked of the room afterwards: there is no acknowledgement
		// to wait for when there is no device.
		expect(server.made.filter((request) => request.path.includes(HANDOVER_HELD_TYPE))).toEqual(
			[]
		);
	});
});
