// The **handover room**: the one encrypted room the user's account and the
// Sensor share, created in the browser during onboarding (ticket #226).
//
// # Why it exists, which is a measurement and not a preference
//
// ADR 0034 hands the Sensor a device credential as an Olm-encrypted to-device
// message. That send is a **silent no-op** when the sender's crypto machine
// does not track the target user: `RustCrypto.encryptToDeviceMessages` asks
// the Olm machine for each device, skips the ones it does not know with a
// `logger.warn`, puts an empty batch on the wire and resolves successfully —
// matrix-js-sdk's own comment concedes that "the batch mechanism removes all
// possibility to get error feedbacks". A user becomes tracked only through
// membership of a shared **encrypted** room, and at onboarding the user's
// account shares none with the Sensor: it is *invited* to the bridges' portal
// rooms and has never accepted (measured on the reference deployment:
// `invite: 33, join: 0`).
//
// So onboarding creates a room for that purpose and for nothing else: the
// user's own session creates it, invites the Sensor, and waits for the Sensor
// to join. The Sensor needs no change — it joins any invitation from an
// account `SENSOR_ALLOWED_INVITERS` names, and that list names the owner
// (`sensor/src/main.rs`).
//
// # This room is not a conversation, and cannot become one
//
// That is the property that matters most here, because consent in Twalk is a
// membership fact (ADR 0024): the portal register answers "is this observed?"
// with the Sensor's own membership, which nobody can forge or forget. A room
// the Sensor is joined to that something counted as a conversation would be
// consent nobody granted — for a correspondent who does not exist, in a room
// with no traffic, but the count on screen would be wrong and the mechanism
// that made it wrong would be ours.
//
// Three properties keep it out, and each is enforced by something other than
// a line of Twalk code remembering to check:
//
//   1. **`m.room.create` carries a `type`** ([`HANDOVER_ROOM_TYPE`]). Matrix's
//      own way of saying a room is not an ordinary conversation — it is how
//      `m.space` keeps a space out of every client's room list — and
//      `m.room.create` is the one state event that can be neither replaced nor
//      redacted, so the marker is there for the room's whole life. It is what
//      `$lib/matrix/rooms.ts` reads to leave the room out of the conversation
//      chooser, with one rule that covers a space and this room alike.
//   2. **No `m.bridge`, and no bridge bot in it.** The portal register reads
//      each *bridge bot's* joined rooms and counts only those carrying an
//      `m.bridge` marker (`companion-gateway/src/portals.rs`). This room is
//      created by the user, holds two members, and no bridge ever hears of it,
//      so it is outside the register's reach twice over rather than filtered
//      out of it once.
//   3. **Nobody can post in it at all.** The power levels are created with
//      `events_default` at [`SEND_LEVEL_NOBODY_HAS`] — above the 100 a room's
//      creator gets, so the homeserver refuses `m.room.message` from *every*
//      member including the user (verified against Synapse: `user_level (100)
//      < send_level (101)`). That is what makes "nothing is ever published on
//      the bus from it" a fact about the deployment rather than a promise
//      about code we do not own: the Sensor publishes what it reads in the
//      rooms it is in, it would read this one as native Matrix traffic
//      (`sensor/src/network.rs` resolves a room with no `m.bridge` to
//      `matrix`), and the only reason it never publishes anything from here is
//      that no event it could publish can exist.
//
// The invitation level is raised with it, so the Sensor — at power level 0 —
// cannot pull a third account in. The room's membership is the user's to
// change and nobody else's.
//
// # Finding the one that exists, rather than remembering that it does
//
// Re-running onboarding must not create a second room, and the fact that one
// exists is not written down anywhere: it is asked of the homeserver, through
// a canonical alias ([`handoverAlias`], the owner's own localpart in it). One
// request answers it, the Companion never lists the user's rooms to find it,
// and the race is safe — Synapse refuses a second `createRoom` with the same
// alias (`M_ROOM_IN_USE`), which is read here as "it already exists" and
// resolved.
//
// # The sync loop, which this module needs and the rest of the app refuses
//
// Creating the room is not enough on its own, and this is the part that would
// have been found in production. The crypto machine learns which users to
// track from `RoomEncryptor`, and `RoomEncryptor` is built by
// `RustCrypto.onCryptoEvent`, which in the installed matrix-js-sdk is called
// from **one place: the sync loop** (`lib/sync.js`). The Companion runs no
// sync loop ($lib/crypto/bootstrap.ts says so, and means it), so a browser
// that created this room and stopped there would still not track the Sensor,
// and the later handover would still send an empty batch.
//
// So the handover **runs a sync, briefly, and stops it**: long enough for the
// machine to see the room, mark the Sensor tracked and query its keys. That is
// a real departure from the app's posture and it is deliberate, bounded to
// this one step, and stated here rather than discovered in `startClient`.
//
// And the answer is checked the only way that means anything: the Sensor's
// devices are asked of the **crypto machine's own store**
// (`getUserDeviceInfo([sensor], false)` — `downloadUncached` false on purpose).
// With `true` the SDK falls back to a plain HTTP `/keys/query` and hands the
// caller a device list the machine never saw, which is exactly the answer that
// would make a broken handover look ready.

import { homeserverCalls, refusalOf, waitFor, type Answer, type Call } from './homeserver';

/** The `m.room.create` type that says this room is not a conversation. */
export const HANDOVER_ROOM_TYPE = 'fr.linagora.twalk.handover';

/**
 * The state event in which the owner says **which device** will hand the
 * credential over (#228, ADR 0034).
 *
 * It lives here, in the room's own module, because what makes it worth anything
 * is a property of the room: `state_default` is 50 and the Sensor sits at 0, so
 * this is a sentence only the owner's account can write, authenticated by the
 * homeserver rather than by anything Twalk checks. The Sensor refuses a
 * credential from any device but the one named here, and nothing could have
 * configured that device beforehand — it is minted by a login performed seconds
 * earlier.
 */
export const HANDOVER_OFFER_TYPE = 'fr.linagora.twalk.owner_device.handover.from';

/**
 * The state event the **Sensor** writes once it holds the credential: the
 * acknowledgement ADR 0034 requires, and the only thing the Companion may read as
 * success.
 *
 * This is the room's one exception to "nobody can post in it at all". The Sensor
 * is granted level 0 for this single event type and nothing else, in the `events`
 * map of the power levels below, because a room in which the Sensor could say
 * nothing would be a room in which a handover could never be confirmed — and
 * ADR 0034's whole point is that a send resolving is not a confirmation.
 */
export const HANDOVER_HELD_TYPE = 'fr.linagora.twalk.owner_device.handover.held';

/**
 * The `events_default` the room is created with: one above the 100 a room's
 * creator holds, so no member — the user included — can post any message
 * event. See the module docs.
 */
export const SEND_LEVEL_NOBODY_HAS = 101;

/** The alias localpart's prefix; the owner's own localpart follows it. */
export const HANDOVER_ALIAS_PREFIX = 'twalk-handover';

/**
 * The alias localpart for one owner, e.g. `twalk-handover-you`.
 *
 * Per owner and not per homeserver, although a deployment has one owner:
 * the homeserver is not always a deployment's own. The test stack is shared
 * by every run and every worktree, so a per-homeserver alias was taken by the
 * first owner ever onboarded there and every later one resolved it to a room
 * they were not in — and reported "Twalk cannot reach its Sensor" over a
 * `403`, which is a true sentence about the wrong room (#267). An owner's
 * own localpart is what makes the alias theirs.
 */
export function handoverAliasLocalpart(ownerLocalpart: string): string {
	return `${HANDOVER_ALIAS_PREFIX}-${ownerLocalpart}`;
}

/** The full alias for an owner, e.g. `#twalk-handover-you:example.com`. */
export function handoverAlias(ownerUserId: string): string | null {
	const localpart = localpartOf(ownerUserId);
	const serverName = serverNameOf(ownerUserId);
	if (localpart === null || serverName === null) {
		return null;
	}
	return `#${handoverAliasLocalpart(localpart)}:${serverName}`;
}

/** The localpart of a Matrix ID, or `null` when it is not one. */
export function localpartOf(matrixId: string): string | null {
	const at = matrixId.startsWith('@') ? matrixId.slice(1) : null;
	if (at === null) {
		return null;
	}
	const colon = at.indexOf(':');
	if (colon <= 0 || colon === at.length - 1) {
		return null;
	}
	return at.slice(0, colon);
}

/** The server name a Matrix ID belongs to, or `null` when it is not one. */
export function serverNameOf(matrixId: string): string | null {
	const at = matrixId.startsWith('@') ? matrixId.slice(1) : null;
	if (at === null) {
		return null;
	}
	const colon = at.indexOf(':');
	if (colon < 0 || colon === 0 || colon === at.length - 1) {
		return null;
	}
	return at.slice(colon + 1);
}

/**
 * The exact `POST /createRoom` body. Pure, and exported so that a test pins
 * every one of the three properties above against a value rather than a
 * comment.
 */
export function handoverRoomCreation(options: {
	sensorUserId: string;
	/** The owner's own localpart, which the alias carries. */
	ownerLocalpart: string;
	/** What the user will see this room called in their own Matrix client. */
	name: string;
}): Record<string, unknown> {
	return {
		preset: 'private_chat',
		visibility: 'private',
		room_alias_name: handoverAliasLocalpart(options.ownerLocalpart),
		name: options.name,
		invite: [options.sensorUserId],
		// Not a direct message: `m.direct` would put it in the user's client
		// beside the people they talk to, which is the one place it does not
		// belong.
		is_direct: false,
		creation_content: { type: HANDOVER_ROOM_TYPE },
		initial_state: [
			{
				type: 'm.room.encryption',
				state_key: '',
				// Encrypted at creation rather than afterwards: it is the whole
				// reason the room exists, and a room that was briefly
				// unencrypted would be a room whose first membership events the
				// machine saw outside an encrypted room.
				content: { algorithm: 'm.megolm.v1.aes-sha2' }
			}
		],
		power_level_content_override: {
			events_default: SEND_LEVEL_NOBODY_HAS,
			// Only the creator can change who is in here: at 0, the Sensor can
			// neither invite a third account nor remove the user.
			invite: 100,
			kick: 100,
			redact: 100,
			// And the one thing the Sensor may write: the acknowledgement of a
			// handover, at level 0, by name. Everything else it could attempt —
			// any message, any other state event — is still refused by the
			// homeserver and not by us.
			events: { [HANDOVER_HELD_TYPE]: 0 }
		}
	};
}

/** What the crypto machine has to be able to answer, and nothing more. */
export interface HandoverCrypto {
	/**
	 * Runs a sync until `stopSync`, so the machine sees the room and starts
	 * tracking its members. See the module docs for why this exists at all.
	 */
	startSync(): Promise<void>;
	stopSync(): void;
	/**
	 * The Sensor's devices **as the crypto machine's own store holds them** —
	 * never a plain `/keys/query` the machine did not see.
	 */
	trackedDeviceCount(userId: string): Promise<number>;
}

/** How the handover ended. Every outcome is a thing that is true. */
export type HandoverOutcome =
	/**
	 * The room exists, the Sensor is joined, and this browser's crypto machine
	 * can enumerate the Sensor's devices — which is the property that makes
	 * ADR 0034's later send possible rather than silently empty.
	 */
	| { kind: 'ready'; roomId: string; sensorDevices: number; created: boolean }
	/** `GATEWAY_SENSOR_USER_ID` is unset: there is nobody to share a room with. */
	| { kind: 'no-sensor' }
	/**
	 * The room exists and the Sensor has not joined it. Its own outcome, for
	 * the same reason ADR 0024 gives `invited` its own state: it is what a
	 * deployment looks like when `SENSOR_ALLOWED_INVITERS` does not name the
	 * owner, or when no Sensor is running, and without it the symptom would be
	 * a handover that fails much later for no stated reason.
	 */
	| { kind: 'sensor-did-not-join'; roomId: string }
	/**
	 * The Sensor joined and the crypto machine still knows no device of its.
	 * Reported rather than passed over: this is precisely the state in which
	 * the credential send would resolve successfully having sent nothing.
	 */
	| { kind: 'sensor-untracked'; roomId: string }
	/** Something the homeserver or the browser refused. `detail` is its words. */
	| { kind: 'failed'; detail: string };

export interface HandoverOptions {
	/** The homeserver's base URL, as `$lib/matrix/discovery.ts` resolved it. */
	baseUrl: string;
	/** The user's own Matrix access token. Never leaves the browser. */
	accessToken: string;
	/** The user's own Matrix ID, which names the server the alias lives on. */
	userId: string;
	/** `GATEWAY_SENSOR_USER_ID`, as `GET /api/session` states it. */
	sensorUserId: string | null;
	/** What the room is called in the user's own client. */
	roomName: string;
	crypto: HandoverCrypto;
	fetchImpl?: typeof fetch;
	/** How long to wait for the Sensor to accept the invitation. */
	joinDeadlineMs?: number;
	/** How long to wait for the crypto machine to know a device of the Sensor's. */
	trackingDeadlineMs?: number;
	/** Between polls. A parameter so a test does not wait in real time. */
	pollIntervalMs?: number;
}

/**
 * Makes sure the handover room exists, holds both accounts, and has made the
 * Sensor a user this browser's crypto machine tracks.
 *
 * Never throws: every way this can end is a [`HandoverOutcome`] the screen can
 * state. Onboarding must not lose an account over it — but it must also never
 * report a handover it does not have, which is why `ready` is the only outcome
 * that says nothing is left to do.
 */
export async function ensureHandoverRoom(options: HandoverOptions): Promise<HandoverOutcome> {
	const {
		baseUrl,
		accessToken,
		userId,
		sensorUserId,
		roomName,
		crypto,
		joinDeadlineMs = 30_000,
		trackingDeadlineMs = 30_000,
		pollIntervalMs = 1_000
	} = options;
	const doFetch = options.fetchImpl ?? globalThis.fetch.bind(globalThis);

	if (sensorUserId === null || sensorUserId.trim() === '') {
		// Not a failure: a deployment with no Sensor has nothing to hand a
		// credential to, and saying so beats an error nobody can act on.
		return { kind: 'no-sensor' };
	}
	const alias = handoverAlias(userId);
	const ownerLocalpart = localpartOf(userId);
	if (alias === null || ownerLocalpart === null) {
		return { kind: 'failed', detail: `${userId} is not a Matrix user ID` };
	}

	const call = homeserverCalls(doFetch, baseUrl, accessToken);

	let roomId: string;
	let created: boolean;
	try {
		const found = await resolveAlias(call, alias);
		if (found !== null) {
			roomId = found;
			created = false;
		} else {
			const creation = await call(
				'POST',
				'/_matrix/client/v3/createRoom',
				handoverRoomCreation({ sensorUserId, ownerLocalpart, name: roomName })
			);
			if (creation.status === 200 && typeof creation.document['room_id'] === 'string') {
				roomId = creation.document['room_id'];
				created = true;
			} else if (creation.document['errcode'] === 'M_ROOM_IN_USE') {
				// Another tab, or this browser a moment ago. The alias is the
				// room's identity, so the answer is to read it, not to make a
				// second room with a different one.
				const raced = await resolveAlias(call, alias);
				if (raced === null) {
					return {
						kind: 'failed',
						detail: `the alias ${alias} is taken by a room the homeserver will not name`
					};
				}
				roomId = raced;
				created = false;
			} else {
				return { kind: 'failed', detail: refusalOf(creation) };
			}
		}

		// The Sensor's one power-level exception, on a room that may predate it.
		// A room created by #226 grants the Sensor nothing at all, so the
		// acknowledgement #228 needs would be refused by the homeserver — and a
		// handover that works and cannot be confirmed reads exactly like one that
		// never arrived. Adding it is the owner's to do: they hold 100 here.
		const granted = await grantTheAcknowledgement(call, roomId);
		if (granted !== null) {
			return { kind: 'failed', detail: granted };
		}

		// An existing room whose Sensor has left, or a deployment whose Sensor
		// id changed: the invitation is what puts it back, and asking for one
		// it already has is answered `already in the room` rather than being an
		// error worth stopping for.
		const membership = await memberOf(call, roomId, sensorUserId);
		if (membership !== 'join' && membership !== 'invite') {
			const invitation = await call(
				'POST',
				`/_matrix/client/v3/rooms/${encodeURIComponent(roomId)}/invite`,
				{ user_id: sensorUserId }
			);
			if (
				invitation.status !== 200 &&
				!String(invitation.document['error'] ?? '').includes('already in the room')
			) {
				return { kind: 'failed', detail: refusalOf(invitation) };
			}
		}

		// Joined, as the homeserver answers it — not as the invitation's
		// success implies. The Sensor accepts on its next sync, which is
		// normally a second and is never instant.
		const joined = await waitFor(
			async () => (await memberOf(call, roomId, sensorUserId)) === 'join',
			joinDeadlineMs,
			pollIntervalMs
		);
		if (!joined) {
			return { kind: 'sensor-did-not-join', roomId };
		}
	} catch (cause) {
		return { kind: 'failed', detail: cause instanceof Error ? cause.message : String(cause) };
	}

	// And now the only question this whole room was created to answer.
	let sensorDevices = 0;
	try {
		await crypto.startSync();
		await waitFor(
			async () => {
				sensorDevices = await crypto.trackedDeviceCount(sensorUserId);
				return sensorDevices > 0;
			},
			trackingDeadlineMs,
			pollIntervalMs
		);
	} catch (cause) {
		return { kind: 'failed', detail: cause instanceof Error ? cause.message : String(cause) };
	} finally {
		crypto.stopSync();
	}

	return sensorDevices > 0
		? { kind: 'ready', roomId, sensorDevices, created }
		: { kind: 'sensor-untracked', roomId };
}

/**
 * Makes sure the Sensor may write [`HANDOVER_HELD_TYPE`] in this room, and
 * nothing else. Answers `null` when it may, or the homeserver's words.
 *
 * Idempotent and normally free: a room created by [`handoverRoomCreation`] already
 * carries the exception, so this reads the power levels and writes nothing. A room
 * created before the exception existed is amended in one request, with every other
 * level left exactly as it was — this is the user's own room, and the only thing
 * being changed is the one type the Sensor is allowed to say.
 */
async function grantTheAcknowledgement(call: Call, roomId: string): Promise<string | null> {
	const path = `/_matrix/client/v3/rooms/${encodeURIComponent(roomId)}/state/m.room.power_levels/`;
	const current = await call('GET', path);
	if (current.status !== 200) {
		return `${current.status} reading this room's power levels`;
	}
	const events =
		typeof current.document['events'] === 'object' && current.document['events'] !== null
			? (current.document['events'] as Record<string, unknown>)
			: {};
	if (events[HANDOVER_HELD_TYPE] === 0) {
		return null;
	}
	const amended = { ...current.document, events: { ...events, [HANDOVER_HELD_TYPE]: 0 } };
	let written = await call('PUT', path, amended);
	if (written.status !== 200) {
		// Once more, after whatever the homeserver asked for. Synapse rate-limits
		// state sends, and a `429` on this one request would otherwise fail an
		// onboarding that is being re-run — the room is there, the Sensor is in it,
		// and the only thing missing is a power level it already agreed to. A
		// refusal that is not about rate is answered the same way and costs one
		// extra request.
		const askedFor = written.document['retry_after_ms'];
		const wait = typeof askedFor === 'number' ? Math.min(askedFor, 5_000) : 1_000;
		await new Promise((resolve) => setTimeout(resolve, wait));
		written = await call('PUT', path, amended);
	}
	return written.status === 200
		? null
		: `${written.status} granting the Sensor the one state event it may write`;
}

/** The room the handover alias points at, or `null`. */
async function resolveAlias(call: Call, alias: string): Promise<string | null> {
	const answer = await call('GET', `/_matrix/client/v3/directory/room/${encodeURIComponent(alias)}`);
	const roomId = answer.document['room_id'];
	return answer.status === 200 && typeof roomId === 'string' ? roomId : null;
}

/** One account's membership in a room, or `null` when there is no event. */
async function memberOf(call: Call, roomId: string, userId: string): Promise<string | null> {
	const answer = await call(
		'GET',
		`/_matrix/client/v3/rooms/${encodeURIComponent(roomId)}/state/m.room.member/${encodeURIComponent(userId)}`
	);
	const membership = answer.document['membership'];
	return answer.status === 200 && typeof membership === 'string' ? membership : null;
}

