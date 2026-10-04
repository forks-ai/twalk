// Replacing the recovery key from a browser that still has its keys.
//
// The key is shown once, at onboarding, and never again: nothing keeps it, by
// design — the store holds the secrets the key *opens*, never the key. So an
// owner who did not save it has, until now, had no way back inside Twalk. The
// only route was another Matrix client pointed at the deployment, which on a
// homeserver published nowhere means an SSH tunnel and a desktop client, and
// nobody does that (#433).
//
// This is the way back. It does not recover the lost key — that is not
// possible — it **replaces** it, from a browser whose crypto store is still
// there. Which is the one precondition, and the reason it could not have
// helped the owner who prompted it: their store was already gone.

import type {
	CreateSecretStorageOpts,
	CrossSigningStatus,
	GeneratedSecretStorageKey,
} from 'matrix-js-sdk/lib/crypto-api';

import { groupRecoveryKey } from '$lib/recovery/key';

/**
 * The two calls this needs from the crypto stack, named so a test can stand
 * in for them. The real one is `MatrixClient.getCrypto()`.
 */
export interface RenewableCrypto {
	createRecoveryKeyFromPassphrase(): Promise<GeneratedSecretStorageKey>;
	bootstrapSecretStorage(opts: CreateSecretStorageOpts): Promise<void>;
	/** What this browser holds of the account's identity — see below. */
	getCrossSigningStatus(): Promise<CrossSigningStatus>;
}

/**
 * Thrown when this browser holds none of the account's cross-signing secrets,
 * so there is nothing for a new key to be given (#445). The screen turns it
 * into the one sentence an owner can act on.
 */
export const NO_LOCAL_KEYS = 'no-local-keys';

/**
 * Generates a new recovery key, installs it as the account's secret storage,
 * and returns it grouped for display. The caller shows it once — this is the
 * only moment it exists outside the crypto stack.
 *
 * `setupNewSecretStorage: true` is the whole correctness of this function and
 * not a detail: without it `bootstrapSecretStorage` finds secret storage
 * already set up and **returns having done nothing**. The user would be shown
 * a key that opens nothing, while the key they lost keeps working. A silent
 * no-op presented as a new key is worse than no feature, which is why the
 * test asserts the option rather than the happy path.
 *
 * `setupNewKeyBackup` is deliberately absent, which leaves it false. Resetting
 * secret storage orphans whatever was sealed with the old key, and minting a
 * fresh backup version on top would discard the old one for no gain: this
 * client puts nothing in a backup — it never syncs history, so it holds no
 * room key to put there. The screen says what is orphaned rather than
 * pretending otherwise.
 */
export async function renewRecoveryKey(
	crypto: RenewableCrypto,
): Promise<string> {
	// **Asked, not assumed** (#445). `bootstrapSecretStorage` below writes the
	// cross-signing secrets *this browser holds* into the new storage. A
	// browser holding none would replace the account's secret storage with an
	// empty one: the owner would be shown a key that opens nothing, while
	// whatever was in there became unreachable. A silent loss dressed as a
	// success, and the one outcome this function must not have.
	//
	// Until #445 the screen inferred this from the absence of a live client,
	// which is a different question and was wrong on every normal visit: the
	// client is built by onboarding and by the recovery screen, and nothing
	// rebuilds one on a page load, so an owner whose keys were right there was
	// told their browser had lost them.
	const status = await crypto.getCrossSigningStatus();
	const cached = status.privateKeysCachedLocally;
	if (!cached.masterKey || !cached.selfSigningKey || !cached.userSigningKey) {
		throw new Error(NO_LOCAL_KEYS);
	}

	const generated = await crypto.createRecoveryKeyFromPassphrase();
	const encoded = generated.encodedPrivateKey;
	if (encoded === undefined || encoded.length === 0) {
		throw new Error('the crypto stack generated no displayable recovery key');
	}
	await crypto.bootstrapSecretStorage({
		createSecretStorageKey: async (): Promise<GeneratedSecretStorageKey> =>
			generated,
		setupNewSecretStorage: true,
	});
	return groupRecoveryKey(encoded);
}
