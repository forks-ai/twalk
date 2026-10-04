import { describe, expect, it, vi } from 'vitest';

import { renewRecoveryKey, type RenewableCrypto } from './renew';

/** A crypto stack that records what it was asked to do. */
function fakeCrypto(
	encodedPrivateKey: string | undefined,
	cached: { masterKey: boolean; selfSigningKey: boolean; userSigningKey: boolean } = {
		masterKey: true,
		selfSigningKey: true,
		userSigningKey: true,
	},
) {
	const bootstrapSecretStorage = vi.fn().mockResolvedValue(undefined);
	const crypto: RenewableCrypto = {
		createRecoveryKeyFromPassphrase: async () =>
			({ encodedPrivateKey, privateKey: new Uint8Array() }) as never,
		bootstrapSecretStorage,
		getCrossSigningStatus: async () =>
			({
				publicKeysOnDevice: true,
				privateKeysInSecretStorage: true,
				privateKeysCachedLocally: cached,
			}) as never,
	};
	return { crypto, bootstrapSecretStorage };
}

/** 48 base58 characters, which is what the crypto stack hands back. */
const ENCODED = 'EsTa1bQd2eFg3hIj4kLm5nOp6qRs7tUv8wXy9zAb1cDe2fGh';

describe('renewing the recovery key', () => {
	/**
   * The one that matters. `bootstrapSecretStorage` finds secret storage
   * already set up and returns having done nothing unless it is told to
   * reset — so without this option the user is shown a fresh key that opens
   * nothing, while the key they lost keeps working.
   *
   * That failure is silent: every call succeeds, the screen shows a key, and
   * the account is unchanged. Nothing else in this test file would catch it.
   */
	it('resets the secret storage rather than finding it already set up', async () => {
		const { crypto, bootstrapSecretStorage } = fakeCrypto(ENCODED);

		await renewRecoveryKey(crypto);

		expect(bootstrapSecretStorage).toHaveBeenCalledOnce();
		expect(bootstrapSecretStorage.mock.calls[0][0]).toMatchObject({
			setupNewSecretStorage: true,
		});
	});

	/**
   * Minting a backup version would discard the existing one, and this client
   * has nothing to put in a backup: it never syncs history, so it holds no
   * room key. Leaving it alone is the choice; the screen says what the reset
   * orphans instead of quietly churning server state.
   */
	it('does not mint a new key backup', async () => {
		const { crypto, bootstrapSecretStorage } = fakeCrypto(ENCODED);

		await renewRecoveryKey(crypto);

		expect(
			bootstrapSecretStorage.mock.calls[0][0].setupNewKeyBackup,
		).toBeFalsy();
	});

	it('hands back the key grouped the way it is shown and written down', async () => {
		const { crypto } = fakeCrypto(ENCODED);

		const key = await renewRecoveryKey(crypto);

		expect(key.split(' ')).toHaveLength(12);
		expect(key).toMatch(/^(\w{4} ){11}\w{4}$/);
	});

	/**
   * A crypto stack that generates nothing must not reach the account. The
   * order is the point: refusing before `bootstrapSecretStorage` leaves the
   * old key working, where resetting first would destroy it and leave the
   * owner with neither.
   */
	it('refuses before touching the account when no key was generated', async () => {
		const { crypto, bootstrapSecretStorage } = fakeCrypto(undefined);

		await expect(renewRecoveryKey(crypto)).rejects.toThrow(
			'no displayable recovery key',
		);
		expect(bootstrapSecretStorage).not.toHaveBeenCalled();
	});
});

describe('what renewing requires of this browser', () => {
	/**
	 * The precondition, enforced rather than assumed (#445).
	 *
	 * `bootstrapSecretStorage({ setupNewSecretStorage: true })` writes the
	 * cross-signing secrets **the local store holds** into the new storage. A
	 * browser that holds none would therefore replace the account's secret
	 * storage with an empty one, and the owner would be shown a key that opens
	 * nothing while the secrets that were in there became unreachable — a
	 * silent loss, dressed as a success.
	 *
	 * So the stack is asked, and the answer is the screen's: "this browser no
	 * longer holds your keys" stops being an inference from a missing session
	 * and becomes something measured.
	 */
	it('refuses when the private keys are not in this browser', async () => {
		const { crypto, bootstrapSecretStorage } = fakeCrypto(ENCODED, {
			masterKey: false,
			selfSigningKey: false,
			userSigningKey: false,
		});

		await expect(renewRecoveryKey(crypto)).rejects.toThrow('no-local-keys');
		expect(bootstrapSecretStorage).not.toHaveBeenCalled();
	});

	it('refuses when only some of the three are here', async () => {
		// A half-populated store is not a store this may write from: the two
		// secrets it could carry would be written and the third lost.
		const { crypto, bootstrapSecretStorage } = fakeCrypto(ENCODED, {
			masterKey: true,
			selfSigningKey: true,
			userSigningKey: false,
		});

		await expect(renewRecoveryKey(crypto)).rejects.toThrow('no-local-keys');
		expect(bootstrapSecretStorage).not.toHaveBeenCalled();
	});

	it('goes ahead when all three are cached locally', async () => {
		const { crypto, bootstrapSecretStorage } = fakeCrypto(ENCODED);

		await expect(renewRecoveryKey(crypto)).resolves.toMatch(/^(\w{4} ){11}\w{4}$/);
		expect(bootstrapSecretStorage).toHaveBeenCalledOnce();
	});
});
