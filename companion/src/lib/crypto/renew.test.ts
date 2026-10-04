import { describe, expect, it, vi } from 'vitest';

import { renewRecoveryKey, type RenewableCrypto } from './renew';

/** A crypto stack that records what it was asked to do. */
function fakeCrypto(encodedPrivateKey: string | undefined) {
	const bootstrapSecretStorage = vi.fn().mockResolvedValue(undefined);
	const crypto: RenewableCrypto = {
		createRecoveryKeyFromPassphrase: async () =>
			({ encodedPrivateKey, privateKey: new Uint8Array() }) as never,
		bootstrapSecretStorage,
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
