/**
 * Changing the master password on a synced vault, end to end.
 *
 * This lives in the server workspace because it is the only place both halves
 * exist: the real Fastify app on a real socket, and the real client helper —
 * `app.inject` cannot exercise code that calls `fetch`.
 *
 * The bug it pins: `changeMasterPassword` mints a fresh Argon2id salt, and the
 * sync auth secret is derived from the password *and that salt*. Nothing rotated
 * the account's verifier, so sync started failing with 401 the moment a user
 * changed their password, and the only way back was the "overwrite remote" repair
 * path — which nobody would connect to having changed a password.
 */

import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { createVault, changeMasterPassword, deriveSyncAuthSecret, type VaultFile } from '@keyhole/core';
import { buildApp } from '../src/app.ts';
import { loadConfig } from '../src/config.ts';
import { Store } from '../src/db.ts';
import { fetchPrelogin, getVault, putVault, SyncClientError } from '../../app/src/sync/client.ts';
import { rotateSyncAuthAfterRekey } from '../../app/src/sync/runSync.ts';

const OLD_PASSWORD = 'the-original-master-passphrase';
const NEW_PASSWORD = 'a-completely-different-passphrase';
const ACCOUNT = 'alice';

let app: FastifyInstance;
let store: Store;
let baseUrl: string;

beforeEach(async () => {
  store = new Store(':memory:');
  app = buildApp({ config: loadConfig({ databasePath: ':memory:' }), store });
  // A real socket, because the client helper speaks HTTP.
  await app.listen({ port: 0, host: '127.0.0.1' });
  const address = app.server.address();
  if (address === null || typeof address === 'string') throw new Error('expected a TCP address');
  baseUrl = `http://127.0.0.1:${address.port}`;
});

afterEach(async () => {
  await app.close();
  store.close();
});

/** Register an account holding a freshly created vault. */
async function registerVault(): Promise<{ file: VaultFile; secret: string }> {
  const { file } = await createVault(OLD_PASSWORD);
  const secret = await deriveSyncAuthSecret(OLD_PASSWORD, file.kdf);
  const res = await fetch(`${baseUrl}/api/v1/account`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ accountId: ACCOUNT, authSecret: secret, envelope: file }),
  });
  expect(res.status).toBe(201);
  return { file, secret };
}

describe('rotating sync auth after a master-password change', () => {
  it('re-points the account so the new password authenticates and the old one does not', async () => {
    const { file, secret: oldSecret } = await registerVault();
    const rekeyed = await changeMasterPassword(file, OLD_PASSWORD, NEW_PASSWORD);

    const rotated = await rotateSyncAuthAfterRekey({
      baseUrl,
      accountId: ACCOUNT,
      currentMasterPassword: OLD_PASSWORD,
      nextMasterPassword: NEW_PASSWORD,
      previousFile: file,
      newFile: rekeyed.file,
    });

    // The secret the caller should now cache works...
    const pulled = await getVault(baseUrl, ACCOUNT, rotated.syncAuthSecretB64);
    expect(pulled.envelope.vaultId).toBe(file.vaultId);
    expect(pulled.version).toBe(rotated.version);

    // ...and the pre-change one is dead.
    await expect(getVault(baseUrl, ACCOUNT, oldSecret)).rejects.toThrow(SyncClientError);
  }, 30_000);

  /**
   * The property that matters for *other* devices: they learn the KDF from
   * prelogin, so the salt the server serves must be the one the new verifier was
   * derived from. Uploading the re-keyed envelope and the new secret together is
   * what keeps those two in step.
   */
  it('leaves a second device able to derive a working secret from prelogin alone', async () => {
    const { file } = await registerVault();
    const rekeyed = await changeMasterPassword(file, OLD_PASSWORD, NEW_PASSWORD);
    await rotateSyncAuthAfterRekey({
      baseUrl,
      accountId: ACCOUNT,
      currentMasterPassword: OLD_PASSWORD,
      nextMasterPassword: NEW_PASSWORD,
      previousFile: file,
      newFile: rekeyed.file,
    });

    const { kdf: accountKdf } = await fetchPrelogin(baseUrl, ACCOUNT);
    expect(accountKdf.saltB64).toBe(rekeyed.file.kdf.saltB64);

    const secondDevice = await deriveSyncAuthSecret(NEW_PASSWORD, accountKdf);
    await expect(getVault(baseUrl, ACCOUNT, secondDevice)).resolves.toBeDefined();
  }, 30_000);

  /**
   * Rotation uploads this device's envelope. If another device wrote first, that
   * upload would drop their changes — refuse instead of silently winning.
   */
  it('refuses to rotate on top of a newer server copy', async () => {
    const { file, secret: oldSecret } = await registerVault();
    const rekeyed = await changeMasterPassword(file, OLD_PASSWORD, NEW_PASSWORD);

    // Another device saves an entry and pushes, so the server now holds content
    // this device has never seen.
    const newer: VaultFile = { ...file, updatedAt: new Date(Date.parse(file.updatedAt) + 60_000).toISOString() };
    const remote = await getVault(baseUrl, ACCOUNT, oldSecret);
    const pushed = await putVault(baseUrl, ACCOUNT, oldSecret, newer, remote.version);
    expect(pushed.conflict).toBe(false);

    await expect(
      rotateSyncAuthAfterRekey({
        baseUrl,
        accountId: ACCOUNT,
        currentMasterPassword: OLD_PASSWORD,
        nextMasterPassword: NEW_PASSWORD,
        previousFile: file,
        newFile: rekeyed.file,
      }),
    ).rejects.toThrow(/Sync, then change the password again/);

    // And the account is untouched: the old secret still works, so the user is not
    // locked out of sync by a failed rotation.
    await expect(getVault(baseUrl, ACCOUNT, oldSecret)).resolves.toBeDefined();
  }, 30_000);
});
