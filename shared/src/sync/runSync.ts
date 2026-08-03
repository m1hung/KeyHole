/**
 * Pull-merge-push sync against a Keyhole sync server.
 *
 * While the vault is unlocked, callers can omit `masterPassword` and reuse the
 * session key to open the remote envelope (same vault id). The sync auth secret
 * still must be supplied (cached in memory after the first derivation).
 */

import {
  deriveSyncAuthSecret,
  mergeVaultData,
  openVaultWithKey,
  saveVault,
  unlockVault,
  type VaultFile,
  type VaultSession,
} from '@keyhole/core';
import { fetchPrelogin, getVault, putVault, SyncClientError } from './client.ts';

export interface PerformSyncParams {
  baseUrl: string;
  accountId: string;
  syncAuthSecretB64: string;
  /** Required only when the remote envelope cannot be opened with session.key. */
  masterPassword?: string;
  localFile: VaultFile;
  session: VaultSession;
}

export interface PerformSyncResult {
  file: VaultFile;
  session: VaultSession;
  message: string;
}

const MAX_RETRIES = 4;

export interface RotateSyncAuthParams {
  baseUrl: string;
  accountId: string;
  /** The password the account's verifier was derived from. */
  currentMasterPassword: string;
  nextMasterPassword: string;
  /** The envelope this device re-keyed *from*, to detect unmerged remote changes. */
  previousFile: VaultFile;
  /** The already re-keyed local envelope — its new KDF salt becomes the account's. */
  newFile: VaultFile;
}

/**
 * Re-point a sync account at a re-keyed vault.
 *
 * MUST run after every master-password change on a synced vault. `changeMasterPassword`
 * mints a fresh Argon2id salt, and the sync auth secret is derived from the master
 * password *and that salt* — so the moment the salt changes, the secret every device
 * derives stops matching the verifier the server holds, and sync fails with 401 for
 * good. Without this, the only way back was the "overwrite remote" repair path, which
 * a user has no reason to connect to having changed their password.
 *
 * The server serves `envelope.kdf` from prelogin and swaps envelope and verifier in
 * one PUT, so uploading the new envelope together with a secret derived from its salt
 * leaves the account self-consistent for every other device.
 *
 * Rotation necessarily *replaces* the server's envelope: the payload has been
 * re-encrypted under a new VEK, so there is nothing to merge into. That makes
 * "is this device up to date?" a precondition rather than a detail — hence the
 * `previousFile` check below, which refuses rather than overwriting changes this
 * device has never seen.
 */
export async function rotateSyncAuthAfterRekey(
  params: RotateSyncAuthParams,
): Promise<{ version: number; syncAuthSecretB64: string }> {
  const { baseUrl, accountId, currentMasterPassword, nextMasterPassword, previousFile, newFile } = params;

  // Authenticate as the account still is: derived from the *account's* KDF, which
  // may not be this device's old salt if the account was registered elsewhere.
  const { kdf: accountKdf } = await fetchPrelogin(baseUrl, accountId);
  const currentSecret = await deriveSyncAuthSecret(currentMasterPassword, accountKdf);
  const nextSecret = await deriveSyncAuthSecret(nextMasterPassword, newFile.kdf);

  const remote = await getVault(baseUrl, accountId, currentSecret);

  // Expected-version alone cannot protect here: we read the version and write it
  // back moments later, so the check would pass no matter how stale this device is.
  // Compare content timestamps instead — the same last-write-wins basis the merge
  // uses — and refuse when the server holds something newer than what we re-keyed.
  const remoteWrittenAt = Date.parse(remote.envelope.updatedAt);
  const localWrittenAt = Date.parse(previousFile.updatedAt);
  if (Number.isFinite(remoteWrittenAt) && Number.isFinite(localWrittenAt) && remoteWrittenAt > localWrittenAt) {
    throw new SyncClientError(
      'The server has changes this device has not merged, and changing the password has to replace the stored vault. Sync, then change the password again.',
      409,
    );
  }

  const uploaded = await putVault(baseUrl, accountId, currentSecret, newFile, remote.version, nextSecret);

  if (uploaded.conflict) {
    // Lost the race between the read above and this write.
    throw new SyncClientError(
      'Another device wrote to the server while the password was being changed. Sync, then change the password again.',
      409,
    );
  }

  return { version: uploaded.result.version, syncAuthSecretB64: nextSecret };
}

async function readRemoteData(envelope: VaultFile, session: VaultSession, masterPassword?: string) {
  if (envelope.vaultId === session.vaultId) {
    try {
      return await openVaultWithKey(envelope, session.key);
    } catch {
      // Fall through to password unlock (e.g. key rotation).
    }
  }
  if (!masterPassword || masterPassword.length === 0) {
    throw new SyncClientError('Master password required to open the remote vault.', 401);
  }
  return (await unlockVault(envelope, masterPassword)).data;
}

export async function performSync(params: PerformSyncParams): Promise<PerformSyncResult> {
  const { baseUrl, accountId, syncAuthSecretB64, masterPassword, localFile, session } = params;

  let remote = await getVault(baseUrl, accountId, syncAuthSecretB64);

  if (remote.envelope.vaultId !== localFile.vaultId) {
    throw new SyncClientError(
      'Remote vault id differs from this device. Refusing to merge two distinct vaults.',
      409,
      'vault_mismatch',
    );
  }

  let workingSession = session;
  let file = localFile;
  let expectedVersion = remote.version;

  const remoteData = await readRemoteData(remote.envelope, workingSession, masterPassword);
  const { data: merged, stats } = mergeVaultData(workingSession.data, remoteData);
  workingSession = { ...workingSession, data: merged };
  file = await saveVault(workingSession, file);

  for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
    const response = await putVault(baseUrl, accountId, syncAuthSecretB64, file, expectedVersion);
    if (!response.conflict) {
      const parts = [
        `${stats.entriesKept} entries kept`,
        stats.entriesDeleted > 0 ? `${stats.entriesDeleted} deleted remotely` : null,
        stats.entriesReconciled > 0 ? `${stats.entriesReconciled} reconciled` : null,
      ].filter(Boolean);
      return {
        file,
        session: workingSession,
        message: `Synced with server (v${response.result.version}). ${parts.join('; ')}.`,
      };
    }

    remote = {
      envelope: response.envelope,
      version: response.version,
      updatedAt: response.updatedAt,
    };
    expectedVersion = remote.version;

    const conflictData = await readRemoteData(remote.envelope, workingSession, masterPassword);
    const { data: remerged } = mergeVaultData(workingSession.data, conflictData);
    workingSession = { ...workingSession, data: remerged };
    file = await saveVault(workingSession, file);
  }

  throw new SyncClientError('Sync failed.', 500);
}
