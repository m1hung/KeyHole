/**
 * Pull-merge-push sync against a Keyhole sync server.
 *
 * While the vault is unlocked, callers can omit `masterPassword` and reuse the
 * session key to open the remote envelope (same vault id). The sync auth secret
 * still must be supplied (cached in memory after the first derivation).
 */

import { mergeVaultData, openVaultWithKey, saveVault, unlockVault, type VaultFile, type VaultSession } from '@keyhole/core';
import { getVault, putVault, SyncClientError } from './client.ts';

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
