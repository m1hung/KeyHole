/**
 * Envelope-level sync decisions.
 *
 * Pure: no I/O. Both the web app and the extension call these after reading
 * two VaultFile envelopes (local cache vs shared file, or cache vs cache).
 * Decrypted entry merge is intentionally out of scope — see docs/SYNC.md.
 */

import type { VaultFile } from './types.ts';

/** Result of comparing two encrypted envelopes. */
export type EnvelopeRelation = 'same' | 'a-newer' | 'b-newer' | 'divergent' | 'unrelated';

export type SyncAction = 'noop' | 'adopt-remote' | 'push-local' | 'conflict' | 'refuse';

export interface SyncDecision {
  action: SyncAction;
  relation: EnvelopeRelation;
  /** Short, UI-safe explanation (no secrets). */
  reason: string;
}

function payloadFingerprint(file: VaultFile): string {
  // IV + ciphertext(+tag) uniquely identify this encryption of the payload.
  // wrappedKey is excluded so a master-password change (new wrap, re-encrypted
  // payload, new updatedAt) still orders correctly via timestamps.
  return `${file.payload.ivB64}:${file.payload.ctB64}`;
}

/**
 * Compare two envelopes without decrypting them.
 *
 * Ordering uses the authenticated `updatedAt` written by `saveVault`, not the
 * filesystem mtime. Identical timestamps with different payloads are
 * `divergent` (clock collision or torn write) rather than an arbitrary pick.
 */
export function compareEnvelopes(a: VaultFile, b: VaultFile): EnvelopeRelation {
  if (a.vaultId !== b.vaultId) return 'unrelated';

  if (a.updatedAt === b.updatedAt) {
    return payloadFingerprint(a) === payloadFingerprint(b) ? 'same' : 'divergent';
  }

  return a.updatedAt > b.updatedAt ? 'a-newer' : 'b-newer';
}

/**
 * Decide how `local` (this client's cache) should move relative to `remote`
 * (typically the shared on-disk file).
 *
 * Last-write-wins on the whole envelope. Never returns an action that would
 * overwrite across different vaultIds.
 */
export function decideSync(local: VaultFile, remote: VaultFile): SyncDecision {
  const relation = compareEnvelopes(local, remote);

  switch (relation) {
    case 'same':
      return { action: 'noop', relation, reason: 'Local cache and remote file already match.' };
    case 'a-newer':
      return {
        action: 'push-local',
        relation,
        reason: 'Local cache is newer than the remote file; write local → file.',
      };
    case 'b-newer':
      return {
        action: 'adopt-remote',
        relation,
        reason: 'Remote file is newer than the local cache; adopt file → cache.',
      };
    case 'divergent':
      return {
        action: 'conflict',
        relation,
        reason: 'Same updatedAt but different ciphertext — choose which envelope to keep.',
      };
    case 'unrelated':
      return {
        action: 'refuse',
        relation,
        reason: 'Vault ids differ; refusing to mix two distinct vaults.',
      };
  }
}

/**
 * Apply a non-conflict decision to pick the envelope that should become
 * canonical. Returns null when the caller must stop (noop is fine; conflict /
 * refuse need UI).
 */
export function pickCanonical(
  local: VaultFile,
  remote: VaultFile,
  decision: SyncDecision = decideSync(local, remote),
): VaultFile | null {
  switch (decision.action) {
    case 'noop':
    case 'push-local':
      return local;
    case 'adopt-remote':
      return remote;
    case 'conflict':
    case 'refuse':
      return null;
  }
}
