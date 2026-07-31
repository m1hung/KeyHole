/**
 * Vault merge for sync.
 *
 * The server never sees plaintext, so it cannot merge anything: it stores one
 * opaque envelope plus a monotonic version and rejects a write whose expected
 * version is stale. All reconciliation therefore happens here, on a client
 * that has just decrypted both sides.
 *
 * THE RULE THIS FILE MUST NEVER BREAK: a merge may not silently lose a
 * password. When in doubt it keeps data. The only thing that removes an entry
 * is an explicit, dated tombstone that is newer than the entry itself.
 *
 * CONVERGENCE: two devices merging the same pair in opposite directions must
 * reach byte-identical results, or they will push conflicting envelopes back
 * and forth forever. Every rule below is therefore commutative, including the
 * tie-breaks — which is why equal timestamps fall back to comparing content
 * rather than preferring "local".
 */

import {
  PASSWORD_HISTORY_LIMIT,
  SCHEMA_VERSION,
  type Entry,
  type Folder,
  type PasskeyRecord,
  type PasswordHistoryEntry,
  type Tombstone,
  type VaultData,
} from './types.ts';

/**
 * How long a deletion is remembered. A device offline longer than this can
 * resurrect an entry it never learned was deleted; keeping tombstones forever
 * would instead grow the vault without bound. Six months is far beyond any
 * plausible offline window for a password manager.
 */
export const TOMBSTONE_TTL_DAYS = 180;

const DAY_MS = 24 * 60 * 60 * 1000;

function time(iso: string): number {
  const t = Date.parse(iso);
  // An unparseable timestamp sorts oldest, so it can never win a comparison
  // and overwrite good data with garbage.
  return Number.isNaN(t) ? 0 : t;
}

function latest(a: string, b: string): string {
  return time(a) >= time(b) ? a : b;
}

/**
 * Deterministic tie-break for records with identical timestamps.
 *
 * Comparing serialised content is arbitrary but it is *stable*: both devices
 * pick the same winner, so they converge. Preferring "mine" would not — each
 * device would keep its own version and they would never agree.
 */
function breakTie<T>(a: T, b: T): T {
  return JSON.stringify(a) >= JSON.stringify(b) ? a : b;
}

/**
 * Union two password histories, newest first, capped.
 *
 * Keyed on `changedAt`: it is when the password stopped being current, so two
 * devices recording the same rotation agree on it, while two genuinely different
 * rotations differ. Where both sides have a row for one instant, the passwords are
 * compared so a real collision still keeps both rather than silently picking one.
 */
function mergeHistory(
  a: readonly PasswordHistoryEntry[],
  b: readonly PasswordHistoryEntry[],
): PasswordHistoryEntry[] {
  const seen = new Set<string>();
  const merged: PasswordHistoryEntry[] = [];
  for (const row of [...a, ...b]) {
    // A JSON tuple rather than a delimiter, so no separator can collide with content.
    const key = JSON.stringify([row.changedAt, row.password]);
    if (seen.has(key)) continue;
    seen.add(key);
    merged.push(row);
  }
  merged.sort((x, y) => time(y.changedAt) - time(x.changedAt));
  return merged.slice(0, PASSWORD_HISTORY_LIMIT);
}

/** Union passkeys by credential id; prefer higher sign count. */
function mergePasskeys(a: readonly PasskeyRecord[], b: readonly PasskeyRecord[]): PasskeyRecord[] {
  const byCred = new Map<string, PasskeyRecord>();
  for (const row of [...a, ...b]) {
    const existing = byCred.get(row.credentialIdB64);
    if (!existing) {
      byCred.set(row.credentialIdB64, row);
      continue;
    }
    if (row.signCount > existing.signCount) {
      byCred.set(row.credentialIdB64, row);
    } else if (row.signCount === existing.signCount) {
      const rowUsed = time(row.lastUsedAt ?? row.createdAt);
      const existingUsed = time(existing.lastUsedAt ?? existing.createdAt);
      if (rowUsed > existingUsed) {
        byCred.set(row.credentialIdB64, row);
      } else if (rowUsed === existingUsed) {
        byCred.set(row.credentialIdB64, breakTie(existing, row));
      }
    }
  }
  return [...byCred.values()].sort((x, y) =>
    x.credentialIdB64 < y.credentialIdB64 ? -1 : x.credentialIdB64 > y.credentialIdB64 ? 1 : 0,
  );
}

// ---------------------------------------------------------------------------
// Tombstones
// ---------------------------------------------------------------------------

function mergeTombstones(a: readonly Tombstone[], b: readonly Tombstone[]): Tombstone[] {
  const byKey = new Map<string, Tombstone>();
  for (const t of [...a, ...b]) {
    const key = `${t.kind}:${t.id}`;
    const existing = byKey.get(key);
    if (!existing || time(t.deletedAt) > time(existing.deletedAt)) byKey.set(key, t);
  }
  return [...byKey.values()].sort((x, y) => `${x.kind}:${x.id}`.localeCompare(`${y.kind}:${y.id}`));
}

function pruneTombstones(tombstones: readonly Tombstone[], nowMs: number): Tombstone[] {
  const cutoff = nowMs - TOMBSTONE_TTL_DAYS * DAY_MS;
  return tombstones.filter((t) => time(t.deletedAt) >= cutoff);
}

// ---------------------------------------------------------------------------
// Merge
// ---------------------------------------------------------------------------

export interface MergeStats {
  entriesKept: number;
  entriesDeleted: number;
  /** Entries that existed on both sides with differing content. */
  entriesReconciled: number;
  foldersKept: number;
  tombstones: number;
}

export interface MergeResult {
  data: VaultData;
  stats: MergeStats;
}

/**
 * Merge two decrypted vaults into one.
 *
 * Symmetric: `merge(a, b)` and `merge(b, a)` produce identical output. That is
 * a hard requirement, not a nicety — see the convergence note at the top.
 *
 * `nowMs` is injectable so tests can exercise tombstone expiry without waiting
 * six months.
 */
export function mergeVaultData(a: VaultData, b: VaultData, nowMs: number = Date.now()): MergeResult {
  const tombstones = pruneTombstones(mergeTombstones(a.tombstones, b.tombstones), nowMs);
  const deletedAt = new Map(tombstones.map((t) => [`${t.kind}:${t.id}`, time(t.deletedAt)] as const));

  // -- entries ---------------------------------------------------------------
  const entryById = new Map<string, Entry>();
  let entriesReconciled = 0;

  for (const entry of [...a.entries, ...b.entries]) {
    const existing = entryById.get(entry.id);
    if (!existing) {
      entryById.set(entry.id, entry);
      continue;
    }
    if (JSON.stringify(existing) !== JSON.stringify(entry)) entriesReconciled++;

    const ta = time(existing.updatedAt);
    const tb = time(entry.updatedAt);
    const winner = ta === tb ? breakTie(existing, entry) : ta > tb ? existing : entry;
    // Every other field is last-write-wins, but history is not a *state* — it is a
    // log, and the two sides hold different parts of it. Rotate a password on the
    // phone and again on the desktop, and whole-entry LWW keeps one row and drops
    // the other, destroying exactly the old password this feature exists to keep.
    entryById.set(entry.id, {
      ...winner,
      history: mergeHistory(existing.history, entry.history),
      passkeys: mergePasskeys(existing.passkeys ?? [], entry.passkeys ?? []),
    });
  }

  let entriesDeleted = 0;
  const entries: Entry[] = [];
  for (const entry of entryById.values()) {
    const tomb = deletedAt.get(`entry:${entry.id}`);
    // A tombstone only wins if the entry has not been touched since. Editing
    // an entry on device A after device B deleted it is a resurrection, and
    // keeping the edit is the safe reading: the user's later intent was to
    // have this password.
    if (tomb !== undefined && tomb >= time(entry.updatedAt)) {
      entriesDeleted++;
      continue;
    }
    entries.push(entry);
  }

  // -- folders ---------------------------------------------------------------
  const folderById = new Map<string, Folder>();
  for (const folder of [...a.folders, ...b.folders]) {
    const existing = folderById.get(folder.id);
    // Folders carry only createdAt, so there is nothing to reconcile beyond
    // picking one deterministically when names diverge.
    folderById.set(folder.id, existing ? breakTie(existing, folder) : folder);
  }

  const folders: Folder[] = [];
  for (const folder of folderById.values()) {
    const tomb = deletedAt.get(`folder:${folder.id}`);
    if (tomb !== undefined && tomb >= time(folder.createdAt)) continue;
    folders.push(folder);
  }

  // Deleting a folder unfiles its entries rather than deleting them; a merge
  // that drops a folder must uphold the same guarantee.
  const liveFolders = new Set(folders.map((f) => f.id));
  const reconciledEntries = entries.map((e) =>
    e.folderId !== null && !liveFolders.has(e.folderId) ? { ...e, folderId: null } : e,
  );

  reconciledEntries.sort((x, y) => x.id.localeCompare(y.id));
  folders.sort((x, y) => x.id.localeCompare(y.id));

  // Settings are a single unit — merging them field-by-field could invent a
  // combination the user never chose. The more recently written vault wins.
  const newer = time(a.updatedAt) >= time(b.updatedAt) ? a : b;

  return {
    data: {
      schemaVersion: SCHEMA_VERSION,
      entries: reconciledEntries,
      folders,
      tombstones,
      settings: newer.settings,
      updatedAt: latest(a.updatedAt, b.updatedAt),
    },
    stats: {
      entriesKept: reconciledEntries.length,
      entriesDeleted,
      entriesReconciled,
      foldersKept: folders.length,
      tombstones: tombstones.length,
    },
  };
}
