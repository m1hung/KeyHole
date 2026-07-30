/**
 * Vault lifecycle: create, unlock, save, CRUD, master-password change.
 *
 * Every function here is pure with respect to storage — nothing in this file
 * reads or writes disk, `chrome.storage`, or the network. Callers own
 * persistence, which is what lets the identical code back both the web app and
 * the extension.
 */

import {
  decrypt,
  defaultKdfParams,
  deriveMasterKey,
  encrypt,
  generateVaultKeyBytes,
  importAesKey,
  payloadAad,
  randomUuid,
  wrappedKeyAad,
  zeroize,
  type KdfPresetName,
} from './crypto.ts';
import { bytesToUtf8, utf8ToBytes } from './encoding.ts';
import { UnsupportedVersionError, ValidationError, VaultFormatError } from './errors.ts';
import { DEFAULT_GENERATOR_OPTIONS } from './password-gen.ts';
import {
  FORMAT_VERSION,
  MAX_ATTACHMENT_BYTES,
  MAX_ATTACHMENTS_VAULT_BYTES,
  PASSWORD_HISTORY_LIMIT,
  SCHEMA_VERSION,
  TRASH_RETENTION_DAYS,
  VAULT_FORMAT_ID,
  type Attachment,
  type CustomField,
  type Entry,
  type PasswordHistoryEntry,
  type Folder,
  type Settings,
  type Tombstone,
  type TotpConfig,
  type VaultData,
  type VaultFile,
  type VaultSession,
} from './types.ts';
import { parseVaultData, parseVaultFile } from './validation.ts';

export const DEFAULT_SETTINGS: Settings = {
  autoLockMinutes: 15,
  clipboardClearSeconds: 30,
  generator: DEFAULT_GENERATOR_OPTIONS,
  theme: 'system',
  lockOnHide: false,
  breachCheckEnabled: false,
};

/** Master passwords shorter than this are refused outright. */
export const MIN_MASTER_PASSWORD_LENGTH = 12;

function now(): string {
  return new Date().toISOString();
}

export function assertMasterPasswordAcceptable(password: string): void {
  if (password.length < MIN_MASTER_PASSWORD_LENGTH) {
    throw new ValidationError(`Master password must be at least ${MIN_MASTER_PASSWORD_LENGTH} characters.`);
  }
}

export function emptyVaultData(): VaultData {
  return {
    schemaVersion: SCHEMA_VERSION,
    entries: [],
    folders: [],
    tombstones: [],
    settings: structuredClone(DEFAULT_SETTINGS),
    updatedAt: now(),
  };
}

// ---------------------------------------------------------------------------
// Create / unlock / save
// ---------------------------------------------------------------------------

export interface CreateVaultOptions {
  kdfPreset?: KdfPresetName;
  initialData?: VaultData;
}

/**
 * Build a brand-new encrypted vault. Returns both the envelope (to persist) and
 * an unlocked session, so the caller does not have to immediately re-run the
 * KDF just to use the vault it created.
 */
export async function createVault(
  masterPassword: string,
  options: CreateVaultOptions = {},
): Promise<{ file: VaultFile; session: VaultSession }> {
  assertMasterPasswordAcceptable(masterPassword);

  const vaultId = randomUuid();
  const kdf = defaultKdfParams(options.kdfPreset ?? 'interactive');
  const header = { vaultId, formatVersion: FORMAT_VERSION, kdf };

  const masterKey = await deriveMasterKey(masterPassword, kdf);
  const vekBytes = generateVaultKeyBytes();
  try {
    const wrappedKey = await encrypt(masterKey, vekBytes, wrappedKeyAad(header));
    const vaultKey = await importAesKey(vekBytes);

    const data = options.initialData ?? emptyVaultData();
    const payload = await encrypt(vaultKey, utf8ToBytes(JSON.stringify(data)), payloadAad(header));

    const timestamp = now();
    const file: VaultFile = {
      format: VAULT_FORMAT_ID,
      formatVersion: FORMAT_VERSION,
      vaultId,
      createdAt: timestamp,
      updatedAt: timestamp,
      kdf,
      wrappedKey,
      payload,
    };
    return {
      file,
      session: { vaultId, key: vaultKey, data, unlockedAt: Date.now(), foreignSchemaVersion: null },
    };
  } finally {
    zeroize(vekBytes);
  }
}

/**
 * Unlock an envelope with a master password.
 *
 * Fail-closed ordering matters here: the VEK unwrap runs first, so a wrong
 * password throws before we ever touch the payload ciphertext. No partial state
 * is constructed on any failure path.
 */
export async function unlockVault(file: unknown, masterPassword: string): Promise<VaultSession> {
  const parsed = parseVaultFile(file);
  if (parsed.formatVersion > FORMAT_VERSION) {
    throw new UnsupportedVersionError(
      `This vault was written by a newer version of Keyhole (format ${parsed.formatVersion}). Please update.`,
    );
  }

  const header = { vaultId: parsed.vaultId, formatVersion: parsed.formatVersion, kdf: parsed.kdf };
  const masterKey = await deriveMasterKey(masterPassword, parsed.kdf);

  // Throws DecryptionError on a wrong password — the GCM tag is the verifier.
  const vekBytes = await decrypt(masterKey, parsed.wrappedKey, wrappedKeyAad(header));
  let vaultKey: CryptoKey;
  try {
    vaultKey = await importAesKey(vekBytes);
  } finally {
    zeroize(vekBytes);
  }

  const plaintext = await decrypt(vaultKey, parsed.payload, payloadAad(header));
  let data: VaultData;
  try {
    data = parseVaultData(JSON.parse(bytesToUtf8(plaintext)));
  } catch (err) {
    if (err instanceof SyntaxError) throw new VaultFormatError('Vault payload is not valid JSON.');
    throw err;
  } finally {
    zeroize(plaintext);
  }

  return {
    vaultId: parsed.vaultId,
    key: vaultKey,
    data: migrate(data),
    unlockedAt: Date.now(),
    foreignSchemaVersion: foreignSchemaVersion(data),
  };
}

/**
 * Decrypt a vault envelope using an already-held vault key (same vault id).
 * Used by sync while unlocked so the master password need not be re-entered.
 */
export async function openVaultWithKey(file: unknown, vaultKey: CryptoKey): Promise<VaultData> {
  const parsed = parseVaultFile(file);
  if (parsed.formatVersion > FORMAT_VERSION) {
    throw new UnsupportedVersionError(
      `This vault was written by a newer version of Keyhole (format ${parsed.formatVersion}). Please update.`,
    );
  }
  const header = { vaultId: parsed.vaultId, formatVersion: parsed.formatVersion, kdf: parsed.kdf };
  const plaintext = await decrypt(vaultKey, parsed.payload, payloadAad(header));
  try {
    return migrate(parseVaultData(JSON.parse(bytesToUtf8(plaintext))));
  } catch (err) {
    if (err instanceof SyntaxError) throw new VaultFormatError('Vault payload is not valid JSON.');
    throw err;
  } finally {
    zeroize(plaintext);
  }
}

/**
 * Re-encrypt the session's current data into an existing envelope.
 *
 * Reuses `kdf` and `wrappedKey` untouched: the master key has not changed, so
 * re-running Argon2id on every save would be pure cost. A fresh random IV is
 * generated for the payload by `encrypt`, so no nonce is ever reused.
 */
export async function saveVault(session: VaultSession, previous: VaultFile): Promise<VaultFile> {
  if (previous.vaultId !== session.vaultId) {
    throw new ValidationError('Session does not belong to this vault file.');
  }
  const data: VaultData = { ...session.data, updatedAt: now() };
  const payload = await encrypt(
    session.key,
    utf8ToBytes(JSON.stringify(data)),
    payloadAad({ vaultId: previous.vaultId, formatVersion: previous.formatVersion }),
  );
  session.data = data;
  return { ...previous, payload, updatedAt: data.updatedAt };
}

/**
 * Change the master password.
 *
 * Rotates *both* layers: a new Argon2id salt (so the old derived key is
 * useless) and a brand-new VEK with the payload re-encrypted under it. Rewrapping
 * alone would have been enough to lock out the old password, but rotating the
 * VEK also means a previously-exposed VEK cannot decrypt anything written after
 * the change.
 */
export async function changeMasterPassword(
  file: VaultFile,
  currentPassword: string,
  newPassword: string,
  options: { kdfPreset?: KdfPresetName } = {},
): Promise<{ file: VaultFile; session: VaultSession }> {
  assertMasterPasswordAcceptable(newPassword);

  // Verifies the current password by unlocking; throws before anything mutates.
  const current = await unlockVault(file, currentPassword);

  const kdf = defaultKdfParams(options.kdfPreset ?? 'interactive');
  const header = { vaultId: file.vaultId, formatVersion: FORMAT_VERSION, kdf };
  const newMasterKey = await deriveMasterKey(newPassword, kdf);

  const vekBytes = generateVaultKeyBytes();
  try {
    const wrappedKey = await encrypt(newMasterKey, vekBytes, wrappedKeyAad(header));
    const newVaultKey = await importAesKey(vekBytes);

    const data: VaultData = { ...current.data, updatedAt: now() };
    const payload = await encrypt(
      newVaultKey,
      utf8ToBytes(JSON.stringify(data)),
      payloadAad({ vaultId: file.vaultId, formatVersion: FORMAT_VERSION }),
    );

    return {
      file: { ...file, formatVersion: FORMAT_VERSION, kdf, wrappedKey, payload, updatedAt: data.updatedAt },
      session: {
        vaultId: file.vaultId,
        key: newVaultKey,
        data,
        unlockedAt: Date.now(),
        // Carried over: re-keying re-encrypts, it does not reinterpret the payload.
        foreignSchemaVersion: current.foreignSchemaVersion,
      },
    };
  } finally {
    zeroize(vekBytes);
  }
}

/**
 * Drop key material for a session. The CryptoKey itself is non-extractable and
 * becomes collectable once the caller releases its reference — this only clears
 * the decrypted data we control.
 */
export function lockSession(session: VaultSession): void {
  session.data = emptyVaultData();
  session.unlockedAt = 0;
}

// ---------------------------------------------------------------------------
// Migrations
// ---------------------------------------------------------------------------

/**
 * Bring a decrypted payload up to the model this build understands.
 *
 * A NEWER PAYLOAD IS NOT AN ERROR. It used to throw here, which meant one device
 * writing a new schema locked every not-yet-updated device out of the vault —
 * including a portable .exe someone had not replaced. Since the payload schemas
 * carry unrecognised fields through rather than rejecting them (see
 * validation.ts), a newer payload whose *known* fields still validate is
 * perfectly usable: we read what we understand and preserve the rest verbatim.
 *
 * `foreignSchemaVersion` on the session reports the gap so the UI can say which
 * way to point the user, since this build will not display or maintain whatever
 * those extra fields mean. A payload that genuinely fails validation still
 * throws, from `parseVaultData`.
 */
function migrate(data: VaultData): VaultData {
  // 1 → 2: sync needs deletions to be recorded rather than merely absent.
  const tombstones = data.tombstones ?? [];

  // Never stamp our own version onto a payload written by a newer build. The
  // fields we do not understand are still in there, and relabelling it as ours
  // would tell the next reader they are gone.
  const schemaVersion = Math.max(data.schemaVersion, SCHEMA_VERSION);

  return { ...data, tombstones, schemaVersion };
}

/** How far ahead of this build a payload is, or null when it is one we know. */
function foreignSchemaVersion(data: VaultData): number | null {
  return data.schemaVersion > SCHEMA_VERSION ? data.schemaVersion : null;
}

// ---------------------------------------------------------------------------
// CRUD over the decrypted model
// ---------------------------------------------------------------------------

export interface EntryInput {
  title: string;
  kind?: Entry['kind'];
  username?: string;
  password?: string;
  urls?: string[];
  notes?: string;
  tags?: string[];
  folderId?: string | null;
  totpSecret?: string | null;
  totpConfig?: TotpConfig | null;
  customFields?: CustomField[];
  attachments?: Attachment[];
}

/** Bytes used by attachments across the vault (pre-base64). */
export function vaultAttachmentBytes(data: VaultData): number {
  return data.entries.reduce(
    (sum, entry) => sum + entry.attachments.reduce((s, a) => s + a.sizeBytes, 0),
    0,
  );
}

function assertAttachmentsWithinBudget(data: VaultData): void {
  for (const entry of data.entries) {
    for (const att of entry.attachments) {
      if (att.sizeBytes > MAX_ATTACHMENT_BYTES) {
        throw new ValidationError(
          `Attachment "${att.name}" is too large (max ${MAX_ATTACHMENT_BYTES} bytes per file).`,
        );
      }
    }
  }
  if (vaultAttachmentBytes(data) > MAX_ATTACHMENTS_VAULT_BYTES) {
    throw new ValidationError(
      `Attachments would exceed the vault budget of ${MAX_ATTACHMENTS_VAULT_BYTES} bytes.`,
    );
  }
}

export function createEntry(data: VaultData, input: EntryInput): { data: VaultData; entry: Entry } {
  if (input.title.trim().length === 0) throw new ValidationError('Entry title must not be empty.');
  const timestamp = now();
  const entry: Entry = {
    id: randomUuid(),
    kind: input.kind ?? 'login',
    title: input.title.trim(),
    username: input.username ?? '',
    password: input.password ?? '',
    urls: input.urls ?? [],
    notes: input.notes ?? '',
    tags: input.tags ?? [],
    folderId: input.folderId ?? null,
    totpSecret: input.totpSecret ?? null,
    totpConfig: input.totpConfig ?? null,
    customFields: input.customFields ?? [],
    attachments: input.attachments ?? [],
    createdAt: timestamp,
    updatedAt: timestamp,
    passwordUpdatedAt: timestamp,
    history: [],
    deletedAt: null,
  };
  const next = { ...data, entries: [...data.entries, entry] };
  assertAttachmentsWithinBudget(next);
  return { data: next, entry };
}

/**
 * Push a superseded password onto an entry's history, newest first.
 *
 * Deduplicated on (changedAt, password) — the *same key `mergeHistory` uses*, and
 * deliberately so. Keying on `changedAt` alone looks equivalent but is not: two
 * rotations landing in the same millisecond would collapse into one row here while
 * the merge kept both, so two devices could disagree about the same entry's
 * history depending only on how fast the user clicked.
 */
function rememberPassword(
  history: readonly PasswordHistoryEntry[],
  previousPassword: string,
  changedAt: string,
): PasswordHistoryEntry[] {
  // Nothing to remember for an entry that never had a password.
  if (previousPassword.length === 0) return [...history];
  const duplicate = (h: PasswordHistoryEntry): boolean =>
    h.changedAt === changedAt && h.password === previousPassword;
  const next = [{ password: previousPassword, changedAt }, ...history.filter((h) => !duplicate(h))];
  return next.slice(0, PASSWORD_HISTORY_LIMIT);
}

export function updateEntry(data: VaultData, id: string, patch: Partial<EntryInput>): VaultData {
  const index = data.entries.findIndex((e) => e.id === id);
  if (index === -1) throw new ValidationError(`No entry with id ${id}.`);
  const existing = data.entries[index]!;

  const passwordChanged = patch.password !== undefined && patch.password !== existing.password;
  const changedAt = now();
  const updated: Entry = {
    ...existing,
    ...(passwordChanged ? { history: rememberPassword(existing.history, existing.password, changedAt) } : {}),
    ...(patch.kind !== undefined ? { kind: patch.kind } : {}),
    ...(patch.title !== undefined ? { title: patch.title.trim() } : {}),
    ...(patch.username !== undefined ? { username: patch.username } : {}),
    ...(patch.password !== undefined ? { password: patch.password } : {}),
    ...(patch.urls !== undefined ? { urls: patch.urls } : {}),
    ...(patch.notes !== undefined ? { notes: patch.notes } : {}),
    ...(patch.tags !== undefined ? { tags: patch.tags } : {}),
    ...(patch.folderId !== undefined ? { folderId: patch.folderId } : {}),
    ...(patch.totpSecret !== undefined ? { totpSecret: patch.totpSecret } : {}),
    ...(patch.totpConfig !== undefined ? { totpConfig: patch.totpConfig } : {}),
    ...(patch.customFields !== undefined ? { customFields: patch.customFields } : {}),
    ...(patch.attachments !== undefined ? { attachments: patch.attachments } : {}),
    updatedAt: changedAt,
    passwordUpdatedAt: passwordChanged ? changedAt : existing.passwordUpdatedAt,
  };
  if (updated.title.length === 0) throw new ValidationError('Entry title must not be empty.');

  const entries = [...data.entries];
  entries[index] = updated;
  const next = { ...data, entries };
  assertAttachmentsWithinBudget(next);
  return next;
}

/**
 * Move an entry to the trash. Reversible with `restoreEntry`.
 *
 * This used to remove the entry and write a tombstone, which propagated the
 * deletion to every synced device: one misclick, gone everywhere, with the vault
 * often the only copy. A soft delete is an ordinary field change, so it merges by
 * last-write-wins like any other edit and needs no new sync rules — and restoring
 * is just another edit. `purgeEntry` is what actually destroys anything.
 */
export function deleteEntry(data: VaultData, id: string): VaultData {
  const index = data.entries.findIndex((e) => e.id === id);
  if (index === -1) throw new ValidationError(`No entry with id ${id}.`);
  const existing = data.entries[index]!;
  if (existing.deletedAt !== null) return data;

  const timestamp = now();
  const entries = [...data.entries];
  entries[index] = { ...existing, deletedAt: timestamp, updatedAt: timestamp };
  return { ...data, entries };
}

/**
 * Move several entries to the trash as one edit.
 *
 * Not a loop over `deleteEntry` at the call site, for two reasons. Every mutation
 * in the app re-encrypts and writes the whole vault, so N calls are N saves — and
 * a failure halfway through leaves a batch the user asked for as one action
 * half-applied. And they share a single `deletedAt`, so the trash shows them as
 * the one sweep it was rather than N timestamps a few milliseconds apart.
 *
 * Unknown or already-trashed ids are skipped rather than thrown on: the caller is
 * typically acting on a list built a moment earlier (a health report), and an
 * entry that a sync has since removed is already in the state this asks for.
 * Failing the whole batch over it would drop the deletions that are still valid.
 */
export function deleteEntries(data: VaultData, ids: readonly string[]): VaultData {
  const wanted = new Set(ids);
  if (wanted.size === 0) return data;
  if (!data.entries.some((e) => wanted.has(e.id) && e.deletedAt === null)) return data;

  const timestamp = now();
  return {
    ...data,
    entries: data.entries.map((e) =>
      wanted.has(e.id) && e.deletedAt === null ? { ...e, deletedAt: timestamp, updatedAt: timestamp } : e,
    ),
  };
}

/** Take an entry back out of the trash. */
export function restoreEntry(data: VaultData, id: string): VaultData {
  const index = data.entries.findIndex((e) => e.id === id);
  if (index === -1) throw new ValidationError(`No entry with id ${id}.`);
  const existing = data.entries[index]!;
  if (existing.deletedAt === null) return data;

  const entries = [...data.entries];
  entries[index] = { ...existing, deletedAt: null, updatedAt: now() };
  return { ...data, entries };
}

/**
 * Destroy an entry for good, on every device.
 *
 * This is the old `deleteEntry`: removal plus a tombstone so peers do not
 * resurrect it. Nothing calls it by accident — it is "delete forever" in the
 * trash, and the automatic sweep below.
 */
export function purgeEntry(data: VaultData, id: string): VaultData {
  if (!data.entries.some((e) => e.id === id)) throw new ValidationError(`No entry with id ${id}.`);
  return {
    ...data,
    entries: data.entries.filter((e) => e.id !== id),
    tombstones: recordTombstone(data.tombstones, { id, kind: 'entry', deletedAt: now() }),
  };
}

/**
 * Purge anything that has sat in the trash past `TRASH_RETENTION_DAYS`.
 *
 * The window is well inside `TOMBSTONE_TTL_DAYS` (180), so the tombstone a purge
 * writes still has months to reach every device before it is pruned — otherwise a
 * device that had been offline would resurrect the entry it never saw deleted.
 */
export function purgeExpiredTrash(data: VaultData, nowMs: number = Date.now()): VaultData {
  const cutoff = nowMs - TRASH_RETENTION_DAYS * 24 * 60 * 60 * 1000;
  const expired = data.entries.filter((e) => {
    if (e.deletedAt === null) return false;
    const deletedAtMs = Date.parse(e.deletedAt);
    return Number.isFinite(deletedAtMs) && deletedAtMs < cutoff;
  });
  if (expired.length === 0) return data;

  const timestamp = new Date(nowMs).toISOString();
  return {
    ...data,
    entries: data.entries.filter((e) => !expired.some((x) => x.id === e.id)),
    tombstones: expired.reduce(
      (acc, entry) => recordTombstone(acc, { id: entry.id, kind: 'entry', deletedAt: timestamp }),
      data.tombstones,
    ),
  };
}

/** Replace any prior tombstone for the same id, so the newest deletion wins. */
function recordTombstone(existing: Tombstone[], next: Tombstone): Tombstone[] {
  return [...existing.filter((t) => !(t.id === next.id && t.kind === next.kind)), next];
}

export function getEntry(data: VaultData, id: string): Entry | undefined {
  return data.entries.find((e) => e.id === id);
}

export function createFolder(data: VaultData, name: string): { data: VaultData; folder: Folder } {
  const trimmed = name.trim();
  if (trimmed.length === 0) throw new ValidationError('Folder name must not be empty.');
  const folder: Folder = { id: randomUuid(), name: trimmed, createdAt: now() };
  return { data: { ...data, folders: [...data.folders, folder] }, folder };
}

/** Deleting a folder orphans its entries rather than deleting them. Never lose secrets implicitly. */
export function deleteFolder(data: VaultData, id: string): VaultData {
  return {
    ...data,
    folders: data.folders.filter((f) => f.id !== id),
    entries: data.entries.map((e) => (e.folderId === id ? { ...e, folderId: null } : e)),
    tombstones: recordTombstone(data.tombstones, { id, kind: 'folder', deletedAt: now() }),
  };
}

export function updateSettings(data: VaultData, patch: Partial<Settings>): VaultData {
  return { ...data, settings: { ...data.settings, ...patch } };
}

// ---------------------------------------------------------------------------
// Search
// ---------------------------------------------------------------------------

/**
 * Substring match over title, username, URLs and tags.
 * Passwords are never searched. Notes are searched only for `kind: 'note'`
 * entries — that is their primary content — not for login credentials.
 */
/** Live entries only — the trash is reached through `trashedEntries`. */
export function liveEntries(data: VaultData): Entry[] {
  return data.entries.filter((e) => e.deletedAt === null);
}

/** What is currently in the trash, most recently deleted first. */
export function trashedEntries(data: VaultData): Entry[] {
  return data.entries
    .filter((e) => e.deletedAt !== null)
    .sort((a, b) => (b.deletedAt ?? '').localeCompare(a.deletedAt ?? ''));
}

export function searchEntries(data: VaultData, query: string): Entry[] {
  const q = query.trim().toLowerCase();
  const live = liveEntries(data);
  if (q.length === 0) return live.sort(byTitle);
  return live
    .filter((e) => {
      return (
        e.title.toLowerCase().includes(q) ||
        e.username.toLowerCase().includes(q) ||
        e.tags.some((t) => t.toLowerCase().includes(q)) ||
        e.urls.some((u) => u.toLowerCase().includes(q)) ||
        // Labels only — never values, matching the rule that passwords are never searched.
        e.customFields.some((f) => f.label.toLowerCase().includes(q)) ||
        (e.kind === 'note' && e.notes.toLowerCase().includes(q))
      );
    })
    .sort(byTitle);
}

function byTitle(a: Entry, b: Entry): number {
  return a.title.localeCompare(b.title, undefined, { sensitivity: 'base' });
}
