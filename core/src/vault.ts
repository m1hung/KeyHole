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
  SCHEMA_VERSION,
  VAULT_FORMAT_ID,
  type Entry,
  type Folder,
  type Settings,
  type Tombstone,
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
    return { file, session: { vaultId, key: vaultKey, data, unlockedAt: Date.now() } };
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

  return { vaultId: parsed.vaultId, key: vaultKey, data: migrate(data), unlockedAt: Date.now() };
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
      session: { vaultId: file.vaultId, key: newVaultKey, data, unlockedAt: Date.now() },
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

function migrate(data: VaultData): VaultData {
  if (data.schemaVersion > SCHEMA_VERSION) {
    throw new UnsupportedVersionError(`Vault schema ${data.schemaVersion} is newer than this build supports.`);
  }

  // 1 → 2: sync needs deletions to be recorded rather than merely absent.
  const tombstones = data.tombstones ?? [];

  return { ...data, tombstones, schemaVersion: SCHEMA_VERSION };
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
    createdAt: timestamp,
    updatedAt: timestamp,
    passwordUpdatedAt: timestamp,
  };
  return { data: { ...data, entries: [...data.entries, entry] }, entry };
}

export function updateEntry(data: VaultData, id: string, patch: Partial<EntryInput>): VaultData {
  const index = data.entries.findIndex((e) => e.id === id);
  if (index === -1) throw new ValidationError(`No entry with id ${id}.`);
  const existing = data.entries[index]!;

  const passwordChanged = patch.password !== undefined && patch.password !== existing.password;
  const updated: Entry = {
    ...existing,
    ...(patch.kind !== undefined ? { kind: patch.kind } : {}),
    ...(patch.title !== undefined ? { title: patch.title.trim() } : {}),
    ...(patch.username !== undefined ? { username: patch.username } : {}),
    ...(patch.password !== undefined ? { password: patch.password } : {}),
    ...(patch.urls !== undefined ? { urls: patch.urls } : {}),
    ...(patch.notes !== undefined ? { notes: patch.notes } : {}),
    ...(patch.tags !== undefined ? { tags: patch.tags } : {}),
    ...(patch.folderId !== undefined ? { folderId: patch.folderId } : {}),
    ...(patch.totpSecret !== undefined ? { totpSecret: patch.totpSecret } : {}),
    updatedAt: now(),
    passwordUpdatedAt: passwordChanged ? now() : existing.passwordUpdatedAt,
  };
  if (updated.title.length === 0) throw new ValidationError('Entry title must not be empty.');

  const entries = [...data.entries];
  entries[index] = updated;
  return { ...data, entries };
}

export function deleteEntry(data: VaultData, id: string): VaultData {
  if (!data.entries.some((e) => e.id === id)) throw new ValidationError(`No entry with id ${id}.`);
  return {
    ...data,
    entries: data.entries.filter((e) => e.id !== id),
    tombstones: recordTombstone(data.tombstones, { id, kind: 'entry', deletedAt: now() }),
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
export function searchEntries(data: VaultData, query: string): Entry[] {
  const q = query.trim().toLowerCase();
  if (q.length === 0) return [...data.entries].sort(byTitle);
  return data.entries
    .filter((e) => {
      return (
        e.title.toLowerCase().includes(q) ||
        e.username.toLowerCase().includes(q) ||
        e.tags.some((t) => t.toLowerCase().includes(q)) ||
        e.urls.some((u) => u.toLowerCase().includes(q)) ||
        (e.kind === 'note' && e.notes.toLowerCase().includes(q))
      );
    })
    .sort(byTitle);
}

function byTitle(a: Entry, b: Entry): number {
  return a.title.localeCompare(b.title, undefined, { sensitivity: 'base' });
}
