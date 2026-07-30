/**
 * Keyhole core type definitions.
 *
 * Two distinct shapes matter here:
 *  - `VaultData`  — the *decrypted* model. Only ever exists in memory, unlocked.
 *  - `VaultFile`  — the *encrypted* envelope. This is what touches disk /
 *                   chrome.storage.local. It must never contain plaintext secrets.
 */

/** Current version of the decrypted vault model. Bump when `VaultData` changes shape. */
export const SCHEMA_VERSION = 3;

/**
 * Superseded passwords kept per entry, newest first.
 *
 * Capped because history is plaintext inside the sealed payload, exactly like
 * `password`: it is no more exposed than the current password, but it does grow
 * the payload, and nobody needs the twentieth-oldest password of an account.
 */
export const PASSWORD_HISTORY_LIMIT = 20;

/** How long a soft-deleted entry stays restorable before it is purged for real. */
export const TRASH_RETENTION_DAYS = 30;

/** Current version of the on-disk envelope. Bump when `VaultFile` changes shape. */
export const FORMAT_VERSION = 1;

/** Magic string identifying a Keyhole vault envelope. */
export const VAULT_FORMAT_ID = 'keyhole.vault';

// ---------------------------------------------------------------------------
// Decrypted model
// ---------------------------------------------------------------------------

/** Login credentials vs a free-form encrypted note (no autofill target). */
export type EntryKind = 'login' | 'note';

export interface PasswordHistoryEntry {
  /** The password this entry used to have. */
  password: string;
  /** When it stopped being the current one. Also the merge key — see sync.ts. */
  changedAt: string;
}

export interface Entry {
  id: string;
  /** Defaults to `login` for vaults created before this field existed. */
  kind: EntryKind;
  title: string;
  username: string;
  password: string;
  /** Origins/URLs used for autofill matching, e.g. "https://github.com/login". */
  urls: string[];
  notes: string;
  tags: string[];
  folderId: string | null;
  /** Base32 TOTP seed. Encrypted with the rest of the vault; codes derived in-memory only. */
  totpSecret: string | null;
  createdAt: string;
  updatedAt: string;
  /** Tracked separately from `updatedAt` so the UI can flag stale passwords. */
  passwordUpdatedAt: string;
  /**
   * Previous passwords, newest first, capped at `PASSWORD_HISTORY_LIMIT`.
   *
   * Exists because rotating a password is the one routine action that could
   * destroy a working credential with no way back: you change it here, the site
   * rejects the change, and the password that still works is gone. "No recovery,
   * no backdoor" makes that unrecoverable, so the old value is kept.
   */
  history: PasswordHistoryEntry[];
  /**
   * When the entry was moved to the trash, or null while it is live.
   *
   * A soft delete rather than a removal, because deleting is the other way to lose
   * a password for good — and with sync, one misclick removed it from every device
   * at once. `purgeEntry` is what actually destroys it.
   */
  deletedAt: string | null;
}

export interface Folder {
  id: string;
  name: string;
  createdAt: string;
}

/** Records a deletion for sync — peers must not resurrect what was removed. */
export interface Tombstone {
  id: string;
  kind: 'entry' | 'folder';
  deletedAt: string;
}

export interface GeneratorOptions {
  length: number;
  lowercase: boolean;
  uppercase: boolean;
  digits: boolean;
  symbols: boolean;
  /** Drop visually confusable glyphs: 0/O, 1/l/I, 5/S, 8/B. */
  excludeAmbiguous: boolean;
}

export interface Settings {
  /** Idle minutes before the vault locks itself. */
  autoLockMinutes: number;
  /** Seconds before a copied secret is cleared from the clipboard. */
  clipboardClearSeconds: number;
  generator: GeneratorOptions;
  theme: 'light' | 'dark' | 'system';
  /** Lock as soon as the browser/tab is hidden. Off by default: it is disruptive. */
  lockOnHide: boolean;
}

export interface VaultData {
  schemaVersion: number;
  entries: Entry[];
  folders: Folder[];
  tombstones: Tombstone[];
  settings: Settings;
  updatedAt: string;
}

// ---------------------------------------------------------------------------
// Encrypted envelope
// ---------------------------------------------------------------------------

export interface KdfParams {
  algorithm: 'argon2id';
  /** Memory cost in kibibytes. */
  memoryKiB: number;
  /** Time cost (passes). */
  iterations: number;
  /** Lanes. */
  parallelism: number;
  /** Random per-vault salt, base64. Not secret. */
  saltB64: string;
  /** Derived key length in bytes. */
  keyLength: number;
}

/**
 * AES-256-GCM output. `ctB64` is ciphertext with the 128-bit auth tag appended,
 * which is what WebCrypto's `encrypt` returns and what its `decrypt` expects.
 */
export interface EncryptedBlob {
  ivB64: string;
  ctB64: string;
}

export interface VaultFile {
  format: typeof VAULT_FORMAT_ID;
  formatVersion: number;
  vaultId: string;
  createdAt: string;
  updatedAt: string;
  kdf: KdfParams;
  /** The vault encryption key, wrapped with the Argon2id-derived master key. */
  wrappedKey: EncryptedBlob;
  /** `VaultData` as JSON, encrypted with the vault encryption key. */
  payload: EncryptedBlob;
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

/**
 * An unlocked vault session. `key` is a non-extractable CryptoKey — the raw key
 * bytes are zeroed immediately after import and are never retained anywhere.
 */
export interface VaultSession {
  vaultId: string;
  key: CryptoKey;
  data: VaultData;
  unlockedAt: number;
  /**
   * Set when the payload was written by a build newer than this one — the schema
   * version found, otherwise null.
   *
   * The vault is fully usable: unknown fields are preserved on save rather than
   * stripped. But this build will not show or maintain whatever they mean, so the
   * UI should say so instead of quietly presenting a partial view of the vault.
   */
  foreignSchemaVersion: number | null;
}

export type LockState = 'locked' | 'unlocked' | 'no-vault';
