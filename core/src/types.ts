/**
 * Keyhole core type definitions.
 *
 * Two distinct shapes matter here:
 *  - `VaultData`  — the *decrypted* model. Only ever exists in memory, unlocked.
 *  - `VaultFile`  — the *encrypted* envelope. This is what touches disk /
 *                   chrome.storage.local. It must never contain plaintext secrets.
 */

/** Current version of the decrypted vault model. Bump when `VaultData` changes shape. */
export const SCHEMA_VERSION = 5;

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

/**
 * Per-file ceiling for attachments inside the encrypted payload.
 *
 * Driven by the extension's 10 MB storage budget (refused above 9 MB) and the
 * sync envelope's 16 MB cap, after base64's +33% overhead — see ARCHITECTURE.
 */
export const MAX_ATTACHMENT_BYTES = 1 * 1024 * 1024;

/** Total attachment payload across the whole vault. */
export const MAX_ATTACHMENTS_VAULT_BYTES = 5 * 1024 * 1024;

/**
 * Highest envelope version this build can *read*.
 *
 *  1 — master password alone.
 *  2 — master password + a device-held Secret Key, with an optional Recovery Kit.
 */
export const FORMAT_VERSION = 2;

/**
 * Envelope version `createVault` writes by default.
 *
 * Deliberately trailing `FORMAT_VERSION`. A format-2 vault is unopenable without
 * the Secret Key, so minting one from a surface that has nowhere to store that key
 * and no UI to show the Recovery Kit would lock the user out of the vault they just
 * created — the exact failure this project treats as unacceptable. Each surface
 * opts in explicitly via `CreateVaultOptions.formatVersion`, and this default flips
 * to 2 once all of them do.
 */
export const DEFAULT_NEW_VAULT_FORMAT_VERSION = 1;

/** Envelope versions that bind derivation to a Secret Key. */
export const SECRET_KEY_FORMAT_VERSION = 2;

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

/**
 * Non-default TOTP parameters. `null` on the entry means the usual defaults
 * (6 digits, 30 s, SHA-1) — matching every issuer that never puts them in the URI.
 */
export interface TotpConfig {
  digits: number;
  periodSeconds: number;
  algorithm: 'SHA-1' | 'SHA-256' | 'SHA-512';
}

/** Free-form field on an entry. `secret: true` masks the value like a password. */
export interface CustomField {
  id: string;
  label: string;
  value: string;
  secret: boolean;
}

/**
 * File stored inside the encrypted payload. Size is gated by
 * `MAX_ATTACHMENT_BYTES` / `MAX_ATTACHMENTS_VAULT_BYTES`.
 */
export interface Attachment {
  id: string;
  name: string;
  mimeType: string;
  sizeBytes: number;
  dataB64: string;
}

/**
 * WebAuthn passkey sealed with the entry (P-256 private key + RP metadata).
 * Created on iOS AutoFill registration; synced so other devices keep the record.
 */
export interface PasskeyRecord {
  id: string;
  /** Credential ID as standard Base64. */
  credentialIdB64: string;
  relyingPartyId: string;
  relyingPartyName: string;
  userName: string;
  userDisplayName: string;
  /** User handle as standard Base64. */
  userHandleB64: string;
  /** P-256 private key raw bytes as standard Base64. */
  privateKeyB64: string;
  signCount: number;
  createdAt: string;
  lastUsedAt: string | null;
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
  /**
   * Digits / period / algorithm when they differ from the defaults. Null keeps
   * existing entries generating the same codes they always have.
   */
  totpConfig: TotpConfig | null;
  /** User-defined fields. Searchable by label, never by value. */
  customFields: CustomField[];
  /** Files sealed with the entry. Empty until the attachments UI is used. */
  attachments: Attachment[];
  /** Passkeys for this login (schema 5). Empty on older entries. */
  passkeys: PasskeyRecord[];
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
  /**
   * Opt-in Have I Been Pwned range checks. Off by default; never automatic —
   * one explicit click per check, and only the 5-character hash prefix leaves
   * the device. See `breach.ts` and the README threat-model row.
   */
  breachCheckEnabled: boolean;
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
  /**
   * KDF parameters for the Recovery Code. Format 2+, present iff a Recovery Kit
   * has been issued. Separate salt from `kdf` so the two derivations are unrelated.
   */
  // `| undefined` is load-bearing under `exactOptionalPropertyTypes`: these values
  // arrive from `parseVaultFile`, and zod's `.optional()` infers `T | undefined`
  // rather than a purely absent property. Without it every caller that round-trips a
  // parsed envelope back into a `VaultFile` fails to typecheck.
  recoveryKdf?: KdfParams | undefined;
  /**
   * The *same* vault encryption key, wrapped a second time under the Recovery Code.
   * Format 2+, paired with `recoveryKdf`.
   *
   * This is what makes "no recovery, no backdoor" survivable: it is a second door
   * to the same key, and the only thing that opens it is a code that exists solely
   * on paper in the user's possession. No server holds it, no third party is
   * trusted, and Keyhole itself cannot use it without being handed the printout.
   *
   * CRITICAL INVARIANT: it wraps the VEK, so anything that rotates the VEK must
   * re-wrap or clear it. See `changeMasterPassword`.
   */
  recoveryWrappedKey?: EncryptedBlob | undefined;
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
