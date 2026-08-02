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
  recoveryAad,
  wrappedKeyAad,
  zeroize,
  type KdfPresetName,
} from './crypto.ts';
import { formatSecret, generateSecretKeyBytes, parseSecret, type SecretKind } from './secret-key.ts';
import { bytesToUtf8, utf8ToBytes } from './encoding.ts';
import { UnsupportedVersionError, ValidationError, VaultFormatError } from './errors.ts';
import { DEFAULT_GENERATOR_OPTIONS } from './password-gen.ts';
import {
  DEFAULT_NEW_VAULT_FORMAT_VERSION,
  FORMAT_VERSION,
  SECRET_KEY_FORMAT_VERSION,
  MAX_ATTACHMENT_BYTES,
  MAX_ATTACHMENTS_VAULT_BYTES,
  PASSWORD_HISTORY_LIMIT,
  SCHEMA_VERSION,
  TRASH_RETENTION_DAYS,
  VAULT_FORMAT_ID,
  type Attachment,
  type CustomField,
  type EncryptedBlob,
  type Entry,
  type KdfParams,
  type PasskeyRecord,
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

/**
 * The two halves of a printed Recovery Kit.
 *
 * Returned exactly once, at the moment they are minted, and never recoverable from
 * the envelope afterwards. A caller that drops this object has thrown away the
 * user's only recovery path — surfaces must render it before persisting anything.
 */
export interface RecoveryKit {
  /**
   * Formatted Secret Key. Stored on each device (OS keychain / `safeStorage` /
   * `chrome.storage.local`) *and* printed, since a device loss otherwise takes the
   * vault with it.
   */
  secretKey: string;
  /**
   * Formatted Recovery Code. Printed only. Keyhole never stores this anywhere, on
   * any surface — that is precisely what keeps it a recovery path rather than a
   * backdoor.
   */
  recoveryCode: string;
}

/** A Secret Key or Recovery Code as bytes, or as the string a user typed. */
export type SecretInput = Uint8Array | string;

function toSecretBytes(kind: SecretKind, input: SecretInput): Uint8Array {
  // Always a fresh copy. Everything here zeroizes its key material on the way out,
  // and doing that to a buffer the caller still owns would wipe *their* Secret Key
  // — silently, and only visibly on the second unlock.
  return typeof input === 'string' ? parseSecret(kind, input) : Uint8Array.from(input);
}

export interface CreateVaultOptions {
  kdfPreset?: KdfPresetName;
  initialData?: VaultData;
  /**
   * Envelope version to write. Defaults to `DEFAULT_NEW_VAULT_FORMAT_VERSION`.
   * Pass 2 only from a surface that can both persist the Secret Key and show the
   * Recovery Kit to the user.
   */
  formatVersion?: 1 | 2;
}

/**
 * Build a brand-new encrypted vault. Returns the envelope (to persist), an
 * unlocked session — so the caller does not have to immediately re-run the KDF
 * just to use the vault it created — and, for format 2, the Recovery Kit.
 */
export async function createVault(
  masterPassword: string,
  options: CreateVaultOptions = {},
): Promise<{ file: VaultFile; session: VaultSession; kit: RecoveryKit | null }> {
  assertMasterPasswordAcceptable(masterPassword);

  const formatVersion = options.formatVersion ?? DEFAULT_NEW_VAULT_FORMAT_VERSION;
  const vaultId = randomUuid();
  const kdf = defaultKdfParams(options.kdfPreset ?? 'interactive');
  const header = { vaultId, formatVersion, kdf };

  const bound = formatVersion >= SECRET_KEY_FORMAT_VERSION;
  const secretKeyBytes = bound ? generateSecretKeyBytes() : undefined;
  const recoveryCodeBytes = bound ? generateSecretKeyBytes() : undefined;

  const masterKey = await deriveMasterKey(masterPassword, kdf, secretKeyBytes);
  const vekBytes = generateVaultKeyBytes();
  try {
    const wrappedKey = await encrypt(masterKey, vekBytes, wrappedKeyAad(header));
    const vaultKey = await importAesKey(vekBytes);

    const data = options.initialData ?? emptyVaultData();
    const payload = await encrypt(vaultKey, utf8ToBytes(JSON.stringify(data)), payloadAad(header));

    const recovery = recoveryCodeBytes
      ? await wrapForRecovery(vekBytes, recoveryCodeBytes, header, options.kdfPreset)
      : undefined;

    const timestamp = now();
    const file: VaultFile = {
      format: VAULT_FORMAT_ID,
      formatVersion,
      vaultId,
      createdAt: timestamp,
      updatedAt: timestamp,
      kdf,
      wrappedKey,
      payload,
      ...recovery,
    };
    return {
      file,
      session: { vaultId, key: vaultKey, data, unlockedAt: Date.now(), foreignSchemaVersion: null },
      kit:
        secretKeyBytes && recoveryCodeBytes
          ? {
              secretKey: formatSecret('secret-key', secretKeyBytes),
              recoveryCode: formatSecret('recovery-code', recoveryCodeBytes),
            }
          : null,
    };
  } finally {
    zeroize(vekBytes, secretKeyBytes, recoveryCodeBytes);
  }
}

/**
 * Wrap the VEK a second time under a Recovery Code.
 *
 * Argon2id over a 128-bit uniformly random code buys no meaningful search
 * resistance — the same argument the sync server makes for hashing its verifier
 * with a single SHA-256. It is used anyway because it costs one run on a path taken
 * at most once per vault, and because carrying real KDF params in the format is
 * what would let a future version accept a user-chosen recovery passphrase without
 * another envelope version.
 */
async function wrapForRecovery(
  vekBytes: Uint8Array,
  recoveryCodeBytes: Uint8Array,
  header: { vaultId: string; formatVersion: number },
  kdfPreset?: KdfPresetName,
): Promise<{ recoveryKdf: KdfParams; recoveryWrappedKey: EncryptedBlob }> {
  const recoveryKdf = defaultKdfParams(kdfPreset ?? 'interactive');
  const recoveryKey = await deriveMasterKey(formatSecret('recovery-code', recoveryCodeBytes), recoveryKdf);
  return {
    recoveryKdf,
    recoveryWrappedKey: await encrypt(recoveryKey, vekBytes, recoveryAad(header, recoveryKdf)),
  };
}

/** True when this envelope cannot be unlocked without a Secret Key. */
export function vaultRequiresSecretKey(file: Pick<VaultFile, 'formatVersion'>): boolean {
  return file.formatVersion >= SECRET_KEY_FORMAT_VERSION;
}

/** True when a Recovery Kit was issued for this envelope and can still open it. */
export function vaultHasRecoveryKit(file: Pick<VaultFile, 'recoveryWrappedKey'>): boolean {
  return file.recoveryWrappedKey !== undefined;
}

/**
 * Unlock an envelope with a master password.
 *
 * Fail-closed ordering matters here: the VEK unwrap runs first, so a wrong
 * password throws before we ever touch the payload ciphertext. No partial state
 * is constructed on any failure path.
 */
export async function unlockVault(
  file: unknown,
  masterPassword: string,
  secretKey?: SecretInput,
): Promise<VaultSession> {
  const parsed = parseVaultFile(file);
  if (parsed.formatVersion > FORMAT_VERSION) {
    throw new UnsupportedVersionError(
      `This vault was written by a newer version of Keyhole (format ${parsed.formatVersion}). Please update.`,
    );
  }

  // Checked before the KDF runs so the two "you gave us the wrong thing" cases are
  // named, rather than both surfacing 105 ms later as an indistinguishable bad tag.
  if (vaultRequiresSecretKey(parsed) && secretKey === undefined) {
    throw new ValidationError('This vault needs its Secret Key as well as the master password.');
  }
  if (!vaultRequiresSecretKey(parsed) && secretKey !== undefined) {
    throw new ValidationError('This vault does not use a Secret Key.');
  }

  const header = { vaultId: parsed.vaultId, formatVersion: parsed.formatVersion, kdf: parsed.kdf };
  const secretKeyBytes = secretKey === undefined ? undefined : toSecretBytes('secret-key', secretKey);
  let vekBytes: Uint8Array;
  try {
    const masterKey = await deriveMasterKey(masterPassword, parsed.kdf, secretKeyBytes);
    // Throws DecryptionError on a wrong password — the GCM tag is the verifier.
    vekBytes = await decrypt(masterKey, parsed.wrappedKey, wrappedKeyAad(header));
  } finally {
    zeroize(secretKeyBytes);
  }

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
  options: { kdfPreset?: KdfPresetName; secretKey?: SecretInput } = {},
): Promise<{ file: VaultFile; session: VaultSession; kit: RecoveryKit | null }> {
  assertMasterPasswordAcceptable(newPassword);

  // Verifies the current password by unlocking; throws before anything mutates.
  const current = await unlockVault(file, currentPassword, options.secretKey);

  // The envelope version never changes here: a password change must not silently
  // upgrade a vault into needing a Secret Key. `upgradeToV2` is the explicit path.
  const formatVersion = file.formatVersion;
  const kdf = defaultKdfParams(options.kdfPreset ?? 'interactive');
  const header = { vaultId: file.vaultId, formatVersion, kdf };

  const secretKeyBytes =
    options.secretKey === undefined ? undefined : toSecretBytes('secret-key', options.secretKey);

  const vekBytes = generateVaultKeyBytes();
  // Reissued rather than preserved — see the note below.
  const recoveryCodeBytes = vaultHasRecoveryKit(file) ? generateSecretKeyBytes() : undefined;

  try {
    const newMasterKey = await deriveMasterKey(newPassword, kdf, secretKeyBytes);
    const wrappedKey = await encrypt(newMasterKey, vekBytes, wrappedKeyAad(header));
    const newVaultKey = await importAesKey(vekBytes);

    const data: VaultData = { ...current.data, updatedAt: now() };
    const payload = await encrypt(
      newVaultKey,
      utf8ToBytes(JSON.stringify(data)),
      payloadAad({ vaultId: file.vaultId, formatVersion }),
    );

    /*
     * THE RECOVERY BLOB MUST NOT SURVIVE THIS UNTOUCHED.
     *
     * `{ ...file }` below carries every field we do not name, and until format 2
     * that was exactly right. It no longer is: `recoveryWrappedKey` wraps the VEK,
     * this function rotates the VEK, and so a carried-over blob decrypts to a key
     * that no longer opens anything. The vault would keep working perfectly and the
     * Recovery Kit would be dead — discovered only by someone who has already
     * forgotten their password and has nothing else left to try.
     *
     * We cannot re-wrap the *existing* code: it lives only on the user's printout,
     * by design. So the kit is reissued, and the caller is handed a new one it is
     * obliged to show. The old printout stops working, which is the honest outcome
     * — a rotated VEK genuinely invalidates it, and saying so beats a kit that
     * looks valid and is not.
     */
    // `{}` rather than explicit undefineds: `recoveryCodeBytes` is unset only when
    // the vault had no kit to begin with, so there is nothing for `...file` to carry
    // through and nothing to blank out.
    const recovery =
      recoveryCodeBytes === undefined
        ? {}
        : await wrapForRecovery(vekBytes, recoveryCodeBytes, header, options.kdfPreset);

    return {
      file: {
        ...file,
        formatVersion,
        kdf,
        wrappedKey,
        payload,
        updatedAt: data.updatedAt,
        ...recovery,
      },
      session: {
        vaultId: file.vaultId,
        key: newVaultKey,
        data,
        unlockedAt: Date.now(),
        // Carried over: re-keying re-encrypts, it does not reinterpret the payload.
        foreignSchemaVersion: current.foreignSchemaVersion,
      },
      kit:
        recoveryCodeBytes && options.secretKey !== undefined
          ? {
              // Unchanged: the Secret Key is a device factor, independent of the
              // password. Reprinting the kit must still show it, since the two
              // halves are useless apart.
              secretKey: formatSecret('secret-key', toSecretBytes('secret-key', options.secretKey)),
              recoveryCode: formatSecret('recovery-code', recoveryCodeBytes),
            }
          : null,
    };
  } finally {
    zeroize(vekBytes, secretKeyBytes, recoveryCodeBytes);
  }
}

/**
 * Upgrade a format-1 vault to format 2: bind it to a fresh Secret Key and issue a
 * Recovery Kit.
 *
 * The VEK is rotated, not reused. Reusing it would leave the pre-upgrade envelope —
 * which anyone who copied it can still attack with the password alone — holding a
 * key that decrypts everything written *after* the upgrade. Rotating means the old
 * copy ages into a snapshot rather than a live key, which is the entire point of
 * upgrading.
 */
export async function upgradeToV2(
  file: VaultFile,
  masterPassword: string,
  options: { kdfPreset?: KdfPresetName } = {},
): Promise<{ file: VaultFile; session: VaultSession; kit: RecoveryKit }> {
  if (file.formatVersion >= SECRET_KEY_FORMAT_VERSION) {
    throw new ValidationError('This vault already uses a Secret Key.');
  }

  const current = await unlockVault(file, masterPassword);

  const formatVersion = SECRET_KEY_FORMAT_VERSION;
  const kdf = defaultKdfParams(options.kdfPreset ?? 'interactive');
  const header = { vaultId: file.vaultId, formatVersion, kdf };

  const secretKeyBytes = generateSecretKeyBytes();
  const recoveryCodeBytes = generateSecretKeyBytes();
  const vekBytes = generateVaultKeyBytes();

  try {
    const masterKey = await deriveMasterKey(masterPassword, kdf, secretKeyBytes);
    const wrappedKey = await encrypt(masterKey, vekBytes, wrappedKeyAad(header));
    const vaultKey = await importAesKey(vekBytes);

    const data: VaultData = { ...current.data, updatedAt: now() };
    const payload = await encrypt(
      vaultKey,
      utf8ToBytes(JSON.stringify(data)),
      payloadAad({ vaultId: file.vaultId, formatVersion }),
    );
    const recovery = await wrapForRecovery(vekBytes, recoveryCodeBytes, header, options.kdfPreset);

    return {
      file: { ...file, formatVersion, kdf, wrappedKey, payload, updatedAt: data.updatedAt, ...recovery },
      session: {
        vaultId: file.vaultId,
        key: vaultKey,
        data,
        unlockedAt: Date.now(),
        foreignSchemaVersion: current.foreignSchemaVersion,
      },
      kit: {
        secretKey: formatSecret('secret-key', secretKeyBytes),
        recoveryCode: formatSecret('recovery-code', recoveryCodeBytes),
      },
    };
  } finally {
    zeroize(vekBytes, secretKeyBytes, recoveryCodeBytes);
  }
}

/**
 * Open a vault with the Recovery Code alone — no master password, no Secret Key.
 *
 * Read access only; the envelope is unchanged. `recoverWithKit` is what actually
 * returns the vault to a usable state.
 *
 * Note what this implies, and say it plainly in any UI that prints a kit: the
 * Recovery Code is on its own equivalent to the vault. The printout is not a hint
 * or a backup password — it is the vault, on paper, and belongs wherever a passport
 * would go. No arrangement of this format can be otherwise while still offering
 * recovery to someone who has forgotten everything else.
 */
export async function unlockWithRecoveryCode(file: unknown, recoveryCode: SecretInput): Promise<VaultSession> {
  const parsed = parseVaultFile(file);
  if (parsed.formatVersion > FORMAT_VERSION) {
    throw new UnsupportedVersionError(
      `This vault was written by a newer version of Keyhole (format ${parsed.formatVersion}). Please update.`,
    );
  }
  if (parsed.recoveryWrappedKey === undefined || parsed.recoveryKdf === undefined) {
    throw new ValidationError('No Recovery Kit was issued for this vault.');
  }

  const codeBytes = toSecretBytes('recovery-code', recoveryCode);
  let vekBytes: Uint8Array;
  try {
    const recoveryKey = await deriveMasterKey(formatSecret('recovery-code', codeBytes), parsed.recoveryKdf);
    vekBytes = await decrypt(
      recoveryKey,
      parsed.recoveryWrappedKey,
      recoveryAad({ vaultId: parsed.vaultId, formatVersion: parsed.formatVersion }, parsed.recoveryKdf),
    );
  } finally {
    zeroize(codeBytes);
  }

  let vaultKey: CryptoKey;
  try {
    vaultKey = await importAesKey(vekBytes);
  } finally {
    zeroize(vekBytes);
  }

  const plaintext = await decrypt(
    vaultKey,
    parsed.payload,
    payloadAad({ vaultId: parsed.vaultId, formatVersion: parsed.formatVersion }),
  );
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
 * The full recovery flow: open with the Recovery Code, set a new master password,
 * and issue a replacement kit.
 *
 * A fresh Secret Key is minted rather than the old one being carried across. The
 * user is already re-establishing this vault everywhere, the previous envelope and
 * key pair are retired together, and requiring the old Secret Key here would mean
 * asking for a second thing from a person who has just proved they lost track of
 * the first. The cost is that every other device must be given the new Secret Key —
 * which is what the reissued kit is for.
 */
export async function recoverWithKit(
  file: VaultFile,
  recoveryCode: SecretInput,
  newPassword: string,
  options: { kdfPreset?: KdfPresetName } = {},
): Promise<{ file: VaultFile; session: VaultSession; kit: RecoveryKit }> {
  assertMasterPasswordAcceptable(newPassword);

  const current = await unlockWithRecoveryCode(file, recoveryCode);

  const formatVersion = Math.max(file.formatVersion, SECRET_KEY_FORMAT_VERSION);
  const kdf = defaultKdfParams(options.kdfPreset ?? 'interactive');
  const header = { vaultId: file.vaultId, formatVersion, kdf };

  const secretKeyBytes = generateSecretKeyBytes();
  const recoveryCodeBytes = generateSecretKeyBytes();
  const vekBytes = generateVaultKeyBytes();

  try {
    const masterKey = await deriveMasterKey(newPassword, kdf, secretKeyBytes);
    const wrappedKey = await encrypt(masterKey, vekBytes, wrappedKeyAad(header));
    const vaultKey = await importAesKey(vekBytes);

    const data: VaultData = { ...current.data, updatedAt: now() };
    const payload = await encrypt(
      vaultKey,
      utf8ToBytes(JSON.stringify(data)),
      payloadAad({ vaultId: file.vaultId, formatVersion }),
    );
    const recovery = await wrapForRecovery(vekBytes, recoveryCodeBytes, header, options.kdfPreset);

    return {
      file: { ...file, formatVersion, kdf, wrappedKey, payload, updatedAt: data.updatedAt, ...recovery },
      session: {
        vaultId: file.vaultId,
        key: vaultKey,
        data,
        unlockedAt: Date.now(),
        foreignSchemaVersion: current.foreignSchemaVersion,
      },
      kit: {
        secretKey: formatSecret('secret-key', secretKeyBytes),
        recoveryCode: formatSecret('recovery-code', recoveryCodeBytes),
      },
    };
  } finally {
    zeroize(vekBytes, secretKeyBytes, recoveryCodeBytes);
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
    passkeys: [],
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

/** Live passkeys whose relying party matches `rpId` (exact, case-insensitive). */
export function findPasskeys(
  data: VaultData,
  rpId: string,
): Array<{ entry: Entry; passkey: PasskeyRecord }> {
  const needle = rpId.toLowerCase();
  const out: Array<{ entry: Entry; passkey: PasskeyRecord }> = [];
  for (const entry of liveEntries(data)) {
    for (const passkey of entry.passkeys) {
      if (passkey.relyingPartyId.toLowerCase() === needle) out.push({ entry, passkey });
    }
  }
  return out;
}

/** Locate a passkey by its stored credential id (standard Base64). */
export function findPasskey(
  data: VaultData,
  credentialIdB64: string,
): { entry: Entry; passkey: PasskeyRecord } | undefined {
  for (const entry of liveEntries(data)) {
    const passkey = entry.passkeys.find((pk) => pk.credentialIdB64 === credentialIdB64);
    if (passkey) return { entry, passkey };
  }
  return undefined;
}

/**
 * Remove one passkey from an entry. Create/use stays on iOS AutoFill; desktop and
 * the extension only manage what is already stored.
 */
export function removePasskey(data: VaultData, entryId: string, passkeyId: string): VaultData {
  const index = data.entries.findIndex((e) => e.id === entryId);
  if (index === -1) throw new ValidationError(`No entry with id ${entryId}.`);
  const existing = data.entries[index]!;
  const nextPasskeys = existing.passkeys.filter((pk) => pk.id !== passkeyId);
  if (nextPasskeys.length === existing.passkeys.length) {
    throw new ValidationError(`No passkey with id ${passkeyId}.`);
  }
  const entries = [...data.entries];
  entries[index] = { ...existing, passkeys: nextPasskeys, updatedAt: now() };
  return { ...data, entries };
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
        // Relying-party host / usernames for synced passkeys — never private key material.
        e.passkeys.some(
          (pk) =>
            pk.relyingPartyId.toLowerCase().includes(q) ||
            pk.userName.toLowerCase().includes(q) ||
            pk.userDisplayName.toLowerCase().includes(q),
        ) ||
        (e.kind === 'note' && e.notes.toLowerCase().includes(q))
      );
    })
    .sort(byTitle);
}

function byTitle(a: Entry, b: Entry): number {
  return a.title.localeCompare(b.title, undefined, { sensitivity: 'base' });
}
