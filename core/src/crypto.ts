/**
 * Keyhole cryptography.
 *
 * Key hierarchy (two layers, deliberately):
 *
 *   master password ──Argon2id(salt, params)──▶ Master Key (MK, 256-bit)
 *                                                   │
 *                                                   │ AES-256-GCM wrap
 *                                                   ▼
 *                        random Vault Encryption Key (VEK, 256-bit)
 *                                                   │
 *                                                   │ AES-256-GCM
 *                                                   ▼
 *                                       VaultData JSON payload
 *
 * Why two layers rather than encrypting the payload directly with the MK:
 *  1. Changing the master password rewraps a small blob instead of forcing a
 *     full re-encrypt (we still rotate the VEK on change — see `vault.ts` — but
 *     the separation keeps that a policy choice, not a structural constraint).
 *  2. Unlock cost is one KDF run plus one 60-byte unwrap. Verifying the master
 *     password does not require touching the whole payload.
 *  3. The GCM tag on `wrappedKey` *is* the password verifier. There is no
 *     separate check value, so a wrong password is indistinguishable from a
 *     corrupt file to an attacker — and we never decrypt anything on a bad
 *     password (fail closed).
 *
 * AES-GCM comes from WebCrypto (platform-audited, constant-time, hardware
 * accelerated). Argon2id comes from `hash-wasm` because no browser ships a
 * memory-hard KDF: WebCrypto offers only PBKDF2. See README for the full
 * justification of that dependency.
 */

import { argon2id } from 'hash-wasm';
import type { EncryptedBlob, KdfParams, VaultFile } from './types.ts';
import { DecryptionError, ValidationError } from './errors.ts';
import { b64ToBytes, bytesToB64, utf8ToBytes } from './encoding.ts';

// ---------------------------------------------------------------------------
// Parameters
// ---------------------------------------------------------------------------

export const CRYPTO = {
  /** 128-bit salt, per RFC 9106's recommendation. */
  SALT_BYTES: 16,
  /**
   * 96-bit nonce. This is the size AES-GCM is defined for; anything else forces
   * an extra GHASH derivation step and buys nothing. Every encryption generates
   * a fresh random nonce from the CSPRNG.
   */
  IV_BYTES: 12,
  /** AES-256. */
  KEY_BYTES: 32,
  /** Full-length GCM tag. */
  TAG_BITS: 128,
} as const;

export type KdfPresetName = 'interactive' | 'hardened';

/**
 * Cost presets. `interactive` measures ~105 ms on an M-series Mac and is the
 * default; `hardened` is ~4x that and is offered in settings for users who
 * accept the slower unlock.
 *
 * Both exceed the OWASP 2024 floor for Argon2id (19 MiB / t=2 / p=1).
 * `parallelism: 1` because hash-wasm executes single-threaded in the browser —
 * requesting more lanes would change the digest without buying real
 * concurrency.
 */
export const KDF_PRESETS: Record<KdfPresetName, Pick<KdfParams, 'memoryKiB' | 'iterations' | 'parallelism'>> = {
  interactive: { memoryKiB: 64 * 1024, iterations: 3, parallelism: 1 },
  hardened: { memoryKiB: 256 * 1024, iterations: 4, parallelism: 1 },
};

/** Reject KDF params weaker than this when *reading* a vault, to block downgrade attacks. */
export const KDF_MINIMUMS = { memoryKiB: 16 * 1024, iterations: 2, parallelism: 1 } as const;

// ---------------------------------------------------------------------------
// Randomness
// ---------------------------------------------------------------------------

function subtle(): SubtleCrypto {
  const c = globalThis.crypto;
  if (!c?.subtle) {
    throw new ValidationError('WebCrypto unavailable. Keyhole requires a secure context (https:// or localhost).');
  }
  return c.subtle;
}

/** Max bytes `getRandomValues` will fill in a single call, per the WebCrypto spec. */
const CSPRNG_CHUNK = 65536;

export function randomBytes(length: number): Uint8Array {
  const out = new Uint8Array(length);
  // getRandomValues throws QuotaExceededError above 64 KiB, so fill in chunks.
  for (let offset = 0; offset < length; offset += CSPRNG_CHUNK) {
    globalThis.crypto.getRandomValues(out.subarray(offset, Math.min(offset + CSPRNG_CHUNK, length)));
  }
  return out;
}

export function randomUuid(): string {
  return globalThis.crypto.randomUUID();
}

export function newSalt(): Uint8Array {
  return randomBytes(CRYPTO.SALT_BYTES);
}

/**
 * Best-effort scrub of a byte buffer.
 *
 * HONEST LIMITATION: this zeroes the one view we hold. It cannot reach copies
 * the JS engine made internally (string interning, GC relocation of the backing
 * store, WASM linear memory inside hash-wasm). Treat it as defence in depth
 * that shrinks the window, not as a guarantee that key material is gone from
 * process memory. Anything with a live memory-dump capability wins regardless —
 * that is explicitly outside the v1 threat model.
 */
export function zeroize(...buffers: Array<Uint8Array | undefined | null>): void {
  for (const buf of buffers) buf?.fill(0);
}

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

export function defaultKdfParams(preset: KdfPresetName = 'interactive'): KdfParams {
  const cost = KDF_PRESETS[preset];
  return {
    algorithm: 'argon2id',
    memoryKiB: cost.memoryKiB,
    iterations: cost.iterations,
    parallelism: cost.parallelism,
    saltB64: bytesToB64(newSalt()),
    keyLength: CRYPTO.KEY_BYTES,
  };
}

export function assertKdfParamsAcceptable(params: KdfParams): void {
  if (params.algorithm !== 'argon2id') {
    throw new ValidationError(`Unsupported KDF: ${String(params.algorithm)}`);
  }
  if (params.keyLength !== CRYPTO.KEY_BYTES) {
    throw new ValidationError(`Unsupported derived key length: ${params.keyLength}`);
  }
  // Downgrade guard: a tampered file must not be able to talk us into a cheap KDF.
  if (
    params.memoryKiB < KDF_MINIMUMS.memoryKiB ||
    params.iterations < KDF_MINIMUMS.iterations ||
    params.parallelism < KDF_MINIMUMS.parallelism
  ) {
    throw new ValidationError('Vault KDF parameters are below the minimum accepted cost.');
  }
  if (b64ToBytes(params.saltB64).length < CRYPTO.SALT_BYTES) {
    throw new ValidationError('Vault salt is too short.');
  }
}

/** Run the KDF and return its raw output. Caller MUST zeroize the result. */
async function argon2Root(masterPassword: string, params: KdfParams): Promise<Uint8Array> {
  assertKdfParamsAcceptable(params);
  if (masterPassword.length === 0) {
    throw new ValidationError('Master password must not be empty.');
  }

  const passwordBytes = utf8ToBytes(masterPassword);
  const salt = b64ToBytes(params.saltB64);
  try {
    return await argon2id({
      password: passwordBytes,
      salt,
      memorySize: params.memoryKiB,
      iterations: params.iterations,
      parallelism: params.parallelism,
      hashLength: params.keyLength,
      outputType: 'binary',
    });
  } finally {
    zeroize(passwordBytes);
  }
}

/**
 * master password → Argon2id → non-extractable AES-256-GCM CryptoKey.
 *
 * The derived bytes are imported and zeroed before returning. The resulting
 * CryptoKey is `extractable: false`, so even a same-origin XSS cannot read the
 * key back out — it can only ask the browser to use it.
 */
export async function deriveMasterKey(masterPassword: string, params: KdfParams): Promise<CryptoKey> {
  let derived: Uint8Array | undefined;
  try {
    derived = await argon2Root(masterPassword, params);
    return await importAesKey(derived);
  } finally {
    zeroize(derived);
  }
}

// ---------------------------------------------------------------------------
// Sync authentication
// ---------------------------------------------------------------------------

/**
 * HKDF label for the sync auth secret. Changing this string invalidates every
 * existing server credential, so it is versioned.
 */
const HKDF_INFO_SYNC_AUTH = 'keyhole/sync-auth/v1';

async function hkdfSha256(root: Uint8Array, salt: Uint8Array, info: string, byteLength: number): Promise<Uint8Array> {
  const key = await subtle().importKey('raw', toBufferSource(root), 'HKDF', false, ['deriveBits']);
  const bits = await subtle().deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: toBufferSource(salt), info: toBufferSource(utf8ToBytes(info)) },
    key,
    byteLength * 8,
  );
  return new Uint8Array(bits);
}

/**
 * The secret a device presents to a sync server, derived from the same
 * Argon2id output as the master key.
 *
 * WHY THIS SHAPE, and why the master-key path above is untouched:
 *
 *  - The master key is still `importAesKey(argon2Output)`, byte for byte what
 *    it always was. Interposing HKDF there would have changed every derived
 *    key and made every existing vault — including the published demo vault —
 *    permanently undecryptable. Sync is not worth bricking saved passwords.
 *
 *  - HKDF is one-way, so a server holding this secret cannot recover the
 *    Argon2id output and therefore cannot unwrap the VEK. Using the root
 *    directly as one key and as HKDF input for another is sound: HKDF-Extract
 *    is a PRF, so its output reveals nothing about its input.
 *
 *  - It grants the server no new offline advantage. Brute-forcing a password
 *    against this secret costs one Argon2id run per guess — exactly what
 *    brute-forcing it against the `wrappedKey` GCM tag already costs, and the
 *    server holds the envelope anyway.
 *
 * The HKDF salt is the vault's own KDF salt, so two vaults sharing a password
 * still produce unrelated auth secrets.
 */
export async function deriveSyncAuthSecret(masterPassword: string, params: KdfParams): Promise<string> {
  let root: Uint8Array | undefined;
  let secret: Uint8Array | undefined;
  try {
    root = await argon2Root(masterPassword, params);
    secret = await hkdfSha256(root, b64ToBytes(params.saltB64), HKDF_INFO_SYNC_AUTH, CRYPTO.KEY_BYTES);
    return bytesToB64(secret);
  } finally {
    zeroize(root, secret);
  }
}

/**
 * Both secrets from a single Argon2id run.
 *
 * Unlocking with sync enabled needs the master key *and* the auth secret;
 * deriving them separately would pay the ~105 ms memory-hard cost twice.
 */
export async function deriveKeyMaterial(
  masterPassword: string,
  params: KdfParams,
): Promise<{ masterKey: CryptoKey; syncAuthSecretB64: string }> {
  let root: Uint8Array | undefined;
  let secret: Uint8Array | undefined;
  try {
    root = await argon2Root(masterPassword, params);
    const masterKey = await importAesKey(root);
    secret = await hkdfSha256(root, b64ToBytes(params.saltB64), HKDF_INFO_SYNC_AUTH, CRYPTO.KEY_BYTES);
    return { masterKey, syncAuthSecretB64: bytesToB64(secret) };
  } finally {
    zeroize(root, secret);
  }
}

/** Import raw bytes as a non-extractable AES-GCM key. Caller zeroes `raw`. */
export async function importAesKey(raw: Uint8Array): Promise<CryptoKey> {
  if (raw.length !== CRYPTO.KEY_BYTES) {
    throw new ValidationError(`Expected a ${CRYPTO.KEY_BYTES}-byte key, got ${raw.length}.`);
  }
  return subtle().importKey('raw', toBufferSource(raw), { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

/** Fresh random 256-bit vault encryption key. Caller must zeroize. */
export function generateVaultKeyBytes(): Uint8Array {
  return randomBytes(CRYPTO.KEY_BYTES);
}

// ---------------------------------------------------------------------------
// AEAD
// ---------------------------------------------------------------------------

/**
 * WebCrypto types want an ArrayBuffer-backed view. A Uint8Array over a
 * SharedArrayBuffer would be rejected at runtime anyway, so narrowing here is
 * both type-correct and behaviour-preserving.
 */
function toBufferSource(bytes: Uint8Array): ArrayBuffer {
  const { buffer, byteOffset, byteLength } = bytes;
  if (byteOffset === 0 && byteLength === buffer.byteLength && buffer instanceof ArrayBuffer) {
    return buffer;
  }
  return bytes.slice().buffer as ArrayBuffer;
}

export async function encrypt(key: CryptoKey, plaintext: Uint8Array, aad: Uint8Array): Promise<EncryptedBlob> {
  const iv = randomBytes(CRYPTO.IV_BYTES);
  const ct = await subtle().encrypt(
    { name: 'AES-GCM', iv: toBufferSource(iv), additionalData: toBufferSource(aad), tagLength: CRYPTO.TAG_BITS },
    key,
    toBufferSource(plaintext),
  );
  return { ivB64: bytesToB64(iv), ctB64: bytesToB64(new Uint8Array(ct)) };
}

/**
 * Authenticated decrypt. Any failure — bad tag, bad AAD, malformed base64 —
 * collapses into a single `DecryptionError` carrying no detail about which
 * check failed, and no partial plaintext is ever returned.
 */
export async function decrypt(key: CryptoKey, blob: EncryptedBlob, aad: Uint8Array): Promise<Uint8Array> {
  try {
    const iv = b64ToBytes(blob.ivB64);
    if (iv.length !== CRYPTO.IV_BYTES) throw new DecryptionError();
    const ct = b64ToBytes(blob.ctB64);
    const pt = await subtle().decrypt(
      { name: 'AES-GCM', iv: toBufferSource(iv), additionalData: toBufferSource(aad), tagLength: CRYPTO.TAG_BITS },
      key,
      toBufferSource(ct),
    );
    return new Uint8Array(pt);
  } catch {
    throw new DecryptionError();
  }
}

// ---------------------------------------------------------------------------
// Associated data
// ---------------------------------------------------------------------------

/**
 * The envelope header is not secret, but it must be *authentic*. Binding it as
 * GCM associated data means an attacker cannot splice a `wrappedKey` from one
 * vault into another, nor edit the stored KDF cost, without the tag failing.
 *
 * Serialisation is an explicit fixed-order template rather than JSON.stringify,
 * because object key order is not a stable contract and a reordering would
 * silently make existing vaults undecryptable.
 */
export type VaultHeader = Pick<VaultFile, 'vaultId' | 'formatVersion' | 'kdf'>;

export function wrappedKeyAad(header: VaultHeader): Uint8Array {
  const { kdf } = header;
  return utf8ToBytes(
    [
      'keyhole.wrapkey.v1',
      header.vaultId,
      header.formatVersion,
      kdf.algorithm,
      kdf.memoryKiB,
      kdf.iterations,
      kdf.parallelism,
      kdf.keyLength,
      kdf.saltB64,
    ].join('|'),
  );
}

export function payloadAad(header: Pick<VaultFile, 'vaultId' | 'formatVersion'>): Uint8Array {
  // Intentionally excludes KDF params: rewrapping the VEK under a new master
  // password must not invalidate the payload ciphertext.
  return utf8ToBytes(['keyhole.payload.v1', header.vaultId, header.formatVersion].join('|'));
}
