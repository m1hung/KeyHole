import { describe, expect, it } from 'vitest';
import { argon2id as nobleArgon2id } from '@noble/hashes/argon2.js';
import {
  CRYPTO,
  KDF_PRESETS,
  assertKdfParamsAcceptable,
  decrypt,
  defaultKdfParams,
  deriveMasterKey,
  encrypt,
  generateVaultKeyBytes,
  importAesKey,
  payloadAad,
  randomBytes,
  wrappedKeyAad,
  zeroize,
} from '../src/crypto.ts';
import { b64ToBytes, bytesToB64, bytesToHex, timingSafeEqual, utf8ToBytes } from '../src/encoding.ts';
import { DecryptionError, ValidationError } from '../src/errors.ts';

// Fast params for tests. Production defaults are exercised separately below.
const testKdf = () => ({ ...defaultKdfParams('interactive'), memoryKiB: 16 * 1024, iterations: 2 });

describe('Argon2id derivation', () => {
  it('agrees byte-for-byte with an independent implementation (@noble/hashes)', async () => {
    // hash-wasm is the shipping implementation; noble is a pure-JS cross-check.
    // If these ever diverge, one of them has a bug and vaults are at risk.
    const password = 'correct horse battery staple';
    const salt = new Uint8Array(16).fill(0x2a);
    // At the KDF_MINIMUMS floor — anything lower is refused by the downgrade guard.
    const params = { memoryKiB: 16 * 1024, iterations: 2, parallelism: 1, keyLength: 32 };

    const noble = nobleArgon2id(utf8ToBytes(password), salt, {
      m: params.memoryKiB,
      t: params.iterations,
      p: params.parallelism,
      dkLen: params.keyLength,
    });

    // Derive through our wrapper and confirm the resulting key encrypts
    // identically to one imported straight from noble's output.
    const ourKey = await deriveMasterKey(password, {
      algorithm: 'argon2id',
      saltB64: bytesToB64(salt),
      ...params,
    });
    const nobleKey = await importAesKey(noble);

    const aad = utf8ToBytes('cross-check');
    const blob = await encrypt(nobleKey, utf8ToBytes('same key?'), aad);
    await expect(decrypt(ourKey, blob, aad)).resolves.toEqual(utf8ToBytes('same key?'));
  });

  it('is deterministic for the same password and salt', async () => {
    const kdf = testKdf();
    const aad = utf8ToBytes('x');
    const k1 = await deriveMasterKey('hunter2hunter2', kdf);
    const k2 = await deriveMasterKey('hunter2hunter2', kdf);
    const blob = await encrypt(k1, utf8ToBytes('secret'), aad);
    await expect(decrypt(k2, blob, aad)).resolves.toEqual(utf8ToBytes('secret'));
  });

  it('produces a different key for a different salt', async () => {
    const aad = utf8ToBytes('x');
    const k1 = await deriveMasterKey('hunter2hunter2', testKdf());
    const k2 = await deriveMasterKey('hunter2hunter2', testKdf()); // new random salt
    const blob = await encrypt(k1, utf8ToBytes('secret'), aad);
    await expect(decrypt(k2, blob, aad)).rejects.toThrow(DecryptionError);
  });

  it('rejects an empty master password', async () => {
    await expect(deriveMasterKey('', testKdf())).rejects.toThrow(ValidationError);
  });

  it('derives a non-extractable key', async () => {
    const key = await deriveMasterKey('hunter2hunter2', testKdf());
    expect(key.extractable).toBe(false);
    await expect(globalThis.crypto.subtle.exportKey('raw', key)).rejects.toThrow();
  });

  it('uses defaults at or above the OWASP floor', () => {
    expect(KDF_PRESETS.interactive.memoryKiB).toBeGreaterThanOrEqual(19 * 1024);
    expect(KDF_PRESETS.interactive.iterations).toBeGreaterThanOrEqual(2);
    const params = defaultKdfParams();
    expect(params.algorithm).toBe('argon2id');
    expect(params.keyLength).toBe(32);
    expect(b64ToBytes(params.saltB64)).toHaveLength(CRYPTO.SALT_BYTES);
  });

  it('generates a fresh random salt every time', () => {
    const salts = new Set(Array.from({ length: 25 }, () => defaultKdfParams().saltB64));
    expect(salts.size).toBe(25);
  });
});

describe('KDF downgrade protection', () => {
  it('rejects parameters below the minimum cost', () => {
    const weak = { ...defaultKdfParams(), memoryKiB: 8, iterations: 1 };
    expect(() => assertKdfParamsAcceptable(weak)).toThrow(ValidationError);
  });

  it('rejects a non-argon2id algorithm', () => {
    const bad = { ...defaultKdfParams(), algorithm: 'pbkdf2' as unknown as 'argon2id' };
    expect(() => assertKdfParamsAcceptable(bad)).toThrow(ValidationError);
  });

  it('rejects a truncated salt', () => {
    const bad = { ...defaultKdfParams(), saltB64: bytesToB64(new Uint8Array(4)) };
    expect(() => assertKdfParamsAcceptable(bad)).toThrow(ValidationError);
  });
});

describe('AES-256-GCM', () => {
  const freshKey = async () => {
    const raw = generateVaultKeyBytes();
    const key = await importAesKey(raw);
    zeroize(raw);
    return key;
  };

  it('round-trips plaintext', async () => {
    const key = await freshKey();
    const aad = utf8ToBytes('aad');
    const message = utf8ToBytes('attack at dawn 🌅');
    const blob = await encrypt(key, message, aad);
    await expect(decrypt(key, blob, aad)).resolves.toEqual(message);
  });

  it('uses a fresh 96-bit nonce for every encryption', async () => {
    const key = await freshKey();
    const aad = utf8ToBytes('aad');
    const ivs = new Set<string>();
    for (let i = 0; i < 200; i += 1) {
      const blob = await encrypt(key, utf8ToBytes('same plaintext every time'), aad);
      expect(b64ToBytes(blob.ivB64)).toHaveLength(CRYPTO.IV_BYTES);
      ivs.add(blob.ivB64);
    }
    expect(ivs.size).toBe(200); // no reuse across repeated encryptions of identical data
  });

  it('produces different ciphertext for identical plaintext', async () => {
    const key = await freshKey();
    const aad = utf8ToBytes('aad');
    const a = await encrypt(key, utf8ToBytes('dup'), aad);
    const b = await encrypt(key, utf8ToBytes('dup'), aad);
    expect(a.ctB64).not.toBe(b.ctB64);
  });

  it('appends a 128-bit authentication tag', async () => {
    const key = await freshKey();
    const plaintext = utf8ToBytes('12345678');
    const blob = await encrypt(key, plaintext, utf8ToBytes(''));
    expect(b64ToBytes(blob.ctB64).length).toBe(plaintext.length + CRYPTO.TAG_BITS / 8);
  });

  it('rejects a flipped ciphertext bit', async () => {
    const key = await freshKey();
    const aad = utf8ToBytes('aad');
    const blob = await encrypt(key, utf8ToBytes('tamper me'), aad);
    const ct = b64ToBytes(blob.ctB64);
    ct[0] = (ct[0] ?? 0) ^ 0x01;
    await expect(decrypt(key, { ...blob, ctB64: bytesToB64(ct) }, aad)).rejects.toThrow(DecryptionError);
  });

  it('rejects a flipped authentication tag bit', async () => {
    const key = await freshKey();
    const aad = utf8ToBytes('aad');
    const blob = await encrypt(key, utf8ToBytes('tamper me'), aad);
    const ct = b64ToBytes(blob.ctB64);
    ct[ct.length - 1] = (ct[ct.length - 1] ?? 0) ^ 0x80;
    await expect(decrypt(key, { ...blob, ctB64: bytesToB64(ct) }, aad)).rejects.toThrow(DecryptionError);
  });

  it('rejects a modified nonce', async () => {
    const key = await freshKey();
    const aad = utf8ToBytes('aad');
    const blob = await encrypt(key, utf8ToBytes('tamper me'), aad);
    const iv = b64ToBytes(blob.ivB64);
    iv[0] = (iv[0] ?? 0) ^ 0xff;
    await expect(decrypt(key, { ...blob, ivB64: bytesToB64(iv) }, aad)).rejects.toThrow(DecryptionError);
  });

  it('rejects mismatched associated data', async () => {
    const key = await freshKey();
    const blob = await encrypt(key, utf8ToBytes('bound'), utf8ToBytes('context-A'));
    await expect(decrypt(key, blob, utf8ToBytes('context-B'))).rejects.toThrow(DecryptionError);
  });

  it('rejects a malformed blob without leaking why', async () => {
    const key = await freshKey();
    const err = await decrypt(key, { ivB64: 'AAAA', ctB64: 'AAAA' }, utf8ToBytes('')).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(DecryptionError);
    expect((err as Error).message).toBe('Decryption failed: wrong master password or corrupted vault.');
  });

  it('refuses a key of the wrong length', async () => {
    await expect(importAesKey(new Uint8Array(16))).rejects.toThrow(ValidationError);
  });
});

describe('associated data binding', () => {
  const header = {
    vaultId: '11111111-1111-4111-8111-111111111111',
    formatVersion: 1,
    kdf: defaultKdfParams(),
  };

  it('binds vault id, so a wrapped key cannot be spliced between vaults', () => {
    const other = { ...header, vaultId: '22222222-2222-4222-8222-222222222222' };
    expect(bytesToHex(wrappedKeyAad(header))).not.toBe(bytesToHex(wrappedKeyAad(other)));
  });

  it('binds KDF cost, so stored parameters cannot be silently weakened', () => {
    const weakened = { ...header, kdf: { ...header.kdf, memoryKiB: 1024 } };
    expect(bytesToHex(wrappedKeyAad(header))).not.toBe(bytesToHex(wrappedKeyAad(weakened)));
  });

  it('is deterministic across calls', () => {
    expect(bytesToHex(wrappedKeyAad(header))).toBe(bytesToHex(wrappedKeyAad({ ...header })));
    expect(bytesToHex(payloadAad(header))).toBe(bytesToHex(payloadAad({ ...header })));
  });

  it('keeps payload AAD independent of KDF params so rewrapping stays possible', () => {
    const rekeyed = { ...header, kdf: defaultKdfParams() };
    expect(bytesToHex(payloadAad(header))).toBe(bytesToHex(payloadAad(rekeyed)));
  });

  it('separates the wrapped-key and payload domains', () => {
    expect(bytesToHex(wrappedKeyAad(header))).not.toBe(bytesToHex(payloadAad(header)));
  });
});

describe('primitives', () => {
  it('zeroize clears buffers and tolerates nullish input', () => {
    const buf = randomBytes(32);
    zeroize(buf, undefined, null);
    expect([...buf].every((b) => b === 0)).toBe(true);
  });

  it('timingSafeEqual compares correctly', () => {
    expect(timingSafeEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 3]))).toBe(true);
    expect(timingSafeEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 4]))).toBe(false);
    expect(timingSafeEqual(new Uint8Array([1, 2]), new Uint8Array([1, 2, 3]))).toBe(false);
  });

  it('base64 round-trips arbitrary bytes including a large buffer', () => {
    for (const size of [0, 1, 15, 16, 1024, 100_000]) {
      const bytes = randomBytes(size);
      expect(b64ToBytes(bytesToB64(bytes))).toEqual(bytes);
    }
  });

  it('randomBytes does not repeat', () => {
    const seen = new Set(Array.from({ length: 100 }, () => bytesToHex(randomBytes(16))));
    expect(seen.size).toBe(100);
  });
});
