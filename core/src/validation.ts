/**
 * Zod schemas for everything that crosses a trust boundary: imported vault
 * files, decrypted payloads, and extension messages.
 *
 * Decrypted payloads are validated too. GCM already proves the bytes were
 * written by someone holding the key, but a vault written by a future (or
 * buggy) build could still be structurally wrong, and we would rather fail
 * loudly at the boundary than propagate `undefined` into the UI.
 */

import { z } from 'zod';
import { VAULT_FORMAT_ID } from './types.ts';
import { MAX_LENGTH, MIN_LENGTH } from './password-gen.ts';
import { VaultFormatError } from './errors.ts';

const isoDate = z.string().refine((s) => !Number.isNaN(Date.parse(s)), 'Expected an ISO-8601 timestamp');
const b64 = z.string().regex(/^[A-Za-z0-9+/]*={0,2}$/, 'Expected base64');

export const encryptedBlobSchema = z
  .object({
    ivB64: b64.min(1),
    ctB64: b64.min(1),
  })
  .strict();

export const kdfParamsSchema = z
  .object({
    algorithm: z.literal('argon2id'),
    memoryKiB: z.int().min(1024).max(2 ** 21),
    iterations: z.int().min(1).max(64),
    parallelism: z.int().min(1).max(16),
    saltB64: b64.min(16),
    keyLength: z.literal(32),
  })
  .strict();

export const generatorOptionsSchema = z
  .object({
    length: z.int().min(MIN_LENGTH).max(MAX_LENGTH),
    lowercase: z.boolean(),
    uppercase: z.boolean(),
    digits: z.boolean(),
    symbols: z.boolean(),
    excludeAmbiguous: z.boolean(),
  })
  .strict();

export const settingsSchema = z
  .object({
    autoLockMinutes: z.number().min(0.5).max(24 * 60),
    clipboardClearSeconds: z.number().min(0).max(600),
    generator: generatorOptionsSchema,
    theme: z.enum(['light', 'dark', 'system']),
    lockOnHide: z.boolean(),
  })
  .strict();

export const entrySchema = z
  .object({
    id: z.uuid(),
    // Missing on vaults written before kinds existed; treat as login.
    kind: z.enum(['login', 'note']).default('login'),
    title: z.string().max(512),
    username: z.string().max(512),
    password: z.string().max(4096),
    urls: z.array(z.string().max(2048)).max(64),
    notes: z.string().max(64 * 1024),
    tags: z.array(z.string().max(64)).max(64),
    folderId: z.uuid().nullable(),
    totpSecret: z.string().max(512).nullable(),
    createdAt: isoDate,
    updatedAt: isoDate,
    passwordUpdatedAt: isoDate,
  })
  .strict();

export const folderSchema = z
  .object({
    id: z.uuid(),
    name: z.string().min(1).max(128),
    createdAt: isoDate,
  })
  .strict();

export const vaultDataSchema = z
  .object({
    // Deliberately permissive: a newer-than-supported version must reach the
    // explicit check in `migrate()` so the user gets "update Keyhole" rather
    // than a generic schema error. The value is authenticated by GCM regardless.
    schemaVersion: z.int().min(1).max(1_000_000),
    entries: z.array(entrySchema).max(100_000),
    folders: z.array(folderSchema).max(10_000),
    settings: settingsSchema,
    updatedAt: isoDate,
  })
  .strict();

export const vaultFileSchema = z
  .object({
    format: z.literal(VAULT_FORMAT_ID),
    // See the note on `schemaVersion`: `unlockVault` performs the explicit
    // version check so the error message is actionable.
    formatVersion: z.int().min(1).max(1_000_000),
    vaultId: z.uuid(),
    createdAt: isoDate,
    updatedAt: isoDate,
    kdf: kdfParamsSchema,
    wrappedKey: encryptedBlobSchema,
    payload: encryptedBlobSchema,
  })
  .strict();

/** Parse an untrusted vault envelope, converting Zod failures into our error type. */
export function parseVaultFile(input: unknown): z.infer<typeof vaultFileSchema> {
  const result = vaultFileSchema.safeParse(input);
  if (!result.success) {
    throw new VaultFormatError(`Not a valid Keyhole vault file: ${result.error.issues[0]?.message ?? 'unknown error'}`);
  }
  return result.data;
}

/** Parse a decrypted payload. Failure here means a corrupt or future-version vault. */
export function parseVaultData(input: unknown): z.infer<typeof vaultDataSchema> {
  const result = vaultDataSchema.safeParse(input);
  if (!result.success) {
    const issue = result.error.issues[0];
    throw new VaultFormatError(
      `Vault contents failed validation at "${issue?.path.join('.') || '<root>'}": ${issue?.message ?? 'unknown error'}`,
    );
  }
  return result.data;
}
