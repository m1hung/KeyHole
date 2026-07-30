/**
 * Zod schemas for everything that crosses a trust boundary: imported vault
 * files, decrypted payloads, and extension messages.
 *
 * Decrypted payloads are validated too. GCM already proves the bytes were
 * written by someone holding the key, but a vault written by a future (or
 * buggy) build could still be structurally wrong, and we would rather fail
 * loudly at the boundary than propagate `undefined` into the UI.
 *
 * STRICT WHERE IT PROVES SOMETHING, LOOSE WHERE IT ONLY HURTS:
 *
 * The envelope schemas stay `.strict()`. That part is unencrypted, so an
 * unexpected key there is a real signal — corruption, or someone appending to a
 * file they cannot decrypt.
 *
 * The payload schemas are `.loose()`: known fields are validated exactly as
 * before, and unrecognised ones are carried through instead of rejected. The
 * distinction that matters is between a *malformed* payload and a *well-formed
 * one carrying a field this build has not learned about yet*. Only a Keyhole
 * holding the key can produce the latter, and rejecting it does not protect the
 * user — it locks them out of their own passwords on whichever device they
 * updated last. Keyhole now runs on four surfaces against one synced vault
 * (desktop, extension, iOS, and any older build still installed), so "newer
 * vault meets older reader" is routine rather than exotic.
 *
 * Carrying unknown fields through also means an older build cannot silently
 * strip them: it re-encrypts what it read, so a round trip through a stale
 * device does not destroy data written by a current one.
 */

import { z } from 'zod';
import {
  MAX_ATTACHMENT_BYTES,
  MAX_ATTACHMENTS_VAULT_BYTES,
  VAULT_FORMAT_ID,
} from './types.ts';
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
  .loose();

export const settingsSchema = z
  .object({
    autoLockMinutes: z.number().min(0.5).max(24 * 60),
    clipboardClearSeconds: z.number().min(0).max(600),
    generator: generatorOptionsSchema,
    theme: z.enum(['light', 'dark', 'system']),
    lockOnHide: z.boolean(),
    // Absent on schema-3 vaults — off by default, never opt someone in.
    breachCheckEnabled: z.boolean().default(false),
  })
  .loose();

export const totpConfigSchema = z
  .object({
    digits: z.int().min(6).max(10),
    periodSeconds: z.int().min(1).max(3600),
    algorithm: z.enum(['SHA-1', 'SHA-256', 'SHA-512']),
  })
  .loose();

export const customFieldSchema = z
  .object({
    id: z.uuid(),
    label: z.string().max(128),
    value: z.string().max(4096),
    secret: z.boolean(),
  })
  .loose();

export const attachmentSchema = z
  .object({
    id: z.uuid(),
    name: z.string().min(1).max(512),
    mimeType: z.string().min(1).max(128),
    sizeBytes: z.int().min(0).max(MAX_ATTACHMENT_BYTES),
    dataB64: b64,
  })
  .loose();

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
    /*
     * Nullable AND defaulted, because "absent" and "null" both occur in the wild.
     * Swift synthesises `encodeIfPresent` for optional properties, so the iOS build
     * omits these keys instead of writing an explicit null — and requiring them
     * present made every vault saved by that app unreadable here, since almost no
     * entry has a TOTP secret. iOS now writes explicit nulls (see Types.swift), but
     * vaults it already wrote have to keep opening.
     */
    folderId: z.uuid().nullable().default(null),
    totpSecret: z.string().max(512).nullable().default(null),
    /*
     * Schema-4 fields. Defaulted so a schema-3 vault opens without a rewrite:
     * null / [] match "never set", which is exactly what older entries mean.
     */
    totpConfig: totpConfigSchema.nullable().default(null),
    customFields: z.array(customFieldSchema).max(64).default([]),
    attachments: z.array(attachmentSchema).max(32).default([]),
    createdAt: isoDate,
    updatedAt: isoDate,
    passwordUpdatedAt: isoDate,
    /*
     * Defaulted, like `kind` before them: a schema-2 vault has neither field, and
     * defaulting here is what lets an older vault open without a rewrite pass.
     * The cap is enforced when writing (see `rememberPassword`), not here, so a
     * vault that somehow exceeds it still opens rather than becoming unreadable.
     */
    history: z
      .array(z.object({ password: z.string().max(4096), changedAt: isoDate }).loose())
      .max(1000)
      .default([]),
    deletedAt: isoDate.nullable().default(null),
  })
  .loose();

export const folderSchema = z
  .object({
    id: z.uuid(),
    name: z.string().min(1).max(128),
    createdAt: isoDate,
  })
  .loose();

export const tombstoneSchema = z
  .object({
    id: z.uuid(),
    kind: z.enum(['entry', 'folder']),
    deletedAt: isoDate,
  })
  .loose();

export const vaultDataSchema = z
  .object({
    // Deliberately permissive: a newer-than-supported version must reach the
    // explicit check in `migrate()` so the user gets "update Keyhole" rather
    // than a generic schema error. The value is authenticated by GCM regardless.
    schemaVersion: z.int().min(1).max(1_000_000),
    entries: z.array(entrySchema).max(100_000),
    folders: z.array(folderSchema).max(10_000),
    /*
     * Optional because this parser runs BEFORE `migrate()`: a schemaVersion-1
     * vault has no tombstones yet, and `migrate()` back-fills `[]`.
     */
    tombstones: z.array(tombstoneSchema).max(100_000).default([]),
    settings: settingsSchema,
    updatedAt: isoDate,
  })
  .loose()
  .superRefine((data, ctx) => {
    let total = 0;
    for (const entry of data.entries) {
      for (const att of entry.attachments) {
        total += att.sizeBytes;
        if (att.sizeBytes > MAX_ATTACHMENT_BYTES) {
          ctx.addIssue({
            code: 'custom',
            message: `Attachment "${att.name}" exceeds the ${MAX_ATTACHMENT_BYTES} byte per-file limit.`,
            path: ['entries'],
          });
        }
      }
    }
    if (total > MAX_ATTACHMENTS_VAULT_BYTES) {
      ctx.addIssue({
        code: 'custom',
        message: `Vault attachments exceed the ${MAX_ATTACHMENTS_VAULT_BYTES} byte total budget.`,
        path: ['entries'],
      });
    }
  });

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
