/**
 * Extension message protocol.
 *
 * Every message crossing a process boundary is defined and validated here.
 * Two rules govern this file:
 *
 *  1. NOTHING in the response types may carry the master key, the vault key, or
 *     more than a single credential. The service worker is the only holder of
 *     the decrypted vault; popup and content script receive the minimum needed.
 *
 *  2. Privileged handlers require `isTrustedExtensionSender`. Content scripts
 *     may only send the narrow `contentScriptRequestSchema` types, which never
 *     accept a client-supplied URL or tab id — the SW always uses `sender.tab`.
 */

import { z } from 'zod';
import type { Attachment, CustomField, TotpConfig } from '@keyhole/core';

// ---------------------------------------------------------------------------
// Requests: extension pages (popup / options) → service worker
// ---------------------------------------------------------------------------

export const requestSchema = z.discriminatedUnion('type', [
  z.object({ type: z.literal('GET_STATE') }).strict(),
  z.object({ type: z.literal('UNLOCK'), masterPassword: z.string().min(1).max(1024) }).strict(),
  z.object({ type: z.literal('LOCK') }).strict(),
  z.object({ type: z.literal('CREATE_VAULT'), masterPassword: z.string().min(1).max(1024) }).strict(),
  z.object({ type: z.literal('IMPORT_VAULT'), file: z.unknown() }).strict(),
  z.object({ type: z.literal('EXPORT_VAULT') }).strict(),
  /**
   * Sign out: erase the stored vault, prefs and sync config from this browser.
   * Takes no master password on purpose — the main reason to reach for it is
   * having forgotten one. Destructive, so the UI gates it behind a typed
   * confirmation; this layer only enforces that the sender is our own page.
   */
  z.object({ type: z.literal('RESET_VAULT') }).strict(),
  /**
   * Re-key the vault. Also re-points the sync account, since the new KDF salt
   * invalidates the account's verifier — see rotateSyncAuthAfterRekey.
   */
  z
    .object({
      type: z.literal('CHANGE_MASTER_PASSWORD'),
      currentPassword: z.string().min(1).max(1024),
      newPassword: z.string().min(1).max(1024),
    })
    .strict(),
  /** Entries whose URLs match a tab. Returns metadata only — never passwords. */
  z.object({ type: z.literal('MATCH_TAB'), tabId: z.number().int().nonnegative() }).strict(),
  z.object({ type: z.literal('LIST_ENTRIES'), query: z.string().max(256).optional() }).strict(),
  /** Full entry for the options editor. Trusted senders only — includes secrets. */
  z.object({ type: z.literal('GET_ENTRY'), entryId: z.uuid() }).strict(),
  /** Offline vault audit. Returns findings only — never a password. */
  z.object({ type: z.literal('HEALTH_REPORT') }).strict(),
  /** Entries in the trash — deleted but still restorable. */
  z.object({ type: z.literal('LIST_TRASH') }).strict(),
  z.object({ type: z.literal('RESTORE_ENTRY'), entryId: z.uuid() }).strict(),
  /** Destroy an entry for good, on every synced device. Not reversible. */
  z.object({ type: z.literal('PURGE_ENTRY'), entryId: z.uuid() }).strict(),
  /** Reveals one secret to the popup, for an explicit copy/reveal gesture. */
  z.object({ type: z.literal('REVEAL_SECRET'), entryId: z.uuid(), field: z.enum(['password', 'username', 'totp']) }).strict(),
  /** The privileged autofill trigger. */
  z.object({ type: z.literal('FILL'), entryId: z.uuid(), tabId: z.number().int().nonnegative() }).strict(),
  z.object({ type: z.literal('SAVE_ENTRY'), entry: z.unknown() }).strict(),
  z.object({ type: z.literal('DELETE_ENTRY'), entryId: z.uuid() }).strict(),
  /**
   * Remove one synced passkey from an entry. Create/use is iOS AutoFill only;
   * the extension can list and delete what sync already carries.
   */
  z
    .object({
      type: z.literal('REMOVE_PASSKEY'),
      entryId: z.uuid(),
      passkeyId: z.uuid(),
    })
    .strict(),
  /**
   * Move several entries to the trash in one save — what the health panel's
   * batch action sends. Reversible, like `DELETE_ENTRY`; the irreversible
   * `PURGE_ENTRY` stays deliberately one entry at a time.
   */
  z.object({ type: z.literal('DELETE_ENTRIES'), entryIds: z.array(z.uuid()).min(1).max(5000) }).strict(),
  z.object({ type: z.literal('KEEPALIVE') }).strict(),
  z.object({ type: z.literal('GET_SYNC_CONFIG') }).strict(),
  z
    .object({
      type: z.literal('SET_THEME'),
      theme: z.enum(['light', 'dark', 'system']),
    })
    .strict(),
  z
    .object({
      type: z.literal('SET_BREACH_CHECK'),
      enabled: z.boolean(),
    })
    .strict(),
  z
    .object({
      type: z.literal('SAVE_SYNC_CONFIG'),
      baseUrl: z.string().max(2048),
      accountId: z.string().max(256),
    })
    .strict(),
  z
    .object({
      type: z.literal('SYNC_REGISTER'),
      masterPassword: z.string().min(1).max(1024),
      baseUrl: z.string().max(2048),
      accountId: z.string().max(256),
    })
    .strict(),
  z
    .object({
      type: z.literal('SYNC_NOW'),
      /** Optional when the sync auth secret is already cached for this unlock. */
      masterPassword: z.string().max(1024).optional(),
      baseUrl: z.string().max(2048),
      accountId: z.string().max(256),
    })
    .strict(),
  /** Replace this device's vault with the one stored on the sync server. */
  z
    .object({
      type: z.literal('SYNC_ADOPT_REMOTE'),
      masterPassword: z.string().min(1).max(1024),
      baseUrl: z.string().max(2048),
      accountId: z.string().max(256),
    })
    .strict(),
  /** Overwrite the sync server account with this device's vault. */
  z
    .object({
      type: z.literal('SYNC_OVERWRITE_REMOTE'),
      masterPassword: z.string().min(1).max(1024),
      baseUrl: z.string().max(2048),
      accountId: z.string().max(256),
    })
    .strict(),
]);

export type Request = z.infer<typeof requestSchema>;

/**
 * Messages a content script may send. Deliberately tiny surface:
 *  - no tabId / URL (matching uses sender.tab from Chrome)
 *  - no secret reveal / export / unlock
 *  - FILL_FROM_PAGE only carries an entry id; the SW re-checks host match
 *  - SAVE_FROM_PAGE only after the user confirms the in-page offer
 */
export const contentScriptRequestSchema = z.discriminatedUnion('type', [
  z.object({ type: z.literal('SUGGEST_FOR_PAGE') }).strict(),
  z.object({ type: z.literal('FILL_FROM_PAGE'), entryId: z.uuid() }).strict(),
  z
    .object({
      type: z.literal('SAVE_FROM_PAGE'),
      username: z.string().max(512),
      password: z.string().min(1).max(4096),
      /** When set, update this matching entry instead of creating a new one. */
      entryId: z.uuid().optional(),
    })
    .strict(),
]);

export type ContentScriptRequest = z.infer<typeof contentScriptRequestSchema>;

// ---------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------

export interface EntrySummary {
  id: string;
  title: string;
  username: string;
  /** When this entry was moved to the trash; absent for live entries. */
  deletedAt?: string | null;
  /** Display host only. The full URL list stays in the service worker. */
  host: string | null;
  /** Loosest is `domain`: same registrable domain, a different host. */
  matchStrength?: 'exact' | 'host' | 'subdomain' | 'domain';
  hasTotp: boolean;
  /** Synced WebAuthn passkeys (created on iOS). Browser cannot assert them. */
  hasPasskey: boolean;
}

/**
 * Passkey metadata for the options editor. Deliberately omits private key and
 * credential id bytes — those never leave the service worker except inside the
 * encrypted vault envelope.
 */
export interface PasskeySummary {
  id: string;
  relyingPartyId: string;
  relyingPartyName: string;
  userName: string;
  userDisplayName: string;
  createdAt: string;
  lastUsedAt: string | null;
  signCount: number;
}

export type Response =
  | {
      ok: true;
      type: 'STATE';
      locked: boolean;
      hasVault: boolean;
      entryCount: number;
      autoLockMinutes: number;
      theme: 'light' | 'dark' | 'system';
      /** Opt-in HIBP range checks. Only meaningful while unlocked. */
      breachCheckEnabled: boolean;
      /**
       * Set when the open vault was written by a newer Keyhole than this build.
       * It works and unknown fields survive a save, but they are not shown here.
       */
      foreignSchemaVersion: number | null;
    }
  | { ok: true; type: 'ENTRIES'; entries: EntrySummary[] }
  | {
      ok: true;
      type: 'ENTRY';
      /** Full entry for editing. Only returned to trusted extension pages. */
      entry: {
        id: string;
        title: string;
        username: string;
        password: string;
        urls: string[];
        notes: string;
        tags: string[];
        totpSecret: string | null;
        totpConfig: TotpConfig | null;
        customFields: CustomField[];
        attachments: Attachment[];
        passkeys: PasskeySummary[];
      };
    }
  | {
      ok: true;
      type: 'SUGGESTIONS';
      locked: boolean;
      theme: 'light' | 'dark' | 'system';
      entries: EntrySummary[];
    }
  | {
      ok: true;
      type: 'HEALTH';
      /**
       * Findings from `analyzeVaultHealth`. Each names an entry and what is wrong
       * with its password — never the password itself, so this stays inside the
       * "metadata only" rule the other list responses follow.
       */
      issues: {
        kind: 'reused' | 'weak' | 'stale' | 'empty' | 'no username';
        entryId: string;
        title: string;
        detail: string;
      }[];
      loginCount: number;
      checkedAt: string;
    }
  | { ok: true; type: 'SECRET'; value: string; clipboardClearSeconds: number }
  | { ok: true; type: 'FILLED'; filledUsername: boolean; filledPassword: boolean; filledTotp: boolean }
  | { ok: true; type: 'EXPORT'; file: unknown }
  | {
      ok: true;
      type: 'SYNC_CONFIG';
      baseUrl: string | null;
      accountId: string | null;
      /** True when sync auth is cached in memory for this unlock. */
      hasSyncAuthSecret: boolean;
    }
  | { ok: true; type: 'SYNC_RESULT'; message: string }
  | { ok: true; type: 'SYNC_VAULT_MISMATCH'; message: string }
  | { ok: true; type: 'OK' }
  | {
      ok: false;
      error: string;
      /**
       * Host-level facts about a failed autofill, shown under the error and logged
       * by the service worker: which frames were visible, which held a login
       * field, which one got the credential, whether the site is allowed.
       *
       * Autofill can fail for structural reasons the user cannot see (a login form
       * in a frame we are not permitted to touch looks identical to a page with no
       * form at all), so "it didn't work" needs to be answerable without a
       * debugger. Hosts only — never paths or query strings, which carry tokens.
       */
      detail?: string;
      /**
       * Set when the failure is "Keyhole is not allowed on this site" and a
       * narrowly-scoped optional permission would fix it — a match pattern the
       * popup can hand to `chrome.permissions.request` under the user's click.
       * The service worker cannot request permissions itself; only a page with a
       * user gesture can.
       */
      needsHostAccess?: string;
    };

// ---------------------------------------------------------------------------
// Service worker → content script
// ---------------------------------------------------------------------------

export const fillCommandSchema = z
  .object({
    type: z.literal('KEYHOLE_FILL'),
    username: z.string().max(512),
    password: z.string().max(4096),
    /** Optional one-time code; only sent when the entry has a TOTP secret. */
    totp: z.string().max(16).optional(),
    /** Origin the service worker verified immediately before dispatching. */
    expectedOrigin: z.string().max(2048),
  })
  .strict();

export type FillCommand = z.infer<typeof fillCommandSchema>;

export const fillResultSchema = z
  .object({
    filledUsername: z.boolean(),
    filledPassword: z.boolean(),
    filledTotp: z.boolean(),
  })
  .strict();

// ---------------------------------------------------------------------------
// Sender validation
// ---------------------------------------------------------------------------

/**
 * True only for messages from *our own extension pages* (popup, options).
 *
 * Accept either `sender.url` or `sender.origin` under our chrome-extension
 * origin. Content scripts carry the page URL/origin (https://…), never ours.
 * Options opened via `chrome.windows.create({ type: 'popup' })` still have a
 * tab — that alone must not disqualify them.
 */
export function isTrustedExtensionSender(sender: chrome.runtime.MessageSender): boolean {
  if (sender.id !== chrome.runtime.id) return false;
  const origin = `chrome-extension://${chrome.runtime.id}`;
  if (typeof sender.origin === 'string' && sender.origin === origin) return true;
  return typeof sender.url === 'string' && sender.url.startsWith(`${origin}/`);
}

/**
 * True for messages from our content script in a web tab.
 *
 * Must never overlap with trusted extension pages (including the vault window,
 * which has a tab but a chrome-extension:// URL).
 */
export function isContentScriptSender(sender: chrome.runtime.MessageSender): boolean {
  if (sender.id !== chrome.runtime.id) return false;
  if (typeof sender.tab?.id !== 'number') return false;
  if (isTrustedExtensionSender(sender)) return false;
  return true;
}

/** True for messages from a content script we injected. Used by the content script side. */
export function isFromOwnExtension(sender: chrome.runtime.MessageSender): boolean {
  return sender.id === chrome.runtime.id;
}

// ---------------------------------------------------------------------------
// Typed transport
// ---------------------------------------------------------------------------

export async function sendToBackground(request: Request): Promise<Response> {
  try {
    const response = (await chrome.runtime.sendMessage(request)) as Response | undefined;
    return response ?? { ok: false, error: 'No response from the background service.' };
  } catch (err) {
    // Most commonly the service worker was evicted mid-flight; the caller
    // should re-check state rather than assume the vault is still unlocked.
    return { ok: false, error: err instanceof Error ? err.message : 'Background service unavailable.' };
  }
}
