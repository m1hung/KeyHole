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
  /** Entries whose URLs match a tab. Returns metadata only — never passwords. */
  z.object({ type: z.literal('MATCH_TAB'), tabId: z.number().int().nonnegative() }).strict(),
  z.object({ type: z.literal('LIST_ENTRIES'), query: z.string().max(256).optional() }).strict(),
  /** Reveals one secret to the popup, for an explicit copy/reveal gesture. */
  z.object({ type: z.literal('REVEAL_SECRET'), entryId: z.uuid(), field: z.enum(['password', 'username', 'totp']) }).strict(),
  /** The privileged autofill trigger. */
  z.object({ type: z.literal('FILL'), entryId: z.uuid(), tabId: z.number().int().nonnegative() }).strict(),
  z.object({ type: z.literal('SAVE_ENTRY'), entry: z.unknown() }).strict(),
  z.object({ type: z.literal('DELETE_ENTRY'), entryId: z.uuid() }).strict(),
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
  /** Display host only. The full URL list stays in the service worker. */
  host: string | null;
  matchStrength?: 'exact' | 'host' | 'subdomain';
  hasTotp: boolean;
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
    }
  | { ok: true; type: 'ENTRIES'; entries: EntrySummary[] }
  | {
      ok: true;
      type: 'SUGGESTIONS';
      locked: boolean;
      theme: 'light' | 'dark' | 'system';
      entries: EntrySummary[];
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
  | { ok: false; error: string };

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
