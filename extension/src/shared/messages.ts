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
 *  2. Every handler must call `isTrustedExtensionSender` (for privileged
 *     messages) before acting. `chrome.runtime.onMessage` fires for content
 *     scripts too, and a compromised page can drive its content script.
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
]);

export type Request = z.infer<typeof requestSchema>;

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
  | { ok: true; type: 'STATE'; locked: boolean; hasVault: boolean; entryCount: number; autoLockMinutes: number }
  | { ok: true; type: 'ENTRIES'; entries: EntrySummary[] }
  | { ok: true; type: 'SECRET'; value: string; clipboardClearSeconds: number }
  | { ok: true; type: 'FILLED'; filledUsername: boolean; filledPassword: boolean }
  | { ok: true; type: 'EXPORT'; file: unknown }
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
    /** Origin the service worker verified immediately before dispatching. */
    expectedOrigin: z.string().max(2048),
  })
  .strict();

export type FillCommand = z.infer<typeof fillCommandSchema>;

export const fillResultSchema = z
  .object({
    filledUsername: z.boolean(),
    filledPassword: z.boolean(),
  })
  .strict();

// ---------------------------------------------------------------------------
// Sender validation
// ---------------------------------------------------------------------------

/**
 * True only for messages from *our own extension pages* (popup, options).
 *
 * Three checks, all necessary:
 *  - `sender.id === chrome.runtime.id` rejects other extensions.
 *  - `sender.url` starting with our origin rejects content scripts, which carry
 *    the page's URL rather than a chrome-extension:// one.
 *  - `sender.tab === undefined` rejects anything running in a web page context.
 *
 * The second and third are what stop a compromised page from driving its
 * content script into asking us to decrypt the vault.
 */
export function isTrustedExtensionSender(sender: chrome.runtime.MessageSender): boolean {
  if (sender.id !== chrome.runtime.id) return false;
  if (sender.tab !== undefined) return false;
  const origin = `chrome-extension://${chrome.runtime.id}/`;
  return typeof sender.url === 'string' && sender.url.startsWith(origin);
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
