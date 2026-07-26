/**
 * Keyhole service worker — the only process that ever holds decrypted data.
 *
 * Invariants:
 *  - The session (CryptoKey + decrypted vault) lives in a module-scope variable
 *    and is NEVER written to chrome.storage, IndexedDB, or anywhere persistent.
 *  - Every privileged message is gated on `isTrustedExtensionSender`.
 *  - Content scripts can never ask for a decrypt. They are not senders we trust,
 *    and there is no message type that returns vault contents to a tab.
 *  - Autofill re-verifies the target tab's URL immediately before dispatching,
 *    closing the window where a page navigates between the user's click and the
 *    credential arriving.
 *
 * MV3 SERVICE WORKER LIFETIME — an honest note:
 * Chrome terminates idle service workers (~30s). When that happens the session
 * is lost and the vault is effectively locked. That is fail-closed and we treat
 * it as a feature, but it would be a poor experience if it fired constantly, so
 * an alarm-driven heartbeat keeps the worker warm *while unlocked only*. Chrome
 * may still evict under memory pressure; the UI handles that by showing the
 * lock screen rather than by pretending to still be unlocked.
 */

import {
  DecryptionError,
  createEntry,
  createVault,
  deleteEntry as coreDeleteEntry,
  displayHost,
  findMatchingEntries,
  generateTotp,
  parseTarget,
  saveVault,
  searchEntries,
  unlockVault,
  updateEntry,
  type Entry,
  type VaultFile,
  type VaultSession,
} from '@keyhole/core';
import {
  isTrustedExtensionSender,
  requestSchema,
  type EntrySummary,
  type Request,
  type Response,
} from '../shared/messages.ts';
import { clearVaultFile, hasVault, loadPrefs, loadVaultFile, savePrefs, saveVaultFile } from '../shared/storage.ts';

const AUTO_LOCK_ALARM = 'keyhole-auto-lock';
const HEARTBEAT_ALARM = 'keyhole-heartbeat';

/** THE session. Module scope, in-memory only, cleared on lock. */
let session: VaultSession | null = null;
let vaultFile: VaultFile | null = null;
let lastActivity = 0;

// ---------------------------------------------------------------------------
// Lock management
// ---------------------------------------------------------------------------

function lock(): void {
  session = null;
  // vaultFile is ciphertext, safe to keep, but drop it so a stale envelope can
  // never be written back over a newer one after a re-unlock.
  vaultFile = null;
  lastActivity = 0;
  void chrome.alarms.clear(HEARTBEAT_ALARM);
  void chrome.action.setBadgeText({ text: '' });
}

async function markUnlocked(newSession: VaultSession, file: VaultFile): Promise<void> {
  session = newSession;
  vaultFile = file;
  lastActivity = Date.now();

  await savePrefs({ autoLockMinutes: newSession.data.settings.autoLockMinutes });
  // 0.5 min is Chrome's practical minimum alarm period.
  await chrome.alarms.create(HEARTBEAT_ALARM, { periodInMinutes: 0.4 });
  await chrome.action.setBadgeText({ text: '🔓' });
  await chrome.action.setBadgeBackgroundColor({ color: '#4f46e5' });
}

function touch(): void {
  if (session) lastActivity = Date.now();
}

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name !== HEARTBEAT_ALARM && alarm.name !== AUTO_LOCK_ALARM) return;
  if (!session) return;
  const timeoutMs = session.data.settings.autoLockMinutes * 60_000;
  if (Date.now() - lastActivity >= timeoutMs) lock();
});

// Locking on browser start is implicit — a fresh worker has no session — but
// being explicit documents the intent and clears any stale badge.
chrome.runtime.onStartup.addListener(() => lock());
chrome.runtime.onInstalled.addListener(() => lock());

// ---------------------------------------------------------------------------
// Message routing
// ---------------------------------------------------------------------------

chrome.runtime.onMessage.addListener((raw, sender, sendResponse) => {
  // Reject anything not from our own extension pages *before* parsing. Content
  // scripts and other extensions never get past this line.
  if (!isTrustedExtensionSender(sender)) {
    sendResponse({ ok: false, error: 'Unauthorized sender.' } satisfies Response);
    return false;
  }

  const parsed = requestSchema.safeParse(raw);
  if (!parsed.success) {
    sendResponse({ ok: false, error: 'Malformed request.' } satisfies Response);
    return false;
  }

  handle(parsed.data)
    .then(sendResponse)
    .catch((err: unknown) => {
      console.error('Handler failed:', err);
      sendResponse({ ok: false, error: 'Internal error.' } satisfies Response);
    });

  return true; // async response
});

/** Reject external messages outright. Keyhole has no public API. */
chrome.runtime.onMessageExternal?.addListener((_msg, _sender, sendResponse) => {
  sendResponse({ ok: false, error: 'Keyhole does not accept external messages.' } satisfies Response);
  return false;
});

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async function handle(request: Request): Promise<Response> {
  switch (request.type) {
    case 'KEEPALIVE':
      return { ok: true, type: 'OK' };

    case 'GET_STATE': {
      const prefs = await loadPrefs();
      return {
        ok: true,
        type: 'STATE',
        locked: session === null,
        hasVault: await hasVault(),
        entryCount: session?.data.entries.length ?? 0,
        autoLockMinutes: session?.data.settings.autoLockMinutes ?? prefs.autoLockMinutes,
      };
    }

    case 'CREATE_VAULT': {
      if (await hasVault()) return { ok: false, error: 'A vault already exists in this browser.' };
      try {
        const { file, session: newSession } = await createVault(request.masterPassword);
        await saveVaultFile(file);
        await markUnlocked(newSession, file);
        return { ok: true, type: 'OK' };
      } catch (err) {
        return { ok: false, error: describe(err) };
      }
    }

    case 'UNLOCK': {
      const file = await loadVaultFile();
      if (!file) return { ok: false, error: 'No vault stored in this browser.' };
      try {
        await markUnlocked(await unlockVault(file, request.masterPassword), file);
        return { ok: true, type: 'OK' };
      } catch (err) {
        lock(); // fail closed
        return { ok: false, error: describe(err) };
      }
    }

    case 'LOCK':
      lock();
      return { ok: true, type: 'OK' };

    case 'IMPORT_VAULT': {
      try {
        const { parseVaultFile } = await import('@keyhole/core');
        const file = parseVaultFile(request.file);
        await saveVaultFile(file);
        lock(); // imported vault needs its own master password
        return { ok: true, type: 'OK' };
      } catch (err) {
        return { ok: false, error: describe(err) };
      }
    }

    case 'EXPORT_VAULT': {
      const file = await loadVaultFile();
      if (!file) return { ok: false, error: 'No vault to export.' };
      return { ok: true, type: 'EXPORT', file };
    }

    case 'LIST_ENTRIES': {
      if (!session) return { ok: false, error: 'Vault is locked.' };
      touch();
      const entries = searchEntries(session.data, request.query ?? '');
      return { ok: true, type: 'ENTRIES', entries: entries.map(toSummary) };
    }

    case 'MATCH_TAB': {
      if (!session) return { ok: false, error: 'Vault is locked.' };
      touch();
      const url = await tabUrl(request.tabId);
      if (!url) return { ok: true, type: 'ENTRIES', entries: [] };
      const matches = findMatchingEntries(session.data.entries, url, 'subdomain');
      return {
        ok: true,
        type: 'ENTRIES',
        entries: matches.map((m) => ({ ...toSummary(m.entry), matchStrength: m.strength })),
      };
    }

    case 'REVEAL_SECRET': {
      if (!session) return { ok: false, error: 'Vault is locked.' };
      touch();
      const entry = session.data.entries.find((e) => e.id === request.entryId);
      if (!entry) return { ok: false, error: 'Entry not found.' };

      let value: string;
      if (request.field === 'password') value = entry.password;
      else if (request.field === 'username') value = entry.username;
      else {
        if (!entry.totpSecret) return { ok: false, error: 'No TOTP secret on this entry.' };
        value = (await generateTotp(entry.totpSecret)).code;
      }
      return {
        ok: true,
        type: 'SECRET',
        value,
        clipboardClearSeconds: session.data.settings.clipboardClearSeconds,
      };
    }

    case 'FILL':
      return fill(request.entryId, request.tabId);

    case 'SAVE_ENTRY':
      return saveEntry(request.entry);

    case 'DELETE_ENTRY': {
      if (!session || !vaultFile) return { ok: false, error: 'Vault is locked.' };
      touch();
      try {
        session.data = coreDeleteEntry(session.data, request.entryId);
        await persist();
        return { ok: true, type: 'OK' };
      } catch (err) {
        return { ok: false, error: describe(err) };
      }
    }

    default: {
      const exhaustive: never = request;
      return { ok: false, error: `Unhandled request: ${JSON.stringify(exhaustive)}` };
    }
  }
}

// ---------------------------------------------------------------------------
// Autofill — the privileged path
// ---------------------------------------------------------------------------

async function fill(entryId: string, tabId: number): Promise<Response> {
  if (!session) return { ok: false, error: 'Vault is locked.' };
  touch();

  const entry = session.data.entries.find((e) => e.id === entryId);
  if (!entry) return { ok: false, error: 'Entry not found.' };

  // TOCTOU GUARD. The popup resolved this entry against the tab's URL some
  // moments ago. Between then and now the page could have navigated — including
  // to an attacker's origin. Re-read the URL and re-run matching *here*, at the
  // instant before the credential leaves this process.
  const currentUrl = await tabUrl(tabId);
  if (!currentUrl) return { ok: false, error: 'Cannot read that tab.' };

  const target = parseTarget(currentUrl);
  if (!target) return { ok: false, error: 'Keyhole only fills on http(s) pages.' };

  const stillMatches = findMatchingEntries([entry], currentUrl, 'subdomain').length > 0;
  if (!stillMatches) {
    return { ok: false, error: `That page (${target.hostname}) does not match this entry. Nothing was filled.` };
  }

  try {
    // Injected on demand under `activeTab`, so Keyhole has no standing access to
    // any site. The grant exists only because the user just invoked the popup.
    await chrome.scripting.executeScript({ target: { tabId, allFrames: false }, files: ['content.js'] });
  } catch {
    return { ok: false, error: 'Cannot inject into this page. Chrome blocks extension pages and the Web Store.' };
  }

  try {
    const result = (await chrome.tabs.sendMessage(tabId, {
      type: 'KEYHOLE_FILL',
      username: entry.username,
      password: entry.password,
      expectedOrigin: target.origin,
    })) as { filledUsername?: boolean; filledPassword?: boolean } | undefined;

    if (!result) return { ok: false, error: 'No login form responded on that page.' };
    if (!result.filledUsername && !result.filledPassword) {
      return { ok: false, error: 'No login fields found on that page.' };
    }
    return {
      ok: true,
      type: 'FILLED',
      filledUsername: result.filledUsername === true,
      filledPassword: result.filledPassword === true,
    };
  } catch {
    return { ok: false, error: 'The page did not accept the fill request.' };
  }
}

// ---------------------------------------------------------------------------
// Entry persistence
// ---------------------------------------------------------------------------

async function saveEntry(raw: unknown): Promise<Response> {
  if (!session || !vaultFile) return { ok: false, error: 'Vault is locked.' };
  touch();

  const input = raw as Partial<Entry> | null;
  if (!input || typeof input.title !== 'string') return { ok: false, error: 'Invalid entry.' };

  const patch = {
    title: input.title,
    username: input.username ?? '',
    password: input.password ?? '',
    urls: Array.isArray(input.urls) ? input.urls : [],
    notes: input.notes ?? '',
    tags: Array.isArray(input.tags) ? input.tags : [],
    totpSecret: input.totpSecret ?? null,
  };

  try {
    session.data =
      typeof input.id === 'string' && session.data.entries.some((e) => e.id === input.id)
        ? updateEntry(session.data, input.id, patch)
        : createEntry(session.data, patch).data;
    await persist();
    return { ok: true, type: 'OK' };
  } catch (err) {
    return { ok: false, error: describe(err) };
  }
}

async function persist(): Promise<void> {
  if (!session || !vaultFile) throw new Error('Vault is locked.');
  vaultFile = await saveVault(session, vaultFile);
  await saveVaultFile(vaultFile);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function toSummary(entry: Entry): EntrySummary {
  return {
    id: entry.id,
    title: entry.title,
    username: entry.username,
    host: entry.urls[0] ? displayHost(entry.urls[0]) : null,
    hasTotp: entry.totpSecret !== null,
  };
}

async function tabUrl(tabId: number): Promise<string | null> {
  try {
    const tab = await chrome.tabs.get(tabId);
    return tab.url ?? null;
  } catch {
    return null;
  }
}

/** Collapse internal error detail into user-facing text without leaking structure. */
function describe(err: unknown): string {
  if (err instanceof DecryptionError) return 'Wrong master password.';
  if (err instanceof Error) return err.message;
  return 'Something went wrong.';
}

export { clearVaultFile };
