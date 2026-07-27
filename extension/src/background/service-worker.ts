/**
 * Keyhole service worker — the only process that ever holds decrypted data.
 *
 * Invariants:
 *  - The session (CryptoKey + decrypted vault) lives in a module-scope variable
 *    and is NEVER written to chrome.storage, IndexedDB, or anywhere persistent.
 *  - Privileged messages are gated on `isTrustedExtensionSender`.
 *  - Content scripts may only send SUGGEST_FOR_PAGE / FILL_FROM_PAGE / SAVE_FROM_PAGE;
 *    matching always uses sender.tab's URL from Chrome, never a page-supplied URL.
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
  deriveSyncAuthSecret,
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
import { healthCheck, registerAccount, fetchPrelogin, getVault, putVault, SyncClientError } from '../../../app/src/sync/client.ts';
import { performSync } from '../../../app/src/sync/runSync.ts';
import {
  contentScriptRequestSchema,
  isContentScriptSender,
  isTrustedExtensionSender,
  requestSchema,
  type ContentScriptRequest,
  type EntrySummary,
  type Request,
  type Response,
} from '../shared/messages.ts';
import { clearVaultFile, hasVault, loadPrefs, loadSyncConfig, loadVaultFile, savePrefs, saveSyncConfig, saveVaultFile } from '../shared/storage.ts';

const AUTO_LOCK_ALARM = 'keyhole-auto-lock';
const HEARTBEAT_ALARM = 'keyhole-heartbeat';

/** THE session. Module scope, in-memory only, cleared on lock. */
let session: VaultSession | null = null;
let vaultFile: VaultFile | null = null;
let lastActivity = 0;
/** Sync auth secret derived once per unlock; never persisted. */
let syncAuthSecretB64: string | null = null;

// ---------------------------------------------------------------------------
// Lock management
// ---------------------------------------------------------------------------

function lock(): void {
  session = null;
  // vaultFile is ciphertext, safe to keep, but drop it so a stale envelope can
  // never be written back over a newer one after a re-unlock.
  vaultFile = null;
  lastActivity = 0;
  syncAuthSecretB64 = null;
  void chrome.alarms.clear(HEARTBEAT_ALARM);
  void clearMatchBadge();
}

async function markUnlocked(newSession: VaultSession, file: VaultFile): Promise<void> {
  session = newSession;
  vaultFile = file;
  lastActivity = Date.now();

  await savePrefs({
    autoLockMinutes: newSession.data.settings.autoLockMinutes,
    theme: newSession.data.settings.theme,
  });
  // 0.5 min is Chrome's practical minimum alarm period.
  await chrome.alarms.create(HEARTBEAT_ALARM, { periodInMinutes: 0.4 });
  await chrome.action.setBadgeBackgroundColor({ color: '#0f62d0' });
  try {
    await chrome.action.setBadgeTextColor({ color: '#ffffff' });
  } catch {
    // Older Chromium builds may lack setBadgeTextColor.
  }
  await updateMatchBadge();
  // Warm the content script on the active tab so suggestions work without a reload.
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (typeof tab?.id === 'number') await ensureContentScript(tab.id, tab.url);
  } catch {
    // Ignore — no active tab.
  }
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

/** Forget a closed vault window so the next open creates a fresh one. */
chrome.windows.onRemoved.addListener((windowId) => {
  void chrome.storage.session.get('keyhole.vaultWindowId').then((stored) => {
    if (stored['keyhole.vaultWindowId'] === windowId) {
      void chrome.storage.session.remove('keyhole.vaultWindowId');
    }
  });
});

// Toolbar badge: matching login count for the active tab while unlocked.
chrome.tabs.onActivated.addListener((info) => {
  void updateMatchBadge(info.tabId);
  void ensureContentScript(info.tabId);
});
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' || changeInfo.url) {
    if (tab.active) void updateMatchBadge(tabId);
    void ensureContentScript(tabId, changeInfo.url ?? tab.url);
  }
});
chrome.windows.onFocusChanged.addListener((windowId) => {
  if (windowId === chrome.windows.WINDOW_ID_NONE) return;
  void updateMatchBadge();
});

// ---------------------------------------------------------------------------
// Message routing
// ---------------------------------------------------------------------------

chrome.runtime.onMessage.addListener((raw, sender, sendResponse) => {
  if (isTrustedExtensionSender(sender)) {
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
  }

  // Narrow content-script surface: metadata matches + fill of a chosen entry.
  // Never accept a client-supplied tab id or URL.
  if (isContentScriptSender(sender)) {
    const parsed = contentScriptRequestSchema.safeParse(raw);
    if (!parsed.success) {
      sendResponse({ ok: false, error: 'Unauthorized sender.' } satisfies Response);
      return false;
    }

    handleContentScript(parsed.data, sender)
      .then(sendResponse)
      .catch((err: unknown) => {
        console.error('Content-script handler failed:', err);
        sendResponse({ ok: false, error: 'Internal error.' } satisfies Response);
      });

    return true;
  }

  sendResponse({ ok: false, error: 'Unauthorized sender.' } satisfies Response);
  return false;
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
        theme: session?.data.settings.theme ?? prefs.theme,
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

    case 'SAVE_ENTRY': {
      const result = await saveEntry(request.entry);
      if (result.ok) void updateMatchBadge();
      return result;
    }

    case 'DELETE_ENTRY': {
      if (!session || !vaultFile) return { ok: false, error: 'Vault is locked.' };
      touch();
      try {
        session.data = coreDeleteEntry(session.data, request.entryId);
        await persist();
        void updateMatchBadge();
        return { ok: true, type: 'OK' };
      } catch (err) {
        return { ok: false, error: describe(err) };
      }
    }

    case 'GET_SYNC_CONFIG': {
      const config = await loadSyncConfig();
      return {
        ok: true,
        type: 'SYNC_CONFIG',
        baseUrl: config?.baseUrl ?? null,
        accountId: config?.accountId ?? null,
        hasSyncAuthSecret: syncAuthSecretB64 !== null,
      };
    }

    case 'SET_THEME': {
      await savePrefs({ theme: request.theme });
      if (session) {
        session = {
          ...session,
          data: {
            ...session.data,
            settings: { ...session.data.settings, theme: request.theme },
          },
        };
        await persist();
      }
      return { ok: true, type: 'OK' };
    }

    case 'SAVE_SYNC_CONFIG': {
      await saveSyncConfig({ baseUrl: request.baseUrl, accountId: request.accountId });
      return { ok: true, type: 'OK' };
    }

    case 'SYNC_REGISTER':
      return syncRegister(request.baseUrl, request.accountId, request.masterPassword);

    case 'SYNC_NOW':
      return syncNow(request.baseUrl, request.accountId, request.masterPassword);

    case 'SYNC_ADOPT_REMOTE':
      return syncAdoptRemote(request.baseUrl, request.accountId, request.masterPassword);

    case 'SYNC_OVERWRITE_REMOTE':
      return syncOverwriteRemote(request.baseUrl, request.accountId, request.masterPassword);

    default: {
      const exhaustive: never = request;
      return { ok: false, error: `Unhandled request: ${JSON.stringify(exhaustive)}` };
    }
  }
}

// ---------------------------------------------------------------------------
// Autofill — the privileged path
// ---------------------------------------------------------------------------

async function handleContentScript(request: ContentScriptRequest, sender: chrome.runtime.MessageSender): Promise<Response> {
  const tabId = sender.tab?.id;
  if (typeof tabId !== 'number') return { ok: false, error: 'Cannot read that tab.' };

  switch (request.type) {
    case 'SUGGEST_FOR_PAGE': {
      const prefs = await loadPrefs();
      const theme = session?.data.settings.theme ?? prefs.theme;
      if (!session) {
        return { ok: true, type: 'SUGGESTIONS', locked: true, theme, entries: [] };
      }
      touch();
      const url = await tabUrl(tabId);
      if (!url) return { ok: true, type: 'SUGGESTIONS', locked: false, theme, entries: [] };
      const matches = findMatchingEntries(session.data.entries, url, 'subdomain');
      return {
        ok: true,
        type: 'SUGGESTIONS',
        locked: false,
        theme,
        entries: matches.map((m) => ({ ...toSummary(m.entry), matchStrength: m.strength })),
      };
    }
    case 'FILL_FROM_PAGE':
      return fill(request.entryId, tabId);
    case 'SAVE_FROM_PAGE':
      return saveFromPage(tabId, request.username, request.password, request.entryId);
    default: {
      const exhaustive: never = request;
      return { ok: false, error: `Unhandled request: ${JSON.stringify(exhaustive)}` };
    }
  }
}

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
    const totp =
      entry.totpSecret !== null ? (await generateTotp(entry.totpSecret)).code : undefined;
    const result = (await chrome.tabs.sendMessage(tabId, {
      type: 'KEYHOLE_FILL',
      username: entry.username,
      password: entry.password,
      ...(totp !== undefined ? { totp } : {}),
      expectedOrigin: target.origin,
    })) as { filledUsername?: boolean; filledPassword?: boolean; filledTotp?: boolean } | undefined;

    if (!result) return { ok: false, error: 'No login form responded on that page.' };
    if (!result.filledUsername && !result.filledPassword && !result.filledTotp) {
      return { ok: false, error: 'No login fields found on that page.' };
    }
    return {
      ok: true,
      type: 'FILLED',
      filledUsername: result.filledUsername === true,
      filledPassword: result.filledPassword === true,
      filledTotp: result.filledTotp === true,
    };
  } catch {
    return { ok: false, error: 'The page did not accept the fill request.' };
  }
}

async function saveFromPage(
  tabId: number,
  username: string,
  password: string,
  entryId?: string,
): Promise<Response> {
  if (!session || !vaultFile) return { ok: false, error: 'Vault is locked.' };
  touch();

  const currentUrl = await tabUrl(tabId);
  if (!currentUrl) return { ok: false, error: 'Cannot read that tab.' };
  const target = parseTarget(currentUrl);
  if (!target) return { ok: false, error: 'Keyhole only saves logins for http(s) pages.' };

  try {
    if (typeof entryId === 'string') {
      const entry = session.data.entries.find((e) => e.id === entryId);
      if (!entry) return { ok: false, error: 'Entry not found.' };
      const stillMatches = findMatchingEntries([entry], currentUrl, 'subdomain').length > 0;
      if (!stillMatches) {
        return { ok: false, error: `That page (${target.hostname}) does not match this entry.` };
      }
      session.data = updateEntry(session.data, entryId, { username, password });
    } else {
      const title = target.hostname.replace(/^www\./, '') || 'Saved login';
      session.data = createEntry(session.data, {
        title,
        username,
        password,
        urls: [target.origin],
      }).data;
    }
    await persist();
    void updateMatchBadge(tabId);
    return { ok: true, type: 'OK' };
  } catch (err) {
    return { ok: false, error: describe(err) };
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
// Sync
// ---------------------------------------------------------------------------

function normalizeSyncUrl(baseUrl: string): string {
  return baseUrl.trim().replace(/\/+$/, '');
}

function normalizeAccountId(accountId: string): string {
  return accountId.trim().toLowerCase();
}

async function syncRegister(baseUrl: string, accountId: string, masterPassword: string): Promise<Response> {
  if (!session || !vaultFile) return { ok: false, error: 'Vault is locked.' };
  touch();

  const url = normalizeSyncUrl(baseUrl);
  const id = normalizeAccountId(accountId);
  if (url.length === 0 || id.length === 0) return { ok: false, error: 'Server URL and account id are required.' };

  try {
    // Confirm the password before talking to the server — otherwise a typo
    // surfaces as a cryptic "Unauthorized." from the sync API.
    await unlockVault(vaultFile, masterPassword);

    const ok = await healthCheck(url);
    if (!ok) {
      return {
        ok: false,
        error:
          'Sync server is not reachable. Confirm it is running (npm run dev:server) and the URL matches — usually http://127.0.0.1:8787.',
      };
    }

    const derived = await deriveSyncAuthSecret(masterPassword, vaultFile.kdf);
    const result = await registerAccount(url, id, derived, vaultFile);
    syncAuthSecretB64 = derived;
    await saveSyncConfig({ baseUrl: url, accountId: id });
    return { ok: true, type: 'SYNC_RESULT', message: `Registered as ${result.accountId} (server version ${result.version}).` };
  } catch (err) {
    return { ok: false, error: describeSync(err, 'Registration failed.') };
  }
}

async function syncNow(baseUrl: string, accountId: string, masterPassword?: string): Promise<Response> {
  if (!session || !vaultFile) return { ok: false, error: 'Vault is locked.' };
  touch();

  const url = normalizeSyncUrl(baseUrl);
  const id = normalizeAccountId(accountId);
  if (url.length === 0 || id.length === 0) return { ok: false, error: 'Server URL and account id are required.' };

  const password = masterPassword?.trim() ?? '';
  if (password.length === 0 && !syncAuthSecretB64) {
    return { ok: false, error: 'Enter your master password once this unlock to enable sync.' };
  }

  try {
    if (password.length > 0) {
      // Confirm the password unlocks *this* device's vault before paying for
      // network / Argon2 against the account's server-side KDF.
      await unlockVault(vaultFile, password);
    }

    const ok = await healthCheck(url);
    if (!ok) {
      return {
        ok: false,
        error:
          'Sync server is not reachable. Confirm it is running (npm run dev:server) and the URL matches — usually http://127.0.0.1:8787.',
      };
    }

    // Auth secret must be derived from the *account's* KDF (via prelogin), not
    // necessarily this device's local salt — otherwise Sync now 401s when the
    // account was registered from another vault/device with the same password.
    let secret = syncAuthSecretB64;
    if (password.length > 0) {
      const { kdf: accountKdf } = await fetchPrelogin(url, id);
      secret = await deriveSyncAuthSecret(password, accountKdf);
      syncAuthSecretB64 = secret;
    }
    if (!secret) return { ok: false, error: 'Enter your master password once this unlock to enable sync.' };

    await saveSyncConfig({ baseUrl: url, accountId: id });

    const result = await performSync({
      baseUrl: url,
      accountId: id,
      syncAuthSecretB64: secret,
      ...(password.length > 0 ? { masterPassword: password } : {}),
      localFile: vaultFile,
      session,
    });

    session = result.session;
    vaultFile = result.file;
    await saveVaultFile(vaultFile);
    void updateMatchBadge();

    return { ok: true, type: 'SYNC_RESULT', message: result.message };
  } catch (err) {
    if (err instanceof SyncClientError && err.code === 'vault_mismatch') {
      return { ok: true, type: 'SYNC_VAULT_MISMATCH', message: err.message };
    }
    return { ok: false, error: describeSync(err, 'Sync failed.') };
  }
}

/**
 * Replace the vault on this device with the account's server copy.
 * Use when Sync now reports a vault-id mismatch and this device should follow the server.
 */
async function syncAdoptRemote(baseUrl: string, accountId: string, masterPassword: string): Promise<Response> {
  if (!session || !vaultFile) return { ok: false, error: 'Vault is locked.' };
  touch();

  const url = normalizeSyncUrl(baseUrl);
  const id = normalizeAccountId(accountId);
  if (url.length === 0 || id.length === 0) return { ok: false, error: 'Server URL and account id are required.' };

  try {
    const ok = await healthCheck(url);
    if (!ok) {
      return {
        ok: false,
        error:
          'Sync server is not reachable. Confirm it is running (npm run dev:server) and the URL matches — usually http://127.0.0.1:8787.',
      };
    }

    const { kdf: accountKdf } = await fetchPrelogin(url, id);
    const derived = await deriveSyncAuthSecret(masterPassword, accountKdf);
    const remote = await getVault(url, id, derived);
    const remoteSession = await unlockVault(remote.envelope, masterPassword);

    await saveVaultFile(remote.envelope);
    await markUnlocked(remoteSession, remote.envelope);
    syncAuthSecretB64 = derived;
    await saveSyncConfig({ baseUrl: url, accountId: id });

    return {
      ok: true,
      type: 'SYNC_RESULT',
      message: `Replaced this device's vault with the server copy (v${remote.version}).`,
    };
  } catch (err) {
    return { ok: false, error: describeSync(err, 'Could not adopt the server vault.') };
  }
}

/**
 * Overwrite the server account with this device's vault (and rotate sync credentials).
 * Use when Sync now reports a vault-id mismatch and the server should follow this device.
 */
async function syncOverwriteRemote(baseUrl: string, accountId: string, masterPassword: string): Promise<Response> {
  if (!session || !vaultFile) return { ok: false, error: 'Vault is locked.' };
  touch();

  const url = normalizeSyncUrl(baseUrl);
  const id = normalizeAccountId(accountId);
  if (url.length === 0 || id.length === 0) return { ok: false, error: 'Server URL and account id are required.' };

  try {
    await unlockVault(vaultFile, masterPassword);

    const ok = await healthCheck(url);
    if (!ok) {
      return {
        ok: false,
        error:
          'Sync server is not reachable. Confirm it is running (npm run dev:server) and the URL matches — usually http://127.0.0.1:8787.',
      };
    }

    const { kdf: accountKdf } = await fetchPrelogin(url, id);
    const currentSecret = await deriveSyncAuthSecret(masterPassword, accountKdf);
    const nextSecret = await deriveSyncAuthSecret(masterPassword, vaultFile.kdf);
    const remote = await getVault(url, id, currentSecret);

    const uploaded = await putVault(url, id, currentSecret, vaultFile, remote.version, nextSecret);
    if (uploaded.conflict) {
      return {
        ok: false,
        error: 'Server changed during overwrite. Try again.',
      };
    }

    syncAuthSecretB64 = nextSecret;
    await saveSyncConfig({ baseUrl: url, accountId: id });
    return {
      ok: true,
      type: 'SYNC_RESULT',
      message: `Replaced the server vault with this device's copy (v${uploaded.result.version}).`,
    };
  } catch (err) {
    return { ok: false, error: describeSync(err, 'Could not overwrite the server vault.') };
  }
}

function describeSync(err: unknown, fallback: string): string {
  if (err instanceof DecryptionError) return 'Wrong master password.';
  if (err instanceof SyncClientError) {
    if (err.status === 429) return err.message;
    if (err.status === 401) return err.message;
    return err.message;
  }
  if (err instanceof TypeError && /fetch|network|load failed/i.test(err.message)) {
    return 'Could not reach the sync server. Confirm the server is running and host permission was granted.';
  }
  if (err instanceof Error) return err.message;
  return fallback;
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

async function clearMatchBadge(): Promise<void> {
  try {
    await chrome.action.setBadgeText({ text: '' });
  } catch {
    // Ignore — action may be unavailable in tests.
  }
}

/**
 * Inject the content script when we have host access (optional permissions or
 * localhost). Declarative content_scripts miss some SPA navigations; this keeps
 * Reddit-style logins covered after unlock / tab changes.
 */
async function ensureContentScript(tabId: number, url?: string | undefined): Promise<void> {
  if (!session) return;
  const pageUrl = url ?? (await tabUrl(tabId));
  if (!pageUrl || !/^https?:/i.test(pageUrl)) return;
  try {
    await chrome.scripting.executeScript({
      target: { tabId, allFrames: false },
      files: ['content.js'],
    });
  } catch {
    // No host permission, chrome:// page, or otherwise blocked.
  }
}

/**
 * Show how many vault logins match the active tab on the toolbar icon.
 * Empty when locked, or when the tab has no matches / no readable URL.
 */
async function updateMatchBadge(tabId?: number): Promise<void> {
  if (!session) {
    await clearMatchBadge();
    return;
  }

  let id = tabId;
  if (typeof id !== 'number') {
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      id = tab?.id;
    } catch {
      await clearMatchBadge();
      return;
    }
  }
  if (typeof id !== 'number') {
    await clearMatchBadge();
    return;
  }

  const url = await tabUrl(id);
  if (!url || !parseTarget(url)) {
    try {
      await chrome.action.setBadgeText({ tabId: id, text: '' });
    } catch {
      await clearMatchBadge();
    }
    return;
  }

  const count = findMatchingEntries(session.data.entries, url, 'subdomain').length;
  const text = count <= 0 ? '' : count > 99 ? '99+' : String(count);
  try {
    await chrome.action.setBadgeText({ tabId: id, text });
  } catch {
    await chrome.action.setBadgeText({ text });
  }
}

/** Collapse internal error detail into user-facing text without leaking structure. */
function describe(err: unknown): string {
  if (err instanceof DecryptionError) return 'Wrong master password.';
  if (err instanceof Error) return err.message;
  return 'Something went wrong.';
}

export { clearVaultFile };
