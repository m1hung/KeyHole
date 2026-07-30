/**
 * Keyhole service worker — the only process that ever holds decrypted data.
 *
 * Invariants:
 *  - The session (CryptoKey + decrypted vault) lives in a module-scope variable
 *    and is NEVER written to chrome.storage, IndexedDB, or anywhere persistent.
 *  - Privileged messages are gated on `isTrustedExtensionSender`.
 *  - Content scripts may only send SUGGEST_FOR_PAGE / FILL_FROM_PAGE / SAVE_FROM_PAGE;
 *    matching always uses the URL Chrome attributes to the sender (sender.url for
 *    the sending frame, sender.tab.url for the page), never a page-supplied URL.
 *  - Autofill re-verifies the target frame's URL immediately before dispatching,
 *    closing the window where a page navigates between the user's click and the
 *    credential arriving.
 *  - A credential is delivered to ONE frame, addressed by frame id. Never
 *    `tabs.sendMessage` without a frameId: that broadcasts to every frame in the
 *    tab, which since we inject into subframes would hand the password to every
 *    ad iframe on the page.
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
  analyzeVaultHealth,
  createEntry,
  changeMasterPassword,
  createVault,
  deleteEntry as coreDeleteEntry,
  deriveSyncAuthSecret,
  displayHost,
  findMatchingEntries,
  generateTotp,
  liveEntries,
  matchRank,
  parseTarget,
  purgeEntry,
  purgeExpiredTrash,
  registrableDomain,
  restoreEntry,
  saveVault,
  searchEntries,
  trashedEntries,
  unlockVault,
  updateEntry,
  type Entry,
  type EntryInput,
  type MatchMode,
  type VaultFile,
  type VaultSession,
} from '@keyhole/core';
import { healthCheck, registerAccount, fetchPrelogin, getVault, putVault, SyncClientError } from '../../../app/src/sync/client.ts';
import { performSync, rotateSyncAuthAfterRekey } from '../../../app/src/sync/runSync.ts';
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
import { clearAllStoredData, hasVault, loadPrefs, loadSyncConfig, loadVaultFile, savePrefs, saveSyncConfig, saveVaultFile } from '../shared/storage.ts';

const AUTO_LOCK_ALARM = 'keyhole-auto-lock';
const HEARTBEAT_ALARM = 'keyhole-heartbeat';

/**
 * How permissively autofill matches the page — see core/src/url-match.ts.
 *
 * `domain` also offers logins saved elsewhere on the same registrable domain, so
 * an entry for accounts.example.com is suggested on billing.example.com, and an
 * entry saved as www.example.com is suggested on example.com. It stays
 * public-suffix aware: a.github.io never sees b.github.io's logins, and an
 * unrecognised namespace falls back to the stricter host/subdomain rules rather
 * than guessing.
 *
 * ONE CONSTANT FOR EVERY READ PATH — deliberately. Suggesting is a promise that
 * Fill will work, and the fill path's TOCTOU re-check is the actual security
 * boundary. If suggest were looser than fill, every similar-site suggestion
 * would be a button that refuses itself; if fill were looser than suggest, we
 * would fill on pages we never vetted. Do not fork these.
 */
const MATCH_MODE: MatchMode = 'domain';

/**
 * Matching for *overwriting* a stored entry from a page (the save/update offer).
 *
 * Intentionally stricter than MATCH_MODE. Reading is recoverable — a suggestion
 * you did not want costs a dismissal. Writing is not: updating the login saved
 * for a sibling host, because the usernames happened to agree, destroys the old
 * password with nothing to restore from. A same-site page gets a new entry.
 */
const SAVE_MATCH_MODE: MatchMode = 'subdomain';

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

  // Sweep expired trash here, not in unlockVault: core stays pure, and a read
  // that silently rewrites the vault would surprise every caller.
  const swept = purgeExpiredTrash(session.data);
  if (swept !== session.data) {
    session.data = swept;
    await persist();
  }

  await savePrefs({
    autoLockMinutes: session.data.settings.autoLockMinutes,
    theme: session.data.settings.theme,
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

/**
 * Keyboard autofill, without opening the popup.
 *
 * A command invocation is a user gesture on the active tab, so it carries the same
 * `activeTab` grant the toolbar click does, and it runs through the identical
 * `fill()` path — frame resolution, TOCTOU re-check and single-frame delivery
 * included. It is a shortcut for the click, not a second, looser way in.
 *
 * WHEN IN DOUBT, DO NOTHING. If several entries match the page equally well, this
 * refuses rather than picking one: a hotkey that silently types the wrong account's
 * password into a login form is worse than a hotkey that does nothing, and there is
 * no UI here in which to disambiguate.
 */
chrome.commands?.onCommand.addListener((command, tab) => {
  if (command !== 'fill-best-match') return;
  void fillBestMatch(tab?.id);
});

async function fillBestMatch(tabId: number | undefined): Promise<void> {
  if (typeof tabId !== 'number' || !session) return;
  touch();

  const url = await tabUrl(tabId);
  if (!url) return;

  const matches = findMatchingEntries(session.data.entries, url, MATCH_MODE);
  const best = matches[0];
  if (!best) return;

  // Ambiguous when the runner-up is just as good a match — "same site, two
  // accounts" is the common case, and only the user knows which one they want.
  const runnerUp = matches[1];
  if (runnerUp && matchRank(runnerUp.strength) === matchRank(best.strength)) {
    await flashBadge(tabId, '?');
    return;
  }

  const result = await fill(best.entry.id, tabId);
  if (!result.ok) await flashBadge(tabId, '!');
}

/**
 * Say something on the toolbar icon, since a keyboard fill has no window to report
 * into. Restores the match count afterwards.
 */
async function flashBadge(tabId: number, text: string): Promise<void> {
  try {
    await chrome.action.setBadgeText({ tabId, text });
    setTimeout(() => void updateMatchBadge(tabId), 2000);
  } catch {
    // Badge unavailable; the fill result is unaffected.
  }
}

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
        // Live only: the trash is reported separately, and counting it here would
        // make "12 entries" disagree with the list the user is looking at.
        entryCount: session ? liveEntries(session.data).length : 0,
        autoLockMinutes: session?.data.settings.autoLockMinutes ?? prefs.autoLockMinutes,
        theme: session?.data.settings.theme ?? prefs.theme,
        breachCheckEnabled: session?.data.settings.breachCheckEnabled ?? false,
        foreignSchemaVersion: session?.foreignSchemaVersion ?? null,
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

    case 'RESET_VAULT': {
      // Drop the session FIRST. `persist()` writes `vaultFile` back to storage,
      // so a save racing this reset could otherwise re-create the envelope a
      // moment after it was deleted; after `lock()` there is nothing to write.
      lock();
      await clearAllStoredData();
      return { ok: true, type: 'OK' };
    }

    case 'CHANGE_MASTER_PASSWORD':
      return changeMasterPasswordHere(request.currentPassword, request.newPassword);

    case 'HEALTH_REPORT': {
      if (!session) return { ok: false, error: 'Vault is locked.' };
      touch();
      // Runs here, in the only process holding decrypted entries, and returns
      // findings rather than passwords. Nothing is persisted or sent anywhere.
      const report = analyzeVaultHealth(session.data);
      return {
        ok: true,
        type: 'HEALTH',
        issues: report.issues,
        loginCount: report.loginCount,
        checkedAt: report.checkedAt,
      };
    }

    case 'LIST_ENTRIES': {
      if (!session) return { ok: false, error: 'Vault is locked.' };
      touch();
      const entries = searchEntries(session.data, request.query ?? '');
      return { ok: true, type: 'ENTRIES', entries: entries.map(toSummary) };
    }

    case 'GET_ENTRY': {
      if (!session) return { ok: false, error: 'Vault is locked.' };
      touch();
      const entry = session.data.entries.find((e) => e.id === request.entryId);
      if (!entry) return { ok: false, error: 'Entry not found.' };
      return {
        ok: true,
        type: 'ENTRY',
        entry: {
          id: entry.id,
          title: entry.title,
          username: entry.username,
          password: entry.password,
          urls: entry.urls,
          notes: entry.notes,
          tags: entry.tags,
          totpSecret: entry.totpSecret,
          totpConfig: entry.totpConfig,
          customFields: entry.customFields,
          attachments: entry.attachments,
        },
      };
    }

    case 'MATCH_TAB': {
      if (!session) return { ok: false, error: 'Vault is locked.' };
      touch();
      const url = await tabUrl(request.tabId);
      if (!url) return { ok: true, type: 'ENTRIES', entries: [] };
      const matches = findMatchingEntries(session.data.entries, url, MATCH_MODE);
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
        value = (await generateTotp(entry.totpSecret, entry.totpConfig ?? undefined)).code;
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

    case 'LIST_TRASH': {
      if (!session) return { ok: false, error: 'Vault is locked.' };
      touch();
      const entries = trashedEntries(session.data).map((entry) => ({
        ...toSummary(entry),
        deletedAt: entry.deletedAt,
      }));
      return { ok: true, type: 'ENTRIES', entries };
    }

    case 'RESTORE_ENTRY': {
      if (!session || !vaultFile) return { ok: false, error: 'Vault is locked.' };
      touch();
      try {
        session.data = restoreEntry(session.data, request.entryId);
        await persist();
        void updateMatchBadge();
        return { ok: true, type: 'OK' };
      } catch (err) {
        return { ok: false, error: describe(err) };
      }
    }

    case 'PURGE_ENTRY': {
      if (!session || !vaultFile) return { ok: false, error: 'Vault is locked.' };
      touch();
      try {
        session.data = purgeEntry(session.data, request.entryId);
        await persist();
        return { ok: true, type: 'OK' };
      } catch (err) {
        return { ok: false, error: describe(err) };
      }
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

    case 'SET_BREACH_CHECK': {
      if (!session || !vaultFile) return { ok: false, error: 'Vault is locked.' };
      touch();
      session = {
        ...session,
        data: {
          ...session.data,
          settings: { ...session.data.settings, breachCheckEnabled: request.enabled },
        },
      };
      await persist();
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

/**
 * One frame of a tab: the id to address it by, and the URL Chrome says it holds.
 *
 * Login forms very often live in a cross-origin child frame — hoyoverse.com puts
 * its whole login UI in an `account.hoyoverse.com` iframe, and every hosted IdP
 * widget works the same way. Matching and filling therefore happen per frame, not
 * per tab. `url` must always come from Chrome (`sender.url`) or from our own
 * isolated-world probe, never from a page-supplied value.
 */
interface FrameTarget {
  frameId: number;
  url: string;
}

/** The frame a content-script message came from. */
function senderFrame(sender: chrome.runtime.MessageSender): FrameTarget | null {
  if (typeof sender.url !== 'string' || sender.url.length === 0) return null;
  return { frameId: typeof sender.frameId === 'number' ? sender.frameId : 0, url: sender.url };
}

async function handleContentScript(request: ContentScriptRequest, sender: chrome.runtime.MessageSender): Promise<Response> {
  const tabId = sender.tab?.id;
  if (typeof tabId !== 'number') return { ok: false, error: 'Cannot read that tab.' };
  // The sending frame, per Chrome. A page cannot forge either field, and for a
  // subframe this is the login form's real origin rather than the address bar's.
  const frame = senderFrame(sender);

  switch (request.type) {
    case 'SUGGEST_FOR_PAGE': {
      const prefs = await loadPrefs();
      const theme = session?.data.settings.theme ?? prefs.theme;
      if (!session) {
        return { ok: true, type: 'SUGGESTIONS', locked: true, theme, entries: [] };
      }
      touch();
      const url = frame?.url ?? (await tabUrl(tabId));
      if (!url) return { ok: true, type: 'SUGGESTIONS', locked: false, theme, entries: [] };
      const matches = findMatchingEntries(session.data.entries, url, MATCH_MODE);
      return {
        ok: true,
        type: 'SUGGESTIONS',
        locked: false,
        theme,
        entries: matches.map((m) => ({ ...toSummary(m.entry), matchStrength: m.strength })),
      };
    }
    case 'FILL_FROM_PAGE':
      // The user clicked a suggestion rendered inside this frame, so fill exactly
      // this frame — no probing, no guessing, no broadcast.
      return fill(request.entryId, tabId, frame);
    case 'SAVE_FROM_PAGE':
      return saveFromPage(tabId, request.username, request.password, request.entryId, frame);
    default: {
      const exhaustive: never = request;
      return { ok: false, error: `Unhandled request: ${JSON.stringify(exhaustive)}` };
    }
  }
}

/**
 * The narrowest match pattern that covers a URL's whole site, for an optional
 * permission request.
 *
 * `activeTab` — what the popup's click grants — only covers the top frame's
 * origin. A login form in a cross-origin child frame (`account.hoyoverse.com`
 * inside `genshin.hoyoverse.com`) therefore stays out of reach until the user
 * allows the site. Asking for `*://*.hoyoverse.com/*` covers the frame and its
 * siblings without asking for the whole web.
 */
function siteAccessPattern(url: string): string | null {
  const target = parseTarget(url);
  if (!target) return null;
  const base = registrableDomain(target.hostname);
  // `*.example.com` includes example.com itself in Chrome's match-pattern rules.
  return base !== null ? `*://*.${base}/*` : `*://${target.hostname}/*`;
}

async function hasSiteAccess(pattern: string): Promise<boolean> {
  try {
    return await chrome.permissions.contains({ origins: [pattern] });
  } catch {
    return false;
  }
}

/**
 * Enumerate the tab's frames, with a note on which ones hold a login field.
 *
 * Runs in our isolated world, so page JS cannot tamper with what it reports, and
 * Chrome — not the page — supplies each `frameId`. Deliberately avoids the
 * `webNavigation` permission, which would add a "read your browsing history"
 * warning at install for information we can get from the injection we are about
 * to perform anyway.
 *
 * Returns [] when we have no access to the tab; callers fall back to the top frame.
 */
async function probeFrames(tabId: number): Promise<Array<FrameTarget & { hasLoginField: boolean }>> {
  let results: chrome.scripting.InjectionResult<{ href: string; hasLoginField: boolean }>[];
  try {
    results = await chrome.scripting.executeScript({
      target: { tabId, allFrames: true },
      // Kept primitive on purpose: this function is serialised and injected, so it
      // must not close over anything or rely on transpiler helpers.
      func: function () {
        var hasLogin = function (root: ParentNode): boolean {
          if (root.querySelector('input[type="password"], input[autocomplete*="username" i]')) return true;
          var hosts = root.querySelectorAll('*');
          for (var i = 0; i < hosts.length; i += 1) {
            var shadow = hosts[i]?.shadowRoot;
            if (shadow && hasLogin(shadow)) return true;
          }
          return false;
        };
        return { href: location.href, hasLoginField: hasLogin(document) };
      },
    });
  } catch {
    return [];
  }
  if (!Array.isArray(results)) return [];

  const frames: Array<FrameTarget & { hasLoginField: boolean }> = [];
  for (const injection of results) {
    const value = injection.result;
    if (!value || typeof value.href !== 'string') continue;
    frames.push({
      frameId: injection.frameId,
      url: value.href,
      hasLoginField: value.hasLoginField === true,
    });
  }
  return frames;
}

/**
 * Pick the frame to fill when the request came from the popup, which knows only a
 * tab id.
 *
 * Preference order among frames the entry actually matches: the one holding a
 * login field, then the strongest match, then the outermost frame. That ordering
 * is what makes an entry saved for `account.hoyoverse.com` land in the login
 * iframe instead of the `genshin.hoyoverse.com` page that merely contains it.
 */
function chooseFillFrame(entry: Entry, candidates: ReadonlyArray<FrameTarget & { hasLoginField: boolean }>): FrameTarget | null {
  const ranked: Array<{ frame: (typeof candidates)[number]; rank: number }> = [];
  for (const frame of candidates) {
    const strength = findMatchingEntries([entry], frame.url, MATCH_MODE)[0]?.strength;
    if (strength === undefined) continue;
    ranked.push({ frame, rank: matchRank(strength) });
  }
  ranked.sort(
    (a, b) =>
      Number(b.frame.hasLoginField) - Number(a.frame.hasLoginField) ||
      b.rank - a.rank ||
      a.frame.frameId - b.frame.frameId,
  );

  const best = ranked[0];
  return best ? { frameId: best.frame.frameId, url: best.frame.url } : null;
}

/**
 * Host-level account of an autofill attempt, for the error the user sees and for
 * the service-worker log.
 *
 * A login form inside a frame we may not touch is indistinguishable, from the
 * outside, from a page with no form at all — both fill nothing. This is what tells
 * those apart without attaching a debugger. Hosts only: paths and query strings on
 * login URLs carry tokens.
 */
function describeFillAttempt(opts: {
  page: string;
  probed: ReadonlyArray<FrameTarget & { hasLoginField: boolean }> | null;
  target: FrameTarget | null;
  siteAccess: boolean;
}): string {
  const hostOf = (url: string): string => parseTarget(url)?.hostname ?? url.split('?')[0] ?? '?';
  const parts = [`page ${opts.page}`];

  if (opts.probed !== null) {
    if (opts.probed.length === 0) {
      parts.push('frames seen none (no access)');
    } else {
      const withFields = [...new Set(opts.probed.filter((f) => f.hasLoginField).map((f) => hostOf(f.url)))];
      parts.push(`frames seen ${opts.probed.length}`);
      parts.push(`login fields in ${withFields.length > 0 ? withFields.join(', ') : 'none of them'}`);
    }
  }

  parts.push(`tried ${opts.target !== null ? hostOf(opts.target.url) : 'nothing — no frame matched'}`);
  parts.push(`site access ${opts.siteAccess ? 'granted' : 'not granted'}`);
  return parts.join(' · ');
}

/**
 * Deliver one credential to one frame.
 *
 * `requestedFrame` is set when a content script asked on behalf of a suggestion it
 * rendered — that frame is the target, full stop. When it is absent (the popup's
 * Fill button, which knows only a tab), the frame is resolved here.
 */
async function fill(entryId: string, tabId: number, requestedFrame?: FrameTarget | null): Promise<Response> {
  if (!session) return { ok: false, error: 'Vault is locked.' };
  touch();

  const entry = session.data.entries.find((e) => e.id === entryId);
  if (!entry) return { ok: false, error: 'Entry not found.' };

  // The tab's own URL, for the error message and as the fallback frame.
  const currentUrl = await tabUrl(tabId);
  if (!currentUrl) return { ok: false, error: 'Cannot read that tab.' };
  const pageTarget = parseTarget(currentUrl);
  if (!pageTarget) return { ok: false, error: 'Keyhole only fills on http(s) pages.' };

  // Probed only on the popup path; a content script already told us its frame.
  let probed: Array<FrameTarget & { hasLoginField: boolean }> | null = null;
  let frame = requestedFrame ?? null;
  if (frame === null) {
    probed = await probeFrames(tabId);
    // No access to enumerate frames (or a page that refuses injection): fall back
    // to exactly what this did before it knew about frames.
    frame = chooseFillFrame(entry, probed.length > 0 ? probed : [{ frameId: 0, url: currentUrl, hasLoginField: true }]);
  }

  const accessPattern = siteAccessPattern(currentUrl);
  const siteAccess = accessPattern !== null && (await hasSiteAccess(accessPattern));
  /** Attach to every failure below, and log it, so "it didn't fill" is answerable. */
  const detailFor = (target: FrameTarget | null): string =>
    describeFillAttempt({ page: pageTarget.hostname, probed, target, siteAccess });

  if (frame === null) {
    const detail = detailFor(null);
    console.warn('[Keyhole] nothing filled:', detail);
    return {
      ok: false,
      error: `That page (${pageTarget.hostname}) does not match this entry. Nothing was filled.`,
      detail,
    };
  }

  const target = parseTarget(frame.url);
  if (!target) return { ok: false, error: 'Keyhole only fills on http(s) pages.', detail: detailFor(frame) };

  // TOCTOU GUARD. Whoever asked resolved this entry against a URL some moments
  // ago. Between then and now the frame could have navigated — including to an
  // attacker's origin. Re-run matching against the frame we are about to fill,
  // *here*, at the instant before the credential leaves this process. The content
  // script re-checks `location.origin` on arrival as the second layer.
  const stillMatches = findMatchingEntries([entry], frame.url, MATCH_MODE).length > 0;
  if (!stillMatches) {
    return {
      ok: false,
      error: `That page (${target.hostname}) does not match this entry. Nothing was filled.`,
      detail: detailFor(frame),
    };
  }

  // Injection is for the popup path only, where the script may not be present yet:
  // it goes in on demand under `activeTab`, so Keyhole has no standing access to
  // any site.
  //
  // A content script that asked for this fill is, by definition, already running in
  // the frame. Re-injecting is not merely redundant there — it FAILS, because
  // `chrome.scripting` into a cross-origin child frame needs that frame's own host
  // permission, while `activeTab` covers only the top document. Refusing the fill
  // on that error is what made every framed login (hoyoverse.com and every embedded
  // IdP) unfillable from its own suggestion panel.
  if (requestedFrame === undefined || requestedFrame === null) {
    try {
      await chrome.scripting.executeScript({ target: { tabId, frameIds: [frame.frameId] }, files: ['content.js'] });
    } catch {
      const detail = detailFor(frame);
      console.warn('[Keyhole] injection refused:', detail);
      if (!siteAccess && accessPattern !== null) {
        return {
          ok: false,
          error: `Keyhole could not reach the login form on ${target.hostname}. Chrome grants access to the page you clicked on, not to frames inside it — allow this site to fill here.`,
          detail,
          needsHostAccess: accessPattern,
        };
      }
      return {
        ok: false,
        error: 'Cannot inject into this page. Chrome blocks extension pages and the Web Store.',
        detail,
      };
    }
  }

  try {
    const totp =
      entry.totpSecret !== null
        ? (await generateTotp(entry.totpSecret, entry.totpConfig ?? undefined)).code
        : undefined;
    // `{ frameId }` is load-bearing, not a hint: without it Chrome delivers the
    // password to every frame in the tab.
    const result = (await chrome.tabs.sendMessage(
      tabId,
      {
        type: 'KEYHOLE_FILL',
        username: entry.username,
        password: entry.password,
        ...(totp !== undefined ? { totp } : {}),
        expectedOrigin: target.origin,
      },
      { frameId: frame.frameId },
    )) as { filledUsername?: boolean; filledPassword?: boolean; filledTotp?: boolean } | undefined;

    const detail = detailFor(frame);
    if (!result) {
      console.warn('[Keyhole] no response from the target frame:', detail);
      return { ok: false, error: 'No login form responded on that page.', detail };
    }
    if (!result.filledUsername && !result.filledPassword && !result.filledTotp) {
      console.warn('[Keyhole] nothing filled:', detail);
      // Most often this really is "no form here". But it is also exactly what a
      // login form inside a cross-origin frame looks like from the outside: we
      // filled the only frame we are allowed to touch, and the fields are in one
      // we are not. Do not leave the user at a dead end — name the cause and hand
      // the popup a pattern it can ask for.
      if (!siteAccess && accessPattern !== null) {
        return {
          ok: false,
          error: `Nothing filled on ${pageTarget.hostname}. If the login form is inside an embedded frame, Keyhole needs access to this site to reach it.`,
          detail,
          needsHostAccess: accessPattern,
        };
      }
      return { ok: false, error: 'No login fields found on that page.', detail };
    }
    return {
      ok: true,
      type: 'FILLED',
      filledUsername: result.filledUsername === true,
      filledPassword: result.filledPassword === true,
      filledTotp: result.filledTotp === true,
    };
  } catch {
    const detail = detailFor(frame);
    console.warn('[Keyhole] the target frame rejected the fill:', detail);
    return { ok: false, error: 'The page did not accept the fill request.', detail };
  }
}

async function saveFromPage(
  tabId: number,
  username: string,
  password: string,
  entryId?: string,
  frame?: FrameTarget | null,
): Promise<Response> {
  if (!session || !vaultFile) return { ok: false, error: 'Vault is locked.' };
  touch();

  // The credential was typed into a form in `frame`, and that frame's origin is
  // where it will be sent — so that, not the address bar, is what we record.
  const currentUrl = frame?.url ?? (await tabUrl(tabId));
  if (!currentUrl) return { ok: false, error: 'Cannot read that tab.' };
  const target = parseTarget(currentUrl);
  if (!target) return { ok: false, error: 'Keyhole only saves logins for http(s) pages.' };

  try {
    if (typeof entryId === 'string') {
      const entry = session.data.entries.find((e) => e.id === entryId);
      if (!entry) return { ok: false, error: 'Entry not found.' };
      const stillMatches = findMatchingEntries([entry], currentUrl, SAVE_MATCH_MODE).length > 0;
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

  const input = raw as Record<string, unknown> | null;
  if (!input || typeof input.title !== 'string') return { ok: false, error: 'Invalid entry.' };

  const existingId =
    typeof input.id === 'string' && session.data.entries.some((e) => e.id === input.id) ? input.id : null;

  try {
    if (existingId) {
      // Partial patch: only keys present in the message. Defaulting absent ones
      // to empty used to wipe notes, tags, TOTP and every URL but the first when
      // the options editor opened from a summary and saved.
      const patch: Partial<EntryInput> = { title: input.title };
      if ('username' in input && typeof input.username === 'string') patch.username = input.username;
      if ('password' in input && typeof input.password === 'string') patch.password = input.password;
      if ('urls' in input && Array.isArray(input.urls)) patch.urls = input.urls as string[];
      if ('notes' in input && typeof input.notes === 'string') patch.notes = input.notes;
      if ('tags' in input && Array.isArray(input.tags)) patch.tags = input.tags as string[];
      if ('totpSecret' in input) {
        patch.totpSecret = typeof input.totpSecret === 'string' ? input.totpSecret : null;
      }
      if ('totpConfig' in input) {
        patch.totpConfig = (input.totpConfig as EntryInput['totpConfig']) ?? null;
      }
      if ('customFields' in input && Array.isArray(input.customFields)) {
        patch.customFields = input.customFields as NonNullable<EntryInput['customFields']>;
      }
      if ('attachments' in input && Array.isArray(input.attachments)) {
        patch.attachments = input.attachments as NonNullable<EntryInput['attachments']>;
      }
      session.data = updateEntry(session.data, existingId, patch);
    } else {
      session.data = createEntry(session.data, {
        title: input.title,
        username: typeof input.username === 'string' ? input.username : '',
        password: typeof input.password === 'string' ? input.password : '',
        urls: Array.isArray(input.urls) ? (input.urls as string[]) : [],
        notes: typeof input.notes === 'string' ? input.notes : '',
        tags: Array.isArray(input.tags) ? (input.tags as string[]) : [],
        totpSecret: typeof input.totpSecret === 'string' ? input.totpSecret : null,
        totpConfig: (input.totpConfig as EntryInput['totpConfig']) ?? null,
        customFields: Array.isArray(input.customFields)
          ? (input.customFields as NonNullable<EntryInput['customFields']>)
          : [],
        attachments: Array.isArray(input.attachments)
          ? (input.attachments as NonNullable<EntryInput['attachments']>)
          : [],
      }).data;
    }
    await persist();
    return { ok: true, type: 'OK' };
  } catch (err) {
    const message = describe(err);
    if (/too large for extension storage/i.test(message) || /attachment/i.test(message)) {
      return { ok: false, error: 'This attachment does not fit. Remove a file or use a smaller one.' };
    }
    return { ok: false, error: message };
  }
}

async function persist(): Promise<void> {
  if (!session || !vaultFile) throw new Error('Vault is locked.');
  vaultFile = await saveVault(session, vaultFile);
  await saveVaultFile(vaultFile);
}

/**
 * Re-key the vault from the extension.
 *
 * Until this existed, someone whose only Keyhole was the extension could not change
 * their master password at all — the capability was in core and surfaced on desktop
 * and iOS only.
 *
 * Ordering matches the desktop path deliberately: persist the re-keyed envelope
 * locally *before* touching the server, so a network failure leaves a vault that
 * opens with the password the user just chose. The reverse could leave the server
 * expecting a password this device never adopted.
 */
async function changeMasterPasswordHere(currentPassword: string, newPassword: string): Promise<Response> {
  if (!session || !vaultFile) return { ok: false, error: 'Vault is locked.' };
  touch();

  const previousFile = vaultFile;
  let rekeyed: { file: VaultFile; session: VaultSession };
  try {
    rekeyed = await changeMasterPassword(previousFile, currentPassword, newPassword);
  } catch (err) {
    return { ok: false, error: describe(err) };
  }

  try {
    await saveVaultFile(rekeyed.file);
  } catch (err) {
    // Nothing was written, so the old password still opens the stored vault.
    return { ok: false, error: describe(err) };
  }

  await markUnlocked(rekeyed.session, rekeyed.file);
  // Derived from the old salt, so worthless now.
  syncAuthSecretB64 = null;

  const config = await loadSyncConfig();
  if (!config) {
    return { ok: true, type: 'SYNC_RESULT', message: 'Master password changed. Re-export your backup.' };
  }

  try {
    const rotated = await rotateSyncAuthAfterRekey({
      baseUrl: config.baseUrl,
      accountId: config.accountId,
      currentMasterPassword: currentPassword,
      nextMasterPassword: newPassword,
      previousFile,
      newFile: rekeyed.file,
    });
    syncAuthSecretB64 = rotated.syncAuthSecretB64;
    return {
      ok: true,
      type: 'SYNC_RESULT',
      message: `Master password changed and the sync account re-pointed (v${rotated.version}). Other devices will need the new password.`,
    };
  } catch (err) {
    // The local change stands — say so plainly, and say what is now broken.
    return {
      ok: false,
      error: `Master password changed on this device, but the sync server could not be updated: ${describeSync(err, 'Rotation failed.')} Sync will refuse this account until you retry.`,
    };
  }
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
 *
 * `allFrames` because the login form is frequently not in the top document —
 * hoyoverse.com, and every embedded IdP widget, put it in a cross-origin iframe.
 * Each frame gets its own instance, holding no vault data and answering only our
 * extension id; suggestions in a frame are matched against that frame's own URL.
 */
async function ensureContentScript(tabId: number, url?: string | undefined): Promise<void> {
  if (!session) return;
  const pageUrl = url ?? (await tabUrl(tabId));
  if (!pageUrl || !/^https?:/i.test(pageUrl)) return;
  try {
    await chrome.scripting.executeScript({
      target: { tabId, allFrames: true },
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

  const count = findMatchingEntries(session.data.entries, url, MATCH_MODE).length;
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
