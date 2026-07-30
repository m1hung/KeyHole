/**
 * End-to-end check of similar-site autofill, driven through the real service
 * worker rather than through the matcher directly.
 *
 * The matching rules themselves are tested in core (`url-match`,
 * `public-suffix`). What is tested here is the wiring, which is where this
 * feature can go wrong in a way unit tests would not see:
 *
 *  - the popup and the in-page panel are offered same-site entries at all;
 *  - Fill accepts exactly what was suggested — its TOCTOU re-check runs in the
 *    same mode, so a "similar" suggestion is never a button that refuses itself;
 *  - a shared-hosting neighbour and a lookalike host are still refused on both
 *    paths.
 */

import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import type { EntrySummary, Response } from '../src/shared/messages.ts';

const EXTENSION_ID = 'abcdefghijklmnopabcdefghijklmnop';
const MASTER_PASSWORD = 'correct horse battery staple';

type Listener = (
  raw: unknown,
  sender: chrome.runtime.MessageSender,
  sendResponse: (response: Response) => void,
) => boolean | void;

const listeners: Listener[] = [];
/** Keyboard-command handlers the worker registered. */
const commandListeners: ((command: string, tab?: { id?: number }) => void)[] = [];
let tabUrl = 'https://example.com/';
/** Badge text the worker set, per tab — how a keyboard fill reports a refusal. */
let badgeTexts: string[] = [];
interface FillDispatch {
  username?: string;
  expectedOrigin?: string;
}
/** Last KEYHOLE_FILL the worker dispatched to the page. */
let lastFill: FillDispatch | null = null;

/** Frames the stubbed tab contains. Empty means "just the top document". */
interface StubFrame {
  frameId: number;
  url: string;
  hasLoginField: boolean;
}
let frames: StubFrame[] = [];
/** Frame ids content.js was injected into, and every sendMessage the worker made. */
let injectedFrameIds: number[] = [];
let dispatches: Array<{ frameId: number | undefined; message: { type?: string } }> = [];

function frameTable(): StubFrame[] {
  return frames.length > 0 ? frames : [{ frameId: 0, url: tabUrl, hasLoginField: true }];
}

/** Whether the extension is allowed on the site, and what it asked about. */
let grantedSiteAccess = true;
let requestedPermissionQueries: string[] = [];

/**
 * Frames `chrome.scripting` is allowed into; null means all of them.
 *
 * This is the constraint that matters most here: `activeTab` covers the top
 * document only, so scripting into a cross-origin child frame throws, and that
 * frame is invisible to an `allFrames` probe. A content script declared in the
 * manifest still runs there — which is why a frame can ask for a fill that we
 * cannot inject into.
 */
let injectableFrameIds: number[] | null = null;

function mayInject(frameId: number): boolean {
  return injectableFrameIds === null || injectableFrameIds.includes(frameId);
}

/**
 * Read `lastFill` through a call, so narrowing from the `lastFill = null` reset in
 * each test does not convince the compiler the stub can never have written to it.
 */
function dispatchedFill(): FillDispatch | null {
  return lastFill;
}

function installChromeStub(): void {
  const store: Record<string, unknown> = {};
  const noop = (): void => {};
  (globalThis as { chrome?: unknown }).chrome = {
    runtime: {
      id: EXTENSION_ID,
      onMessage: { addListener: (fn: Listener) => listeners.push(fn) },
      onMessageExternal: { addListener: noop },
      onStartup: { addListener: noop },
      onInstalled: { addListener: noop },
    },
    storage: {
      local: {
        get: async (key: string) => (store[key] !== undefined ? { [key]: store[key] } : {}),
        set: async (obj: Record<string, unknown>) => void Object.assign(store, obj),
        remove: async (key: string) => void delete store[key],
      },
      session: {
        get: async () => ({}),
        set: async () => {},
        remove: async () => {},
      },
    },
    alarms: { create: async () => {}, clear: async () => {}, onAlarm: { addListener: noop } },
    commands: {
      onCommand: {
        addListener: (fn: (command: string, tab?: { id?: number }) => void) => commandListeners.push(fn),
      },
    },
    action: {
      setBadgeText: async (details: { text?: string }) => {
        if (typeof details.text === 'string' && details.text.length > 0) badgeTexts.push(details.text);
      },
      setBadgeBackgroundColor: async () => {},
      setBadgeTextColor: async () => {},
    },
    tabs: {
      get: async () => ({ url: tabUrl }),
      query: async () => [{ id: 1, url: tabUrl, active: true }],
      sendMessage: async (
        _tabId: number,
        message: { type?: string; username?: string; expectedOrigin?: string },
        options?: { frameId?: number },
      ) => {
        dispatches.push({ frameId: options?.frameId, message });
        lastFill = message;
        // Only the frame holding a login field reports a fill, like the real script.
        const target = frameTable().find((f) => f.frameId === options?.frameId);
        const filled = target?.hasLoginField === true;
        return { filledUsername: filled, filledPassword: filled, filledTotp: false };
      },
      onActivated: { addListener: noop },
      onUpdated: { addListener: noop },
    },
    scripting: {
      // Mirrors Chrome: a `func` injection returns one result per frame, carrying
      // the frame id; a `files` injection returns nothing useful.
      executeScript: async (opts: {
        target: { allFrames?: boolean; frameIds?: number[] };
        func?: unknown;
        files?: string[];
      }) => {
        if (typeof opts.func === 'function') {
          // A probe cannot see frames it may not enter.
          return frameTable()
            .filter((f) => mayInject(f.frameId))
            .map((f) => ({
              frameId: f.frameId,
              result: { href: f.url, hasLoginField: f.hasLoginField },
            }));
        }
        const ids = opts.target.frameIds ?? (opts.target.allFrames === true ? frameTable().map((f) => f.frameId) : [0]);
        for (const id of ids) {
          if (!mayInject(id)) throw new Error('Cannot access contents of the page.');
        }
        injectedFrameIds.push(...ids);
        return [];
      },
    },
    permissions: {
      contains: async (query: { origins?: string[] }) => {
        requestedPermissionQueries.push(query.origins?.[0] ?? '');
        return grantedSiteAccess;
      },
    },
    windows: {
      onRemoved: { addListener: noop },
      onFocusChanged: { addListener: noop },
      create: async () => ({}),
      update: async () => ({}),
      WINDOW_ID_NONE: -1,
    },
  };
}

const popupSender = {
  id: EXTENSION_ID,
  url: `chrome-extension://${EXTENSION_ID}/popup.html`,
} as chrome.runtime.MessageSender;

/**
 * A content script in one frame of tab 1. `url` and `frameId` are what Chrome
 * attaches to the message — a page cannot set either — and for a subframe they
 * describe the frame, not the address bar.
 */
function frameSender(url: string, frameId = 0): chrome.runtime.MessageSender {
  return { id: EXTENSION_ID, url, frameId, tab: { id: 1 } } as unknown as chrome.runtime.MessageSender;
}

async function send(message: unknown, sender = popupSender): Promise<Response> {
  const listener = listeners[0];
  if (!listener) throw new Error('service worker registered no message listener');
  return new Promise<Response>((resolve) => {
    listener(message, sender, resolve);
  });
}

async function saveEntry(title: string, url: string): Promise<void> {
  const response = await send({
    type: 'SAVE_ENTRY',
    entry: { title, username: `${title}@example.test`, password: 'stored-password', urls: [url] },
  });
  expect(response.ok).toBe(true);
}

/**
 * Entries offered for `url` — either through the popup (which matches on the tab)
 * or through the in-page panel (which matches on the asking frame).
 */
async function entriesFor(url: string, via: 'popup' | 'page' = 'popup'): Promise<EntrySummary[]> {
  tabUrl = url;
  const response =
    via === 'popup'
      ? await send({ type: 'MATCH_TAB', tabId: 1 })
      : await send({ type: 'SUGGEST_FOR_PAGE' }, frameSender(url));
  if (!response.ok || (response.type !== 'ENTRIES' && response.type !== 'SUGGESTIONS')) {
    throw new Error(`unexpected response: ${JSON.stringify(response)}`);
  }
  return response.entries;
}

beforeAll(async () => {
  installChromeStub();
  await import('../src/background/service-worker.ts');
  const created = await send({ type: 'CREATE_VAULT', masterPassword: MASTER_PASSWORD });
  expect(created.ok).toBe(true);

  await saveEntry('Accounts', 'https://accounts.example.com');
  await saveEntry('Alice Pages', 'https://alice.github.io');
}, 60_000);

describe('suggestions for similar sites', () => {
  it('offers a sibling host of the same site, labelled as a domain match', async () => {
    const entries = await entriesFor('https://billing.example.com/login');
    expect(entries.map((e) => [e.title, e.matchStrength])).toEqual([['Accounts', 'domain']]);
  });

  it('offers the parent of a host the entry was saved under', async () => {
    const entries = await entriesFor('https://example.com/signin');
    expect(entries.map((e) => e.matchStrength)).toEqual(['domain']);
  });

  it('still prefers a stronger match on the entry’s own host', async () => {
    const entries = await entriesFor('https://accounts.example.com/login');
    expect(entries.map((e) => e.matchStrength)).toEqual(['exact']);
  });

  it('offers the same entries to the in-page panel as to the popup', async () => {
    const inPage = await entriesFor('https://billing.example.com/login', 'page');
    expect(inPage.map((e) => [e.title, e.matchStrength])).toEqual([['Accounts', 'domain']]);
  });

  it('offers nothing to a shared-hosting neighbour', async () => {
    expect(await entriesFor('https://bob.github.io/login')).toEqual([]);
    expect(await entriesFor('https://bob.github.io/login', 'page')).toEqual([]);
  });

  it('offers nothing to a lookalike host', async () => {
    expect(await entriesFor('https://accounts.example.com.evil.test/login')).toEqual([]);
    expect(await entriesFor('https://notexample.com/login')).toEqual([]);
  });
});

describe('filling accepts exactly what was suggested', () => {
  it('fills a same-site page the popup offered', async () => {
    const [entry] = await entriesFor('https://billing.example.com/login');
    expect(entry).toBeDefined();
    lastFill = null;

    const filled = await send({ type: 'FILL', entryId: entry?.id, tabId: 1 });
    expect(filled).toMatchObject({ ok: true, type: 'FILLED', filledPassword: true });
    expect(dispatchedFill()?.expectedOrigin).toBe('https://billing.example.com');
  });

  it('refuses to fill a shared-hosting neighbour of the entry', async () => {
    const [alice] = await entriesFor('https://alice.github.io/login');
    expect(alice).toBeDefined();
    lastFill = null;

    tabUrl = 'https://bob.github.io/login';
    const refused = await send({ type: 'FILL', entryId: alice?.id, tabId: 1 });
    expect(refused.ok).toBe(false);
    expect(dispatchedFill()).toBeNull();
  });

  it('addresses the fill to one frame, never broadcasting to the tab', async () => {
    const [entry] = await entriesFor('https://billing.example.com/login');
    dispatches = [];

    await send({ type: 'FILL', entryId: entry?.id, tabId: 1 });
    expect(dispatches.length).toBeGreaterThan(0);
    for (const dispatch of dispatches) {
      expect(typeof dispatch.frameId).toBe('number');
    }
  });

  it('refuses to fill a page that navigated to a lookalike after the match', async () => {
    const [entry] = await entriesFor('https://billing.example.com/login');
    expect(entry).toBeDefined();
    lastFill = null;

    tabUrl = 'https://billing.example.com.evil.test/login';
    const refused = await send({ type: 'FILL', entryId: entry?.id, tabId: 1 });
    expect(refused.ok).toBe(false);
    expect(dispatchedFill()).toBeNull();
  });
});

/**
 * The hoyoverse.com shape: the page you are looking at hosts nothing but a
 * cross-origin iframe carrying the actual login form.
 */
describe('login forms inside an iframe', () => {
  const TOP = 'https://game.example.com/en/home';
  const LOGIN_FRAME = 'https://accounts.example.com/login-platform/index.html#/password-login';
  const AD_FRAME = 'https://ads.unrelated.test/banner.html';
  const LOGIN_FRAME_ID = 7;

  beforeEach(() => {
    tabUrl = TOP;
    frames = [
      { frameId: 0, url: TOP, hasLoginField: false },
      { frameId: LOGIN_FRAME_ID, url: LOGIN_FRAME, hasLoginField: true },
      { frameId: 9, url: AD_FRAME, hasLoginField: false },
    ];
    injectedFrameIds = [];
    dispatches = [];
    lastFill = null;
  });

  afterEach(() => {
    frames = [];
  });

  it('fills the login iframe, not the page that merely contains it', async () => {
    // The popup matched on the top URL, which is same-site with the entry.
    const [entry] = await entriesFor(TOP);
    expect(entry?.title).toBe('Accounts');

    tabUrl = TOP;
    const filled = await send({ type: 'FILL', entryId: entry?.id, tabId: 1 });

    expect(filled).toMatchObject({ ok: true, type: 'FILLED', filledPassword: true });
    expect(dispatches.map((d) => d.frameId)).toEqual([LOGIN_FRAME_ID]);
    expect(dispatchedFill()?.expectedOrigin).toBe('https://accounts.example.com');
    // content.js goes into that one frame, not every frame of the tab.
    expect(injectedFrameIds).toEqual([LOGIN_FRAME_ID]);
  });

  it('matches an in-frame suggestion request against the frame, not the address bar', async () => {
    const response = await send({ type: 'SUGGEST_FOR_PAGE' }, frameSender(LOGIN_FRAME, LOGIN_FRAME_ID));
    expect(response.ok).toBe(true);
    if (!response.ok || response.type !== 'SUGGESTIONS') throw new Error('expected suggestions');
    // 'exact' — the frame *is* the entry's origin, a stronger match than the
    // same-site 'domain' the top-level page would have produced.
    expect(response.entries.map((e) => [e.title, e.matchStrength])).toEqual([['Accounts', 'exact']]);
  });

  it('offers a third-party frame nothing, even though the page itself matches', async () => {
    const response = await send({ type: 'SUGGEST_FOR_PAGE' }, frameSender(AD_FRAME, 9));
    if (!response.ok || response.type !== 'SUGGESTIONS') throw new Error('expected suggestions');
    expect(response.entries).toEqual([]);
  });

  it('fills the frame that asked, without probing or re-picking', async () => {
    const [entry] = await entriesFor(TOP);
    dispatches = [];
    injectedFrameIds = [];

    const filled = await send(
      { type: 'FILL_FROM_PAGE', entryId: entry?.id },
      frameSender(LOGIN_FRAME, LOGIN_FRAME_ID),
    );
    expect(filled).toMatchObject({ ok: true, type: 'FILLED' });
    expect(dispatches.map((d) => d.frameId)).toEqual([LOGIN_FRAME_ID]);
    expect(dispatchedFill()?.expectedOrigin).toBe('https://accounts.example.com');
  });

  it('refuses a fill requested by a frame the entry does not match', async () => {
    const [entry] = await entriesFor(TOP);
    dispatches = [];

    const refused = await send({ type: 'FILL_FROM_PAGE', entryId: entry?.id }, frameSender(AD_FRAME, 9));
    expect(refused.ok).toBe(false);
    expect(dispatches).toEqual([]);
  });

  it('records the frame origin when saving a login submitted in the iframe', async () => {
    const saved = await send(
      { type: 'SAVE_FROM_PAGE', username: 'framed@example.test', password: 'from-the-iframe' },
      frameSender(LOGIN_FRAME, LOGIN_FRAME_ID),
    );
    expect(saved.ok).toBe(true);

    // The new entry belongs to the frame's origin, so it is an exact match there.
    const inFrame = await send({ type: 'SUGGEST_FOR_PAGE' }, frameSender(LOGIN_FRAME, LOGIN_FRAME_ID));
    if (!inFrame.ok || inFrame.type !== 'SUGGESTIONS') throw new Error('expected suggestions');
    const saved_entry = inFrame.entries.find((e) => e.username === 'framed@example.test');
    expect(saved_entry?.matchStrength).toBe('exact');
    expect(saved_entry?.host).toBe('accounts.example.com');
  });
});

/**
 * `activeTab` — what clicking the toolbar icon grants — covers the top frame's
 * origin only. A login form in a cross-origin frame is therefore unreachable until
 * the user allows the site, and "nothing happened" is the worst possible way to
 * report that.
 */
describe('when the login frame is out of reach', () => {
  const TOP = 'https://game.example.com/en/home';

  beforeEach(() => {
    tabUrl = TOP;
    // Only the top frame is visible to us; the login frame is not injectable, so
    // the probe never sees it.
    frames = [{ frameId: 0, url: TOP, hasLoginField: false }];
    dispatches = [];
    requestedPermissionQueries = [];
    lastFill = null;
  });

  afterEach(() => {
    frames = [];
    grantedSiteAccess = true;
  });

  it('asks for the site, scoped to its registrable domain, when access is missing', async () => {
    grantedSiteAccess = false;
    const [entry] = await entriesFor(TOP);

    tabUrl = TOP;
    const response = await send({ type: 'FILL', entryId: entry?.id, tabId: 1 });

    expect(response.ok).toBe(false);
    if (response.ok) throw new Error('expected a failure');
    expect(response.needsHostAccess).toBe('*://*.example.com/*');
    expect(response.error).toContain('embedded frame');
    expect(requestedPermissionQueries).toContain('*://*.example.com/*');
  });

  it('does not blame permissions when the site is already allowed', async () => {
    grantedSiteAccess = true;
    const [entry] = await entriesFor(TOP);

    tabUrl = TOP;
    const response = await send({ type: 'FILL', entryId: entry?.id, tabId: 1 });

    expect(response.ok).toBe(false);
    if (response.ok) throw new Error('expected a failure');
    expect(response.needsHostAccess).toBeUndefined();
    expect(response.error).toBe('No login fields found on that page.');
  });
});

describe('explaining a failed fill', () => {
  const TOP = 'https://game.example.com/en/home';

  beforeEach(() => {
    tabUrl = TOP;
    dispatches = [];
    requestedPermissionQueries = [];
    lastFill = null;
  });

  afterEach(() => {
    frames = [];
    grantedSiteAccess = true;
  });

  it('names the frame holding the fields when it could not be filled', async () => {
    // What an unreachable login frame looks like: we see the page, not the frame.
    grantedSiteAccess = false;
    frames = [{ frameId: 0, url: TOP, hasLoginField: false }];
    const [entry] = await entriesFor(TOP);

    tabUrl = TOP;
    const response = await send({ type: 'FILL', entryId: entry?.id, tabId: 1 });
    if (response.ok) throw new Error('expected a failure');

    expect(response.detail).toContain('page game.example.com');
    expect(response.detail).toContain('login fields in none of them');
    expect(response.detail).toContain('tried game.example.com');
    expect(response.detail).toContain('site access not granted');
  });

  it('reports which frame it did fill when the fields were elsewhere', async () => {
    frames = [
      { frameId: 0, url: TOP, hasLoginField: false },
      { frameId: 4, url: 'https://accounts.example.com/login', hasLoginField: true },
    ];
    const [entry] = await entriesFor(TOP);

    tabUrl = TOP;
    const response = await send({ type: 'FILL', entryId: entry?.id, tabId: 1 });
    expect(response.ok).toBe(true);
  });

  it('says so when no frame matched the entry at all', async () => {
    frames = [{ frameId: 0, url: 'https://unrelated.test/login', hasLoginField: true }];
    tabUrl = 'https://unrelated.test/login';
    // Reach the entry through search, the way the popup's "all entries" list does.
    const listed = await send({ type: 'LIST_ENTRIES', query: 'Accounts' });
    if (!listed.ok || listed.type !== 'ENTRIES') throw new Error('expected entries');

    const response = await send({ type: 'FILL', entryId: listed.entries[0]?.id, tabId: 1 });
    if (response.ok) throw new Error('expected a failure');
    expect(response.error).toContain('does not match this entry');
    expect(response.detail).toContain('tried nothing — no frame matched');
    expect(dispatches).toEqual([]);
  });

  it('never puts a path or query string in the detail', async () => {
    grantedSiteAccess = false;
    frames = [{ frameId: 0, url: `${TOP}?token=secret-value#/step`, hasLoginField: false }];
    tabUrl = `${TOP}?token=secret-value#/step`;
    const listed = await send({ type: 'LIST_ENTRIES', query: 'Accounts' });
    if (!listed.ok || listed.type !== 'ENTRIES') throw new Error('expected entries');

    const response = await send({ type: 'FILL', entryId: listed.entries[0]?.id, tabId: 1 });
    if (response.ok) throw new Error('expected a failure');
    expect(response.detail).not.toContain('secret-value');
    expect(response.detail).not.toContain('/en/home');
  });
});

/**
 * The hoyoverse.com failure, exactly as it presented: the login frame runs our
 * declared content script and asks for a fill, but `activeTab` does not let
 * `chrome.scripting` into that cross-origin frame. Re-injecting a script that is
 * already there must not be what decides whether the fill happens.
 */
describe('filling a frame that cannot be injected into', () => {
  const TOP = 'https://game.example.com/en/home';
  const LOGIN_FRAME = 'https://accounts.example.com/login-platform/index.html#/password-login';
  const LOGIN_FRAME_ID = 7;

  beforeEach(() => {
    tabUrl = TOP;
    frames = [
      { frameId: 0, url: TOP, hasLoginField: false },
      { frameId: LOGIN_FRAME_ID, url: LOGIN_FRAME, hasLoginField: true },
    ];
    // What activeTab grants: the top document, and nothing else.
    injectableFrameIds = [0];
    grantedSiteAccess = false;
    injectedFrameIds = [];
    dispatches = [];
    lastFill = null;
  });

  afterEach(() => {
    frames = [];
    injectableFrameIds = null;
    grantedSiteAccess = true;
  });

  it('fills when that frame asked, without attempting to re-inject it', async () => {
    const [entry] = await entriesFor(TOP);

    const filled = await send(
      { type: 'FILL_FROM_PAGE', entryId: entry?.id },
      frameSender(LOGIN_FRAME, LOGIN_FRAME_ID),
    );

    expect(filled).toMatchObject({ ok: true, type: 'FILLED', filledPassword: true });
    expect(injectedFrameIds).toEqual([]);
    expect(dispatches.map((d) => d.frameId)).toEqual([LOGIN_FRAME_ID]);
    expect(dispatchedFill()?.expectedOrigin).toBe('https://accounts.example.com');
  });

  it('still refuses a frame the entry does not match, injectable or not', async () => {
    const [entry] = await entriesFor(TOP);
    const refused = await send(
      { type: 'FILL_FROM_PAGE', entryId: entry?.id },
      frameSender('https://ads.unrelated.test/banner.html', 9),
    );
    expect(refused.ok).toBe(false);
    expect(dispatches).toEqual([]);
  });

  it('offers the popup a scoped grant, since it cannot even see that frame', async () => {
    const [entry] = await entriesFor(TOP);

    tabUrl = TOP;
    const response = await send({ type: 'FILL', entryId: entry?.id, tabId: 1 });

    expect(response.ok).toBe(false);
    if (response.ok) throw new Error('expected a failure');
    expect(response.needsHostAccess).toBe('*://*.example.com/*');
    // It saw one frame — the top one — because the other is beyond its reach.
    expect(response.detail).toContain('frames seen 1');
  });
});

/**
 * Re-keying from the extension. Until this existed, an extension-only user could
 * not change their master password at all.
 */
describe('changing the master password', () => {
  const NEW_PASSWORD = 'an-entirely-different-passphrase';

  // These tests mutate state the whole file shares — every later block unlocks
  // with MASTER_PASSWORD — so put it back rather than leaving a landmine.
  afterAll(async () => {
    await send({ type: 'UNLOCK', masterPassword: NEW_PASSWORD });
    const restored = await send({
      type: 'CHANGE_MASTER_PASSWORD',
      currentPassword: NEW_PASSWORD,
      newPassword: MASTER_PASSWORD,
    });
    expect(restored.ok).toBe(true);
  }, 60_000);

  it('re-keys so the new password unlocks and the old one does not', async () => {
    const changed = await send({
      type: 'CHANGE_MASTER_PASSWORD',
      currentPassword: MASTER_PASSWORD,
      newPassword: NEW_PASSWORD,
    });
    expect(changed.ok).toBe(true);

    // Still unlocked afterwards — re-keying must not log the user out.
    const state = await send({ type: 'GET_STATE' });
    if (!state.ok || state.type !== 'STATE') throw new Error('expected state');
    expect(state.locked).toBe(false);

    await send({ type: 'LOCK' });
    const withOld = await send({ type: 'UNLOCK', masterPassword: MASTER_PASSWORD });
    expect(withOld.ok).toBe(false);

    const withNew = await send({ type: 'UNLOCK', masterPassword: NEW_PASSWORD });
    expect(withNew.ok).toBe(true);
  }, 60_000);

  it('refuses a wrong current password without touching the stored vault', async () => {
    const refused = await send({
      type: 'CHANGE_MASTER_PASSWORD',
      currentPassword: 'not-the-current-password',
      newPassword: 'something-else-entirely',
    });
    expect(refused.ok).toBe(false);

    // The password from the previous test still works, so nothing was rewritten.
    await send({ type: 'LOCK' });
    const unlocked = await send({ type: 'UNLOCK', masterPassword: NEW_PASSWORD });
    expect(unlocked.ok).toBe(true);
  }, 60_000);
});

/**
 * The health report, which core has always computed but only the desktop app
 * surfaced.
 */
describe('vault health', () => {
  /** Weak enough to be flagged, distinctive enough to spot if it leaks. */
  const WEAK_SHARED_PASSWORD = 'zzzz1';

  it('reports findings without ever returning a password', async () => {
    // Two logins sharing a password, which is also weak.
    await saveEntry('Shared A', 'https://a.example.org');
    await saveEntry('Shared B', 'https://b.example.org');
    const listed = await send({ type: 'LIST_ENTRIES', query: 'Shared' });
    if (!listed.ok || listed.type !== 'ENTRIES') throw new Error('expected entries');
    for (const entry of listed.entries) {
      const saved = await send({
        type: 'SAVE_ENTRY',
        entry: { id: entry.id, title: entry.title, username: entry.username, password: WEAK_SHARED_PASSWORD, urls: [] },
      });
      expect(saved.ok).toBe(true);
    }

    const response = await send({ type: 'HEALTH_REPORT' });
    expect(response.ok).toBe(true);
    if (!response.ok || response.type !== 'HEALTH') throw new Error('expected a health report');

    const kinds = new Set(response.issues.map((i) => i.kind));
    expect(kinds.has('reused')).toBe(true);
    expect(kinds.has('weak')).toBe(true);
    expect(response.loginCount).toBeGreaterThan(0);

    // The response must not contain the secret it is complaining about: it
    // crosses a process boundary into a page, so findings only. (Asserted against
    // the value, not the word — the findings themselves legitimately say
    // "password".)
    expect(JSON.stringify(response)).not.toContain(WEAK_SHARED_PASSWORD);
    expect(JSON.stringify(response)).not.toContain('stored-password');
  }, 60_000);

  it('refuses when locked', async () => {
    await send({ type: 'LOCK' });
    const response = await send({ type: 'HEALTH_REPORT' });
    expect(response.ok).toBe(false);
  });
});

/**
 * The keyboard shortcut. It reuses `fill()` wholesale, so what needs pinning here
 * is the decision it makes *before* filling — with no popup open, a wrong guess
 * types someone else's password into a login form with nothing to undo it.
 */
describe('fill-best-match hotkey', () => {
  // Its own site: other blocks have added entries to shared origins, and "how many
  // entries match" is exactly what these tests are about.
  const TOP = 'https://hotkey.example.net/login';

  /** Invoke the command the way Chrome does. */
  async function pressHotkey(tabId: number | undefined = 1): Promise<void> {
    const listener = commandListeners[0];
    if (!listener) throw new Error('service worker registered no command listener');
    listener('fill-best-match', { id: tabId });
    // The handler is async and Chrome does not await it.
    await new Promise((resolve) => setTimeout(resolve, 50));
  }

  beforeAll(async () => {
    await send({ type: 'UNLOCK', masterPassword: MASTER_PASSWORD });
    await saveEntry('Hotkey Only', 'https://hotkey.example.net');
  }, 60_000);

  beforeEach(async () => {
    tabUrl = TOP;
    dispatches = [];
    badgeTexts = [];
    lastFill = null;
    await send({ type: 'UNLOCK', masterPassword: MASTER_PASSWORD });
  });

  it('fills the single best match without opening anything', async () => {
    await pressHotkey();
    expect(dispatches.map((d) => d.message.type)).toEqual(['KEYHOLE_FILL']);
    expect(dispatchedFill()?.expectedOrigin).toBe('https://hotkey.example.net');
  });

  it('ignores commands it does not own', async () => {
    const listener = commandListeners[0];
    listener?.('some-other-command', { id: 1 });
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(dispatches).toEqual([]);
  });

  it('does nothing on a page with no match', async () => {
    tabUrl = 'https://nothing-saved-here.test/login';
    await pressHotkey();
    expect(dispatches).toEqual([]);
  });

  /**
   * Two accounts on one site is the ordinary case, not an edge case. Picking one
   * silently would be the worst possible behaviour, so it refuses and says so on
   * the toolbar icon.
   */
  it('refuses to guess between equally good matches', async () => {
    const second = await send({
      type: 'SAVE_ENTRY',
      entry: {
        title: 'Hotkey second login',
        username: 'other@example.test',
        password: 'another-password',
        urls: ['https://hotkey.example.net'],
      },
    });
    expect(second.ok).toBe(true);

    await pressHotkey();
    expect(dispatches).toEqual([]);
    expect(badgeTexts).toContain('?');

    // Clean up so later tests see one match again.
    const listed = await send({ type: 'LIST_ENTRIES', query: 'Hotkey second login' });
    if (!listed.ok || listed.type !== 'ENTRIES') throw new Error('expected entries');
    const id = listed.entries[0]?.id;
    if (id) await send({ type: 'DELETE_ENTRY', entryId: id });
  });

  it('does nothing when the vault is locked', async () => {
    await send({ type: 'LOCK' });
    await pressHotkey();
    expect(dispatches).toEqual([]);
  });
});

/**
 * Trash, through the service worker. The property that matters most is the last
 * one: a deleted login must stop being offered for autofill immediately, on every
 * path, or "delete" does not mean what the user thinks it means.
 */
describe('trash', () => {
  /**
   * A distinct registrable domain per test. Entries accumulate across this file
   * and these tests assert on *how many* match — and since matching is same-site,
   * sharing even a parent domain (example.org) would pull in other blocks' logins.
   */
  async function trashableEntry(name: string): Promise<{ id: string; site: string }> {
    const site = `https://${name}-trash.org`;
    await send({ type: 'UNLOCK', masterPassword: MASTER_PASSWORD });
    await saveEntry(name, site);
    const listed = await send({ type: 'LIST_ENTRIES', query: name });
    if (!listed.ok || listed.type !== 'ENTRIES') throw new Error('expected entries');
    const id = listed.entries[0]?.id;
    if (!id) throw new Error('entry not created');
    return { id, site };
  }

  it('hides a deleted entry from lists and offers it in the trash instead', async () => {
    const { id } = await trashableEntry('binned');
    expect((await send({ type: 'DELETE_ENTRY', entryId: id })).ok).toBe(true);

    const listed = await send({ type: 'LIST_ENTRIES', query: 'binned' });
    if (!listed.ok || listed.type !== 'ENTRIES') throw new Error('expected entries');
    expect(listed.entries).toHaveLength(0);

    const trash = await send({ type: 'LIST_TRASH' });
    if (!trash.ok || trash.type !== 'ENTRIES') throw new Error('expected entries');
    expect(trash.entries.map((e) => e.id)).toContain(id);
    expect(trash.entries.find((e) => e.id === id)?.deletedAt).toBeTruthy();

    // ...and it comes back.
    expect((await send({ type: 'RESTORE_ENTRY', entryId: id })).ok).toBe(true);
    const relisted = await send({ type: 'LIST_ENTRIES', query: 'binned' });
    if (!relisted.ok || relisted.type !== 'ENTRIES') throw new Error('expected entries');
    expect(relisted.entries).toHaveLength(1);
  }, 60_000);

  it('stops offering a deleted entry for autofill, and refuses to fill it', async () => {
    const { id, site } = await trashableEntry('unfillable');
    tabUrl = `${site}/login`;
    expect(await entriesFor(`${site}/login`)).toHaveLength(1);

    await send({ type: 'DELETE_ENTRY', entryId: id });

    expect(await entriesFor(`${site}/login`)).toEqual([]);
    expect(await entriesFor(`${site}/login`, 'page')).toEqual([]);

    // Even asked for by id — the popup could be holding a stale list.
    dispatches = [];
    const refused = await send({ type: 'FILL', entryId: id, tabId: 1 });
    expect(refused.ok).toBe(false);
    expect(dispatches).toEqual([]);
  }, 60_000);

  it('purges for good, leaving a tombstone rather than the entry', async () => {
    const { id } = await trashableEntry('purgeable');
    await send({ type: 'DELETE_ENTRY', entryId: id });
    expect((await send({ type: 'PURGE_ENTRY', entryId: id })).ok).toBe(true);

    const trash = await send({ type: 'LIST_TRASH' });
    if (!trash.ok || trash.type !== 'ENTRIES') throw new Error('expected entries');
    expect(trash.entries.map((e) => e.id)).not.toContain(id);

    // Gone: a second purge has nothing to work on.
    expect((await send({ type: 'PURGE_ENTRY', entryId: id })).ok).toBe(false);
  }, 60_000);

  it('sweeps trash older than 30 days on unlock, and leaves yesterday alone', async () => {
    const {
      createEntry,
      createVault,
      deleteEntry,
      saveVault,
      TRASH_RETENTION_DAYS,
      unlockVault,
    } = await import('@keyhole/core');
    const dayMs = 24 * 60 * 60 * 1000;
    const password = 'trash-sweep-master-pw';

    // Keep the shared vault so later tests in this file still unlock.
    const backup = await send({ type: 'EXPORT_VAULT' });
    if (!backup.ok || backup.type !== 'EXPORT') throw new Error('expected export');

    // Build a vault outside the shared stub so we can fabricate deletedAt
    // without a test-only mutation path in the service worker.
    const { file: created, session } = await createVault(password);
    const expired = createEntry(session.data, {
      title: 'Expired trash',
      username: 'old@test',
      password: 'x',
      urls: ['https://expired-sweep.org'],
    });
    const fresh = createEntry(expired.data, {
      title: 'Fresh trash',
      username: 'new@test',
      password: 'y',
      urls: ['https://fresh-sweep.org'],
    });
    session.data = deleteEntry(deleteEntry(fresh.data, expired.entry.id), fresh.entry.id);

    const expiredIndex = session.data.entries.findIndex((e) => e.id === expired.entry.id);
    const freshIndex = session.data.entries.findIndex((e) => e.id === fresh.entry.id);
    const now = Date.now();
    session.data.entries[expiredIndex] = {
      ...session.data.entries[expiredIndex]!,
      deletedAt: new Date(now - (TRASH_RETENTION_DAYS + 1) * dayMs).toISOString(),
    };
    session.data.entries[freshIndex] = {
      ...session.data.entries[freshIndex]!,
      deletedAt: new Date(now - dayMs).toISOString(),
    };

    const seeded = await saveVault(session, created);
    expect((await send({ type: 'IMPORT_VAULT', file: seeded })).ok).toBe(true);
    expect((await send({ type: 'UNLOCK', masterPassword: password })).ok).toBe(true);

    const trash = await send({ type: 'LIST_TRASH' });
    if (!trash.ok || trash.type !== 'ENTRIES') throw new Error('expected entries');
    expect(trash.entries.map((e) => e.id)).not.toContain(expired.entry.id);
    expect(trash.entries.map((e) => e.id)).toContain(fresh.entry.id);

    // Confirm a tombstone was written for the purge.
    const exported = await send({ type: 'EXPORT_VAULT' });
    if (!exported.ok || exported.type !== 'EXPORT') throw new Error('expected export');
    const reopened = await unlockVault(exported.file, password);
    expect(reopened.data.tombstones.some((t) => t.id === expired.entry.id && t.kind === 'entry')).toBe(true);
    expect(reopened.data.entries.some((e) => e.id === expired.entry.id)).toBe(false);

    expect((await send({ type: 'IMPORT_VAULT', file: backup.file })).ok).toBe(true);
    expect((await send({ type: 'UNLOCK', masterPassword: MASTER_PASSWORD })).ok).toBe(true);
  }, 60_000);
});

/**
 * Opening an existing entry and pressing Save used to wipe every field the
 * options editor did not load from the summary (notes, tags, TOTP, extra URLs).
 */
describe('entry editor round-trip', () => {
  it('preserves fields absent from a partial SAVE_ENTRY patch', async () => {
    await send({ type: 'UNLOCK', masterPassword: MASTER_PASSWORD });
    const created = await send({
      type: 'SAVE_ENTRY',
      entry: {
        title: 'Round trip',
        username: 'user@example.test',
        password: 'keep-me',
        urls: ['https://one.example.org/login', 'https://two.example.org/app'],
        notes: 'recovery codes live here',
        tags: ['work', 'important'],
        totpSecret: 'JBSWY3DPEHPK3PXP',
      },
    });
    expect(created.ok).toBe(true);

    const listed = await send({ type: 'LIST_ENTRIES', query: 'Round trip' });
    if (!listed.ok || listed.type !== 'ENTRIES') throw new Error('expected entries');
    const id = listed.entries[0]?.id;
    expect(id).toBeTruthy();

    const loaded = await send({ type: 'GET_ENTRY', entryId: id! });
    if (!loaded.ok || loaded.type !== 'ENTRY') throw new Error('expected entry');
    expect(loaded.entry.notes).toBe('recovery codes live here');
    expect(loaded.entry.tags).toEqual(['work', 'important']);
    expect(loaded.entry.totpSecret).toBe('JBSWY3DPEHPK3PXP');
    expect(loaded.entry.urls).toHaveLength(2);

    // Title only — the bug defaulted every missing key to empty.
    const saved = await send({
      type: 'SAVE_ENTRY',
      entry: { id, title: 'Round trip renamed' },
    });
    expect(saved.ok).toBe(true);

    const after = await send({ type: 'GET_ENTRY', entryId: id! });
    if (!after.ok || after.type !== 'ENTRY') throw new Error('expected entry');
    expect(after.entry.title).toBe('Round trip renamed');
    expect(after.entry.username).toBe('user@example.test');
    expect(after.entry.password).toBe('keep-me');
    expect(after.entry.notes).toBe('recovery codes live here');
    expect(after.entry.tags).toEqual(['work', 'important']);
    expect(after.entry.totpSecret).toBe('JBSWY3DPEHPK3PXP');
    expect(after.entry.urls).toEqual([
      'https://one.example.org/login',
      'https://two.example.org/app',
    ]);
  }, 60_000);
});
