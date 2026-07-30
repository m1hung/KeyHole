/**
 * End-to-end check of the health panel's batch delete, driven through the real
 * service worker rather than through core directly.
 *
 * `deleteEntries` is unit-tested in core. What is tested here is the wiring, and
 * the two properties that make a bulk action on a machine-generated list safe to
 * offer at all:
 *
 *  - it is the REVERSIBLE delete — the entries land in the trash and come back,
 *    rather than being destroyed on this device and every synced one;
 *  - it is privileged — a content script cannot reach it, so a hostile page
 *    cannot empty a vault into the trash without the user ever seeing the popup.
 */

import { beforeAll, describe, expect, it } from 'vitest';
import type { EntrySummary, Response } from '../src/shared/messages.ts';

const EXTENSION_ID = 'abcdefghijklmnopabcdefghijklmnop';
const MASTER_PASSWORD = 'correct horse battery staple';

type Listener = (
  raw: unknown,
  sender: chrome.runtime.MessageSender,
  sendResponse: (response: Response) => void,
) => boolean | void;

const listeners: Listener[] = [];

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
      session: { get: async () => ({}), set: async () => {}, remove: async () => {} },
    },
    alarms: { create: async () => {}, clear: async () => {}, onAlarm: { addListener: noop } },
    commands: { onCommand: { addListener: noop } },
    action: {
      setBadgeText: async () => {},
      setBadgeBackgroundColor: async () => {},
      setBadgeTextColor: async () => {},
    },
    tabs: {
      get: async () => ({ url: 'https://example.com/' }),
      query: async () => [{ id: 1, url: 'https://example.com/', active: true }],
      sendMessage: async () => ({}),
      onActivated: { addListener: noop },
      onUpdated: { addListener: noop },
    },
    scripting: { executeScript: async () => [] },
    permissions: { contains: async () => true },
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
  url: `chrome-extension://${EXTENSION_ID}/options.html`,
} as chrome.runtime.MessageSender;

/** A content script in a page — untrusted, whatever it claims to be sending. */
const pageSender = {
  id: EXTENSION_ID,
  url: 'https://example.com/',
  frameId: 0,
  tab: { id: 1 },
} as unknown as chrome.runtime.MessageSender;

async function send(message: unknown, sender = popupSender): Promise<Response> {
  const listener = listeners[0];
  if (!listener) throw new Error('service worker registered no message listener');
  return new Promise<Response>((resolve) => {
    listener(message, sender, resolve);
  });
}

async function listEntries(message: 'LIST_ENTRIES' | 'LIST_TRASH'): Promise<EntrySummary[]> {
  const response = await send({ type: message });
  if (!response.ok || response.type !== 'ENTRIES') throw new Error(`unexpected: ${JSON.stringify(response)}`);
  return response.entries;
}

async function health(): Promise<Extract<Response, { type: 'HEALTH' }>> {
  const response = await send({ type: 'HEALTH_REPORT' });
  if (!response.ok || response.type !== 'HEALTH') throw new Error(`unexpected: ${JSON.stringify(response)}`);
  return response;
}

async function idsFor(...titles: string[]): Promise<string[]> {
  const entries = await listEntries('LIST_ENTRIES');
  return titles.map((title) => {
    const found = entries.find((e) => e.title === title);
    if (!found) throw new Error(`no entry titled ${title}`);
    return found.id;
  });
}

beforeAll(async () => {
  installChromeStub();
  await import('../src/background/service-worker.ts');
  const created = await send({ type: 'CREATE_VAULT', masterPassword: MASTER_PASSWORD });
  expect(created.ok).toBe(true);

  // Two share a password (reused + weak), one is weak alone, one is healthy.
  for (const [title, password] of [
    ['Forum', 'hunter2'],
    ['Newsletter', 'hunter2'],
    ['Airline', '1234'],
    ['Bank', 'C9!wq2-Ledger_Trout_49xz'],
  ] as const) {
    const saved = await send({
      type: 'SAVE_ENTRY',
      entry: { title, username: `me@${title}.test`, password, urls: [`https://${title}.example`] },
    });
    expect(saved.ok).toBe(true);
  }
}, 60_000);

describe('DELETE_ENTRIES — the health panel batch action', () => {
  it('reports the findings the panel groups into selectable rows', async () => {
    const report = await health();
    expect(report.loginCount).toBe(4);
    // Both shared-password entries are reused; the healthy one is named by nothing.
    expect(report.issues.filter((i) => i.kind === 'reused').map((i) => i.title).sort()).toEqual([
      'Forum',
      'Newsletter',
    ]);
    expect(report.issues.some((i) => i.title === 'Bank')).toBe(false);
  });

  it('bins every named entry in one call and leaves the rest alone', async () => {
    const ids = await idsFor('Forum', 'Newsletter');
    expect((await send({ type: 'DELETE_ENTRIES', entryIds: ids })).ok).toBe(true);

    expect((await listEntries('LIST_ENTRIES')).map((e) => e.title).sort()).toEqual(['Airline', 'Bank']);
    expect((await listEntries('LIST_TRASH')).map((e) => e.title).sort()).toEqual(['Forum', 'Newsletter']);

    // The finding that only existed because both were live is gone with them.
    const report = await health();
    expect(report.loginCount).toBe(2);
    expect(report.issues.some((i) => i.kind === 'reused')).toBe(false);
  });

  it('is the reversible delete: a batch is restorable entry by entry', async () => {
    const [trashed] = await listEntries('LIST_TRASH');
    expect(trashed).toBeDefined();
    expect((await send({ type: 'RESTORE_ENTRY', entryId: trashed!.id })).ok).toBe(true);
    expect((await listEntries('LIST_ENTRIES')).map((e) => e.title)).toContain(trashed!.title);
  });

  it('survives an id that is already binned or unknown to the vault', async () => {
    const [live] = await idsFor('Airline');
    const stranger = '11111111-1111-4111-8111-111111111111';
    const alreadyBinned = (await listEntries('LIST_TRASH'))[0];
    expect(alreadyBinned).toBeDefined();

    // A stale selection must not cost the deletions that are still valid: the
    // health report the user acted on is a snapshot, and sync moves under it.
    const response = await send({
      type: 'DELETE_ENTRIES',
      entryIds: [live!, stranger, alreadyBinned!.id],
    });
    expect(response.ok).toBe(true);
    expect((await listEntries('LIST_ENTRIES')).some((e) => e.title === 'Airline')).toBe(false);
  });

  it('refuses a content script, so a page cannot bulk-delete a vault', async () => {
    const ids = await idsFor('Bank');
    const response = await send({ type: 'DELETE_ENTRIES', entryIds: ids }, pageSender);
    expect(response.ok).toBe(false);
    // Still there, and still the only healthy login.
    expect((await listEntries('LIST_ENTRIES')).map((e) => e.title)).toContain('Bank');
  });

  it('refuses once the vault is locked', async () => {
    const ids = await idsFor('Bank');
    expect((await send({ type: 'LOCK' })).ok).toBe(true);
    const response = await send({ type: 'DELETE_ENTRIES', entryIds: ids });
    expect(response.ok).toBe(false);
  });
});
