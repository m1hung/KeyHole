import { beforeAll, describe, expect, it } from 'vitest';
import {
  contentScriptRequestSchema,
  isContentScriptSender,
  isFromOwnExtension,
  isTrustedExtensionSender,
  requestSchema,
} from '../src/shared/messages.ts';

const EXTENSION_ID = 'abcdefghijklmnopabcdefghijklmnop';
const OTHER_EXTENSION_ID = 'zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz';

beforeAll(() => {
  // Minimal chrome stub — only `runtime.id` is consulted by these functions.
  (globalThis as { chrome?: unknown }).chrome = { runtime: { id: EXTENSION_ID } };
});

/**
 * Build a MessageSender with only the fields the guard inspects.
 *
 * Takes a loose record rather than Partial<MessageSender>: these tests
 * deliberately construct malformed senders, including an explicitly-undefined
 * `url`, which exactOptionalPropertyTypes forbids on the real type.
 */
function sender(overrides: Record<string, unknown>): chrome.runtime.MessageSender {
  return overrides as chrome.runtime.MessageSender;
}

describe('isTrustedExtensionSender — the privileged-message gate', () => {
  it('accepts the popup', () => {
    expect(
      isTrustedExtensionSender(sender({ id: EXTENSION_ID, url: `chrome-extension://${EXTENSION_ID}/popup.html` })),
    ).toBe(true);
  });

  it('accepts the options page', () => {
    expect(
      isTrustedExtensionSender(sender({ id: EXTENSION_ID, url: `chrome-extension://${EXTENSION_ID}/options.html` })),
    ).toBe(true);
  });

  it('accepts an options page opened in a popup window (has a tab)', () => {
    // chrome.windows.create({ type: 'popup' }) still attaches a Tab to the
    // sender. That must not block unlock / import from the vault window.
    expect(
      isTrustedExtensionSender(
        sender({
          id: EXTENSION_ID,
          url: `chrome-extension://${EXTENSION_ID}/options.html`,
          tab: { id: 7, url: `chrome-extension://${EXTENSION_ID}/options.html` },
        }),
      ),
    ).toBe(true);
  });

  it('REJECTS a content script, even one of ours', () => {
    // This is the critical case: our own content script carries our extension
    // id, but runs in a tab with the *page* URL. It must never decrypt.
    expect(
      isTrustedExtensionSender(
        sender({ id: EXTENSION_ID, url: 'https://evil.example/login', tab: { id: 7 } }),
      ),
    ).toBe(false);
  });

  it('REJECTS another extension', () => {
    expect(
      isTrustedExtensionSender(
        sender({ id: OTHER_EXTENSION_ID, url: `chrome-extension://${OTHER_EXTENSION_ID}/popup.html` }),
      ),
    ).toBe(false);
  });

  it('REJECTS another extension impersonating our URL', () => {
    expect(
      isTrustedExtensionSender(
        sender({ id: OTHER_EXTENSION_ID, url: `chrome-extension://${EXTENSION_ID}/popup.html` }),
      ),
    ).toBe(false);
  });

  it('REJECTS a web page origin', () => {
    expect(isTrustedExtensionSender(sender({ id: EXTENSION_ID, url: 'https://example.com/' }))).toBe(false);
  });

  it('REJECTS a URL that merely contains our extension origin', () => {
    // startsWith, not includes — otherwise this would pass.
    expect(
      isTrustedExtensionSender(
        sender({ id: EXTENSION_ID, url: `https://evil.example/?x=chrome-extension://${EXTENSION_ID}/popup.html` }),
      ),
    ).toBe(false);
  });

  it('accepts the options page via origin when url is missing', () => {
    expect(
      isTrustedExtensionSender(sender({ id: EXTENSION_ID, origin: `chrome-extension://${EXTENSION_ID}` })),
    ).toBe(true);
  });

  it('REJECTS a content script origin', () => {
    expect(
      isTrustedExtensionSender(
        sender({ id: EXTENSION_ID, origin: 'https://evil.example', url: 'https://evil.example/login', tab: { id: 7 } }),
      ),
    ).toBe(false);
  });

  it('REJECTS an empty sender', () => {
    expect(isTrustedExtensionSender(sender({}))).toBe(false);
  });
});

describe('isFromOwnExtension — content script side', () => {
  it('accepts our own extension and rejects others', () => {
    expect(isFromOwnExtension(sender({ id: EXTENSION_ID }))).toBe(true);
    expect(isFromOwnExtension(sender({ id: OTHER_EXTENSION_ID }))).toBe(false);
    expect(isFromOwnExtension(sender({}))).toBe(false);
  });
});

describe('isContentScriptSender — page-injected script gate', () => {
  it('accepts our content script in a web tab', () => {
    expect(
      isContentScriptSender(
        sender({ id: EXTENSION_ID, url: 'https://example.com/login', tab: { id: 7 } }),
      ),
    ).toBe(true);
  });

  it('REJECTS extension pages even when they have a tab', () => {
    expect(
      isContentScriptSender(
        sender({
          id: EXTENSION_ID,
          url: `chrome-extension://${EXTENSION_ID}/options.html`,
          tab: { id: 7, url: `chrome-extension://${EXTENSION_ID}/options.html` },
        }),
      ),
    ).toBe(false);
  });

  it('REJECTS messages without a tab id', () => {
    expect(isContentScriptSender(sender({ id: EXTENSION_ID, url: 'https://example.com/' }))).toBe(false);
  });

  it('REJECTS another extension', () => {
    expect(
      isContentScriptSender(
        sender({ id: OTHER_EXTENSION_ID, url: 'https://example.com/', tab: { id: 1 } }),
      ),
    ).toBe(false);
  });
});

describe('contentScriptRequestSchema', () => {
  it('accepts suggest, fill-from-page, and save-from-page', () => {
    expect(contentScriptRequestSchema.safeParse({ type: 'SUGGEST_FOR_PAGE' }).success).toBe(true);
    expect(
      contentScriptRequestSchema.safeParse({
        type: 'FILL_FROM_PAGE',
        entryId: '11111111-1111-4111-8111-111111111111',
      }).success,
    ).toBe(true);
    expect(
      contentScriptRequestSchema.safeParse({
        type: 'SAVE_FROM_PAGE',
        username: 'ada',
        password: 'hunter2',
      }).success,
    ).toBe(true);
    expect(
      contentScriptRequestSchema.safeParse({
        type: 'SAVE_FROM_PAGE',
        username: 'ada',
        password: 'hunter2',
        entryId: '11111111-1111-4111-8111-111111111111',
      }).success,
    ).toBe(true);
  });

  it('rejects privileged shapes and smuggled tab/url fields', () => {
    expect(contentScriptRequestSchema.safeParse({ type: 'EXPORT_VAULT' }).success).toBe(false);
    // A page must never be able to wipe the vault.
    expect(contentScriptRequestSchema.safeParse({ type: 'RESET_VAULT' }).success).toBe(false);
    // ...nor re-key it, which would lock the user out of their own vault.
    expect(
      contentScriptRequestSchema.safeParse({
        type: 'CHANGE_MASTER_PASSWORD',
        currentPassword: 'x'.repeat(20),
        newPassword: 'y'.repeat(20),
      }).success,
    ).toBe(false);
    expect(contentScriptRequestSchema.safeParse({ type: 'UNLOCK', masterPassword: 'x'.repeat(20) }).success).toBe(
      false,
    );
    expect(
      contentScriptRequestSchema.safeParse({ type: 'SUGGEST_FOR_PAGE', url: 'https://evil.example/' }).success,
    ).toBe(false);
    expect(
      contentScriptRequestSchema.safeParse({
        type: 'FILL_FROM_PAGE',
        entryId: '11111111-1111-4111-8111-111111111111',
        tabId: 9,
      }).success,
    ).toBe(false);
    expect(
      contentScriptRequestSchema.safeParse({
        type: 'SAVE_FROM_PAGE',
        username: 'ada',
        password: 'hunter2',
        urls: ['https://evil.example/'],
      }).success,
    ).toBe(false);
  });
});

describe('requestSchema', () => {
  it('accepts well-formed requests', () => {
    const valid: unknown[] = [
      { type: 'GET_STATE' },
      { type: 'UNLOCK', masterPassword: 'correct horse battery staple' },
      { type: 'LOCK' },
      { type: 'MATCH_TAB', tabId: 3 },
      { type: 'FILL', entryId: '11111111-1111-4111-8111-111111111111', tabId: 0 },
      { type: 'REVEAL_SECRET', entryId: '11111111-1111-4111-8111-111111111111', field: 'password' },
      { type: 'GET_ENTRY', entryId: '11111111-1111-4111-8111-111111111111' },
      { type: 'LIST_FOLDERS' },
      { type: 'CREATE_FOLDER', name: 'Work' },
      { type: 'DELETE_FOLDER', folderId: '11111111-1111-4111-8111-111111111111' },
      {
        type: 'UPDATE_VAULT_SETTINGS',
        autoLockMinutes: 10,
        clipboardClearSeconds: 20,
        lockOnHide: true,
        generator: {
          length: 20,
          lowercase: true,
          uppercase: true,
          digits: true,
          symbols: false,
          excludeAmbiguous: true,
        },
      },
      {
        type: 'REMOVE_PASSKEY',
        entryId: '11111111-1111-4111-8111-111111111111',
        passkeyId: '22222222-2222-4222-8222-222222222222',
      },
      { type: 'GET_SYNC_CONFIG' },
      {
        type: 'SYNC_REGISTER',
        masterPassword: 'correct horse battery staple',
        baseUrl: 'http://127.0.0.1:8787',
        accountId: 'you@home',
      },
      {
        type: 'SYNC_NOW',
        masterPassword: 'correct horse battery staple',
        baseUrl: 'http://127.0.0.1:8787',
        accountId: 'you@home',
      },
      {
        type: 'SYNC_NOW',
        baseUrl: 'http://127.0.0.1:8787',
        accountId: 'you@home',
      },
      {
        type: 'SAVE_SYNC_CONFIG',
        baseUrl: 'http://127.0.0.1:8787',
        accountId: 'you@home',
      },
    ];
    for (const request of valid) {
      expect(requestSchema.safeParse(request).success).toBe(true);
    }
  });

  it('accepts RESET_VAULT with no payload', () => {
    expect(requestSchema.safeParse({ type: 'RESET_VAULT' }).success).toBe(true);
    // No master password, no confirmation token: the guard is the sender check
    // plus the typed confirmation in the UI, and adding fields here would only
    // create a second, weaker path.
    expect(requestSchema.safeParse({ type: 'RESET_VAULT', confirm: 'DELETE' }).success).toBe(false);
  });

  it('accepts CHANGE_MASTER_PASSWORD with both passwords', () => {
    const request = { type: 'CHANGE_MASTER_PASSWORD', currentPassword: 'old-one', newPassword: 'new-one' };
    expect(requestSchema.safeParse(request).success).toBe(true);
    // Both are required: a re-key with a missing current password would be a
    // takeover, and one with no new password would be a lockout.
    expect(requestSchema.safeParse({ type: 'CHANGE_MASTER_PASSWORD', newPassword: 'new-one' }).success).toBe(false);
    expect(requestSchema.safeParse({ type: 'CHANGE_MASTER_PASSWORD', currentPassword: 'old-one' }).success).toBe(false);
    expect(requestSchema.safeParse({ ...request, currentPassword: '' }).success).toBe(false);
  });

  it('accepts DELETE_ENTRIES as a list of entry ids', () => {
    const id = '11111111-1111-4111-8111-111111111111';
    const other = '22222222-2222-4222-8222-222222222222';
    expect(requestSchema.safeParse({ type: 'DELETE_ENTRIES', entryIds: [id, other] }).success).toBe(true);
    // Every id is validated, so one bad member cannot slip a non-uuid into the
    // batch path, and an empty batch is a bug rather than a no-op worth serving.
    expect(requestSchema.safeParse({ type: 'DELETE_ENTRIES', entryIds: [id, 'nope'] }).success).toBe(false);
    expect(requestSchema.safeParse({ type: 'DELETE_ENTRIES', entryIds: [] }).success).toBe(false);
    expect(requestSchema.safeParse({ type: 'DELETE_ENTRIES', entryId: id }).success).toBe(false);
  });

  it('accepts SET_THEME', () => {
    expect(requestSchema.safeParse({ type: 'SET_THEME', theme: 'dark' }).success).toBe(true);
    expect(requestSchema.safeParse({ type: 'SET_THEME', theme: 'neon' }).success).toBe(false);
  });

  it('rejects extra fields, so a smuggled payload cannot ride along', () => {
    expect(requestSchema.safeParse({ type: 'GET_STATE', extra: 'payload' }).success).toBe(false);
    expect(requestSchema.safeParse({ type: 'LOCK', callback: 'x' }).success).toBe(false);
  });

  it('rejects malformed identifiers', () => {
    expect(requestSchema.safeParse({ type: 'FILL', entryId: 'not-a-uuid', tabId: 1 }).success).toBe(false);
    expect(
      requestSchema.safeParse({ type: 'FILL', entryId: '11111111-1111-4111-8111-111111111111', tabId: -1 }).success,
    ).toBe(false);
    expect(
      requestSchema.safeParse({ type: 'FILL', entryId: '11111111-1111-4111-8111-111111111111', tabId: 1.5 }).success,
    ).toBe(false);
  });

  it('rejects an unknown reveal field', () => {
    expect(
      requestSchema.safeParse({
        type: 'REVEAL_SECRET',
        entryId: '11111111-1111-4111-8111-111111111111',
        field: 'masterKey',
      }).success,
    ).toBe(false);
  });

  it('bounds the master password length', () => {
    expect(requestSchema.safeParse({ type: 'UNLOCK', masterPassword: '' }).success).toBe(false);
    expect(requestSchema.safeParse({ type: 'UNLOCK', masterPassword: 'x'.repeat(2000) }).success).toBe(false);
  });

  it('rejects non-objects', () => {
    for (const junk of [null, undefined, 'GET_STATE', 42, []]) {
      expect(requestSchema.safeParse(junk).success).toBe(false);
    }
  });
});
