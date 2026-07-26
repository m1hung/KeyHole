import { beforeAll, describe, expect, it } from 'vitest';
import { isFromOwnExtension, isTrustedExtensionSender, requestSchema } from '../src/shared/messages.ts';

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

  it('REJECTS a content script, even one of ours', () => {
    // This is the critical case: our own content script carries our extension
    // id, but runs in a tab. It must never be able to request a decrypt.
    expect(
      isTrustedExtensionSender(
        sender({ id: EXTENSION_ID, url: 'https://evil.example/login', tab: { id: 7 } }),
      ),
    ).toBe(false);
  });

  it('REJECTS a content script even when it forges an extension URL', () => {
    // A compromised page cannot set sender.url, but defence in depth: the
    // presence of `tab` alone is disqualifying.
    expect(
      isTrustedExtensionSender(
        sender({
          id: EXTENSION_ID,
          url: `chrome-extension://${EXTENSION_ID}/popup.html`,
          tab: { id: 7 },
        }),
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

  it('REJECTS a missing or non-string url', () => {
    expect(isTrustedExtensionSender(sender({ id: EXTENSION_ID }))).toBe(false);
    expect(isTrustedExtensionSender(sender({ id: EXTENSION_ID, url: undefined }))).toBe(false);
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

describe('requestSchema', () => {
  it('accepts well-formed requests', () => {
    const valid: unknown[] = [
      { type: 'GET_STATE' },
      { type: 'UNLOCK', masterPassword: 'correct horse battery staple' },
      { type: 'LOCK' },
      { type: 'MATCH_TAB', tabId: 3 },
      { type: 'FILL', entryId: '11111111-1111-4111-8111-111111111111', tabId: 0 },
      { type: 'REVEAL_SECRET', entryId: '11111111-1111-4111-8111-111111111111', field: 'password' },
    ];
    for (const request of valid) {
      expect(requestSchema.safeParse(request).success).toBe(true);
    }
  });

  it('rejects unknown message types', () => {
    expect(requestSchema.safeParse({ type: 'DUMP_VAULT' }).success).toBe(false);
    expect(requestSchema.safeParse({ type: 'EXPORT_KEY' }).success).toBe(false);
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
