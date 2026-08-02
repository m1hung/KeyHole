import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest';
import { mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { tmpdir } from 'node:os';
import { DatabaseSync } from 'node:sqlite';
import type { FastifyInstance } from 'fastify';
import { buildControlApp, createControlToken } from '../src/control.ts';
import { buildApp } from '../src/app.ts';
import { loadConfig } from '../src/config.ts';
import { Store } from '../src/db.ts';

const TOKEN = 'test-token-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const config = loadConfig({ databasePath: ':memory:', control: true, port: 8787, controlPort: 8788 });

let app: FastifyInstance;
let onStop: Mock<() => void>;
let onRestart: Mock<() => void>;
let setRegistration: Mock<(allow: boolean) => { allowRegistration: boolean; persisted: boolean }>;
let controlStore: Store;

/** The handlers fire on a short timer so the reply flushes first. */
const settle = () => new Promise((r) => setTimeout(r, 120));

beforeEach(() => {
  onStop = vi.fn<() => void>();
  onRestart = vi.fn<() => void>();
  setRegistration = vi.fn((allow: boolean) => ({ allowRegistration: allow, persisted: true }));
  controlStore = new Store(':memory:');
  app = buildControlApp({
    config,
    token: TOKEN,
    onStop,
    onRestart,
    setRegistration,
    store: controlStore,
  });
});

afterEach(async () => {
  await app.close();
  controlStore.close();
});

describe('control plane auth', () => {
  it('rejects a request with no Authorization header', async () => {
    const res = await app.inject({ method: 'GET', url: '/control/v1/status' });
    expect(res.statusCode).toBe(401);
  });

  it('rejects a wrong token', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/control/v1/status',
      headers: { authorization: 'Bearer not-the-token' },
    });
    expect(res.statusCode).toBe(401);
  });

  it('rejects a token that is a prefix of the real one', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/control/v1/status',
      headers: { authorization: `Bearer ${TOKEN.slice(0, -1)}` },
    });
    expect(res.statusCode).toBe(401);
  });

  it('rejects Basic auth carrying the token', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/control/v1/status',
      headers: { authorization: `Basic ${Buffer.from(`x:${TOKEN}`).toString('base64')}` },
    });
    expect(res.statusCode).toBe(401);
  });

  it('accepts the right token', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/control/v1/status',
      headers: { authorization: `Bearer ${TOKEN}` },
    });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toMatchObject({ ok: true, apiPort: 8787, controlPort: 8788 });
  });

  it('does not act on an unauthorised stop', async () => {
    await app.inject({ method: 'POST', url: '/control/v1/stop' });
    await settle();
    expect(onStop).not.toHaveBeenCalled();
  });
});

describe('control plane actions', () => {
  it('stops', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/control/v1/stop',
      headers: { authorization: `Bearer ${TOKEN}` },
    });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ ok: true, action: 'stop' });
    await settle();
    expect(onStop).toHaveBeenCalledOnce();
    expect(onRestart).not.toHaveBeenCalled();
  });

  it('restarts', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/control/v1/restart',
      headers: { authorization: `Bearer ${TOKEN}` },
    });
    expect(res.statusCode).toBe(200);
    await settle();
    expect(onRestart).toHaveBeenCalledOnce();
    expect(onStop).not.toHaveBeenCalled();
  });

  it('has no start route — nothing would be running to answer it', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/control/v1/start',
      headers: { authorization: `Bearer ${TOKEN}` },
    });
    expect(res.statusCode).toBe(404);
  });
});

describe('control plane registration toggle', () => {
  const post = (payload: Record<string, unknown>, auth = true) =>
    app.inject({
      method: 'POST',
      url: '/control/v1/registration',
      headers: auth ? { authorization: `Bearer ${TOKEN}` } : {},
      payload,
    });

  it('rejects an unauthenticated caller without acting', async () => {
    const res = await post({ allow: false }, false);
    expect(res.statusCode).toBe(401);
    expect(setRegistration).not.toHaveBeenCalled();
  });

  it('closes registration', async () => {
    const res = await post({ allow: false });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ ok: true, allowRegistration: false, persisted: true });
    expect(setRegistration).toHaveBeenCalledWith(false);
  });

  it('opens registration', async () => {
    const res = await post({ allow: true });
    expect(res.json()).toMatchObject({ allowRegistration: true });
  });

  // The string "false" is truthy. Coercing it would open registration while the
  // caller believed it was closing it — the worst possible direction to be wrong.
  it('rejects a stringy allow rather than coercing it', async () => {
    const res = await post({ allow: 'false' });
    expect(res.statusCode).toBe(400);
    expect(setRegistration).not.toHaveBeenCalled();
  });

  it('rejects a missing allow', async () => {
    expect((await post({})).statusCode).toBe(400);
    expect(setRegistration).not.toHaveBeenCalled();
  });

  it('reports when the change could not be persisted', async () => {
    setRegistration.mockReturnValueOnce({ allowRegistration: false, persisted: false });
    const res = await post({ allow: false });
    expect(res.json()).toMatchObject({ persisted: false });
  });

  it('gives a foreign origin no CORS headers on preflight', async () => {
    const res = await app.inject({
      method: 'OPTIONS',
      url: '/control/v1/registration',
      headers: { origin: 'https://evil.example', 'access-control-request-method': 'POST' },
    });
    expect(res.headers['access-control-allow-origin']).toBeUndefined();
  });
});

describe('control plane backup', () => {
  const tmpBackups = () =>
    readdirSync(tmpdir()).filter((f) => f.startsWith('keyhole-backup-')).length;

  it('rejects an unauthenticated caller', async () => {
    const res = await app.inject({ method: 'GET', url: '/control/v1/backup' });
    expect(res.statusCode).toBe(401);
  });

  // rawPayload, not body: body is decoded as UTF-8 and mangles the bytes, so an
  // assertion on it would pass for a file that is not a database.
  it('returns something that is actually a SQLite database', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/control/v1/backup',
      headers: { authorization: `Bearer ${TOKEN}` },
    });
    expect(res.statusCode).toBe(200);
    expect(res.rawPayload.subarray(0, 16).toString('latin1')).toBe('SQLite format 3\0');
    expect(res.headers['content-disposition']).toContain('.sqlite');
  });

  it('contains the data that was in the live store', async () => {
    controlStore.create({
      accountId: 'backup-subject',
      verifierSalt: 'c2FsdA==',
      verifierHash: 'aGFzaA==',
      envelope: '{"marker":"present"}',
    });

    const res = await app.inject({
      method: 'GET',
      url: '/control/v1/backup',
      headers: { authorization: `Bearer ${TOKEN}` },
    });

    const scratch = join(mkdtempSync(join(tmpdir(), 'keyhole-backup-verify-')), 'restored.sqlite');
    writeFileSync(scratch, res.rawPayload);
    const restored = new DatabaseSync(scratch);
    const row = restored
      .prepare('SELECT account_id, envelope FROM accounts WHERE account_id = ?')
      .get('backup-subject') as Record<string, string> | undefined;
    restored.close();
    rmSync(dirname(scratch), { recursive: true, force: true });

    expect(row?.['account_id']).toBe('backup-subject');
    expect(row?.['envelope']).toBe('{"marker":"present"}');
  });

  it('leaves no temp file behind', async () => {
    const before = tmpBackups();
    await app.inject({
      method: 'GET',
      url: '/control/v1/backup',
      headers: { authorization: `Bearer ${TOKEN}` },
    });
    expect(tmpBackups()).toBe(before);
  });

  it('gives a foreign origin no CORS headers on preflight', async () => {
    const res = await app.inject({
      method: 'OPTIONS',
      url: '/control/v1/backup',
      headers: { origin: 'https://evil.example', 'access-control-request-method': 'GET' },
    });
    expect(res.headers['access-control-allow-origin']).toBeUndefined();
  });
});

describe('control plane CORS', () => {
  it('allows the dashboard origin', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/control/v1/status',
      headers: { authorization: `Bearer ${TOKEN}`, origin: 'http://127.0.0.1:8787' },
    });
    expect(res.headers['access-control-allow-origin']).toBe('http://127.0.0.1:8787');
  });

  it('gives a foreign origin no CORS headers, so the browser discards the reply', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/control/v1/status',
      headers: { authorization: `Bearer ${TOKEN}`, origin: 'https://evil.example' },
    });
    expect(res.headers['access-control-allow-origin']).toBeUndefined();
  });

  it('does not let a foreign origin preflight its way in', async () => {
    const res = await app.inject({
      method: 'OPTIONS',
      url: '/control/v1/stop',
      headers: { origin: 'https://evil.example', 'access-control-request-method': 'POST' },
    });
    expect(res.headers['access-control-allow-origin']).toBeUndefined();
  });
});

/**
 * The mechanism, not the route: the control plane and the API share one mutable
 * config object, and POST /api/v1/account reads the field per request. A future
 * refactor that copied the config, or froze it, would break this silently — the
 * toggle would report success and change nothing.
 */
describe('registration toggle reaches the API', () => {
  it('closes and reopens account creation on the live API', async () => {
    const shared = loadConfig({ databasePath: ':memory:', control: true, allowRegistration: true });
    const store = new Store(':memory:');
    const api = buildApp({ config: shared, store });
    const control = buildControlApp({
      config: shared,
      token: TOKEN,
      onStop: () => {},
      onRestart: () => {},
      setRegistration: (allow) => {
        shared.allowRegistration = allow;
        return { allowRegistration: allow, persisted: false };
      },
      store,
    });

    const register = (accountId: string) =>
      api.inject({
        method: 'POST',
        url: '/api/v1/account',
        payload: {
          accountId,
          authSecret: Buffer.alloc(32, 3).toString('base64'),
          envelope: {
            format: 'keyhole.vault',
            formatVersion: 1,
            vaultId: '33333333-3333-4333-8333-333333333333',
            kdf: {
              algorithm: 'argon2id',
              memoryKiB: 65536,
              iterations: 3,
              parallelism: 1,
              saltB64: Buffer.alloc(16, 1).toString('base64'),
              keyLength: 32,
            },
            wrappedKey: { ivB64: 'AAAAAAAAAAAAAAAA', ctB64: 'Y2lwaGVy' },
            payload: { ivB64: 'BBBBBBBBBBBBBBBB', ctB64: 'cGF5bG9hZA==' },
          },
        },
      });

    expect((await register('first')).statusCode).toBe(201);

    await control.inject({
      method: 'POST',
      url: '/control/v1/registration',
      headers: { authorization: `Bearer ${TOKEN}` },
      payload: { allow: false },
    });
    expect((await register('second')).statusCode).toBe(403);

    await control.inject({
      method: 'POST',
      url: '/control/v1/registration',
      headers: { authorization: `Bearer ${TOKEN}` },
      payload: { allow: true },
    });
    expect((await register('third')).statusCode).toBe(201);

    // And the status route reports the live value, not a boot-time snapshot.
    const status = await control.inject({
      method: 'GET',
      url: '/control/v1/status',
      headers: { authorization: `Bearer ${TOKEN}` },
    });
    expect(status.json()).toMatchObject({ allowRegistration: true });

    await api.close();
    await control.close();
    store.close();
  });
});

describe('control token', () => {
  it('does not write a file for an in-memory database', () => {
    const { token, path } = createControlToken(':memory:');
    expect(path).toBeUndefined();
    expect(token.length).toBeGreaterThan(20);
  });

  it('issues a different token each time, so a leaked one dies on restart', () => {
    expect(createControlToken(':memory:').token).not.toBe(createControlToken(':memory:').token);
  });
});

describe('dashboard exposure of the control token', () => {
  let store: Store;
  let api: FastifyInstance;

  beforeEach(() => {
    store = new Store(':memory:');
    api = buildApp({ config, store, controlToken: TOKEN });
  });

  afterEach(async () => {
    await api.close();
  });

  it('embeds the controls for a direct loopback request', async () => {
    const res = await api.inject({ method: 'GET', url: '/' });
    expect(res.statusCode).toBe(200);
    expect(res.body).toContain('id="restart-btn"');
    expect(res.body).toContain(TOKEN);
  });

  it('withholds the token when a proxy forwarded the request', async () => {
    const res = await api.inject({
      method: 'GET',
      url: '/',
      headers: { 'x-forwarded-for': '100.70.35.91' },
    });
    expect(res.statusCode).toBe(200);
    expect(res.body).not.toContain(TOKEN);
    // Assert on the button ids, not the visible heading: prose appears in CSS
    // comments and stylesheet text too, which made this pass for the wrong
    // reason once already.
    expect(res.body).not.toContain('id="restart-btn"');
    expect(res.body).not.toContain('id="stop-btn"');
  });

  it('withholds the token from a tailscale-identified viewer', async () => {
    const res = await api.inject({
      method: 'GET',
      url: '/',
      headers: { 'tailscale-user-login': 'someone@example.com' },
    });
    expect(res.body).not.toContain(TOKEN);
  });

  it('shows host details to a direct loopback viewer', async () => {
    const res = await api.inject({ method: 'GET', url: '/' });
    expect(res.body).toContain('This host');
    expect(res.body).toContain(String(process.pid));
  });

  it('withholds host details from a proxied viewer', async () => {
    const res = await api.inject({
      method: 'GET',
      url: '/',
      headers: { 'x-forwarded-for': '100.70.35.91' },
    });
    expect(res.body).not.toContain('This host');
    expect(res.body).not.toContain(String(process.pid));
  });

  it('still renders the page for a proxied viewer', async () => {
    const res = await api.inject({
      method: 'GET',
      url: '/',
      headers: { 'x-forwarded-for': '100.70.35.91' },
    });
    expect(res.statusCode).toBe(200);
    expect(res.body).toContain('Keyhole');
    expect(res.body).toContain('Live console');
  });

  it('renders no controls at all when the control plane is off', async () => {
    const off = buildApp({ config, store: new Store(':memory:') });
    const res = await off.inject({ method: 'GET', url: '/' });
    expect(res.body).not.toContain('id="restart-btn"');
    expect(res.body).not.toContain('id="stop-btn"');
    await off.close();
  });

  it('shows the roster, with account ids, to a direct loopback viewer', async () => {
    store.create({
      accountId: 'someone@example.com',
      verifierSalt: 'c2FsdA==',
      verifierHash: 'aGFzaA==',
      envelope: '{}',
    });
    const res = await api.inject({ method: 'GET', url: '/' });
    expect(res.body).toContain('class="rows roster"');
    expect(res.body).toContain('someone@example.com');
  });

  it('withholds the roster and the account ids from a proxied viewer', async () => {
    store.create({
      accountId: 'someone@example.com',
      verifierSalt: 'c2FsdA==',
      verifierHash: 'aGFzaA==',
      envelope: '{}',
    });
    const res = await api.inject({
      method: 'GET',
      url: '/',
      headers: { 'x-forwarded-for': '100.70.35.91' },
    });
    expect(res.body).not.toContain('class="rows roster"');
    expect(res.body).not.toContain('someone@example.com');
  });

  it('never exposes verifier material in the roster', async () => {
    store.create({
      accountId: 'someone@example.com',
      verifierSalt: 'VUNIQUESALT==',
      verifierHash: 'VUNIQUEHASH==',
      envelope: '{}',
    });
    const res = await api.inject({ method: 'GET', url: '/' });
    expect(res.body).not.toContain('VUNIQUESALT');
    expect(res.body).not.toContain('VUNIQUEHASH');
  });

  it('offers the console export to everyone — it is the viewer’s own data', async () => {
    const res = await api.inject({
      method: 'GET',
      url: '/',
      headers: { 'x-forwarded-for': '100.70.35.91' },
    });
    expect(res.body).toContain('id="export-btn"');
  });
});
