import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { buildApp } from '../src/app.ts';
import { loadConfig } from '../src/config.ts';
import { Store } from '../src/db.ts';

const SECRET = Buffer.alloc(32, 7).toString('base64');
const OTHER_SECRET = Buffer.alloc(32, 9).toString('base64');

/** A structurally valid envelope. Contents are opaque to the server. */
function envelope(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    format: 'keyhole.vault',
    formatVersion: 1,
    vaultId: '11111111-1111-4111-8111-111111111111',
    createdAt: '2026-01-01T00:00:00.000Z',
    updatedAt: '2026-01-01T00:00:00.000Z',
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
    ...overrides,
  };
}

const basic = (account: string, secret: string) =>
  `Basic ${Buffer.from(`${account}:${secret}`).toString('base64')}`;

let app: FastifyInstance;
let store: Store;

beforeEach(async () => {
  store = new Store(':memory:');
  app = buildApp({ config: loadConfig({ databasePath: ':memory:' }), store });
  await app.ready();
});

afterEach(async () => {
  await app.close();
  store.close();
});

async function register(accountId = 'alice', secret = SECRET) {
  return app.inject({
    method: 'POST',
    url: '/api/v1/account',
    payload: { accountId, authSecret: secret, envelope: envelope() },
  });
}

describe('health', () => {
  it('reports readiness', async () => {
    const res = await app.inject({ method: 'GET', url: '/api/v1/health' });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toMatchObject({ ok: true, apiVersion: 1 });
  });

  it('serves a status page at /', async () => {
    const res = await app.inject({ method: 'GET', url: '/' });
    expect(res.statusCode).toBe(200);
    expect(res.headers['content-type']).toMatch(/text\/html/);
    expect(res.body).toContain('Keyhole');
    expect(res.body).toContain('Healthy');
    expect(res.body).toContain('--accent');
    expect(res.body).toContain('Live console');
    expect(res.body).toContain('/api/v1/console');
  });

  it('allows cross-origin browser clients (CORS)', async () => {
    const origin = 'http://127.0.0.1:5173';
    const preflight = await app.inject({
      method: 'OPTIONS',
      url: '/api/v1/account',
      headers: {
        origin,
        'access-control-request-method': 'POST',
        'access-control-request-headers': 'content-type',
      },
    });
    expect(preflight.statusCode).toBe(204);
    expect(preflight.headers['access-control-allow-origin']).toBe(origin);
    expect(String(preflight.headers['access-control-allow-methods'])).toMatch(/POST/);

    const health = await app.inject({
      method: 'GET',
      url: '/api/v1/health',
      headers: { origin },
    });
    expect(health.statusCode).toBe(200);
    expect(health.headers['access-control-allow-origin']).toBe(origin);
  });
});

describe('registration', () => {
  it('creates an account at version 1', async () => {
    const res = await register();
    expect(res.statusCode).toBe(201);
    expect(res.json()).toMatchObject({ accountId: 'alice', version: 1 });
  });

  it('normalises the account id', async () => {
    await register('Alice');
    const res = await app.inject({ method: 'GET', url: '/api/v1/vault', headers: { authorization: basic('ALICE', SECRET) } });
    expect(res.statusCode).toBe(200);
  });

  it('refuses a duplicate account', async () => {
    await register();
    expect((await register()).statusCode).toBe(409);
  });

  it('rejects junk in place of an envelope', async () => {
    for (const bad of [null, 'a string', 42, {}, { format: 'not-keyhole' }, [envelope()]]) {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/account',
        payload: { accountId: 'bob', authSecret: SECRET, envelope: bad },
      });
      expect(res.statusCode).toBe(400);
    }
  });

  it('rejects malformed account identifiers', async () => {
    for (const bad of ['ab', 'has space', 'x'.repeat(65), '../etc/passwd', '']) {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/account',
        payload: { accountId: bad, authSecret: SECRET, envelope: envelope() },
      });
      expect(res.statusCode).toBe(400);
    }
  });

  it('can be closed off entirely', async () => {
    const closed = buildApp({ config: loadConfig({ databasePath: ':memory:', allowRegistration: false }), store });
    await closed.ready();
    const res = await closed.inject({
      method: 'POST',
      url: '/api/v1/account',
      payload: { accountId: 'mallory', authSecret: SECRET, envelope: envelope() },
    });
    expect(res.statusCode).toBe(403);
    await closed.close();
  });
});

describe('authentication', () => {
  it('rejects a wrong secret', async () => {
    await register();
    const res = await app.inject({ method: 'GET', url: '/api/v1/vault', headers: { authorization: basic('alice', OTHER_SECRET) } });
    expect(res.statusCode).toBe(401);
  });

  it('rejects a missing or malformed header', async () => {
    await register();
    for (const header of [undefined, '', 'Bearer token', 'Basic !!!not-base64', 'Basic ' + Buffer.from('nocolon').toString('base64')]) {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/vault',
        ...(header === undefined ? {} : { headers: { authorization: header } }),
      });
      expect(res.statusCode).toBe(401);
    }
  });

  it('gives the same answer for an unknown account as for a wrong secret', async () => {
    await register();
    const unknown = await app.inject({ method: 'GET', url: '/api/v1/vault', headers: { authorization: basic('nobody', SECRET) } });
    const wrong = await app.inject({ method: 'GET', url: '/api/v1/vault', headers: { authorization: basic('alice', OTHER_SECRET) } });
    expect(unknown.statusCode).toBe(wrong.statusCode);
    expect(unknown.json()).toEqual(wrong.json());
  });

  it("cannot read another account's vault", async () => {
    await register('alice', SECRET);
    await register('bob', OTHER_SECRET);
    const res = await app.inject({ method: 'GET', url: '/api/v1/vault', headers: { authorization: basic('bob', SECRET) } });
    expect(res.statusCode).toBe(401);
  });
});

describe('prelogin', () => {
  it('returns the real KDF parameters for a known account', async () => {
    await register();
    const res = await app.inject({ method: 'GET', url: '/api/v1/prelogin?account=alice' });
    expect(res.statusCode).toBe(200);
    expect(res.json().kdf).toMatchObject({ algorithm: 'argon2id', memoryKiB: 65536, iterations: 3 });
  });

  it('does not reveal whether an account exists', async () => {
    await register();
    const known = await app.inject({ method: 'GET', url: '/api/v1/prelogin?account=alice' });
    const unknown = await app.inject({ method: 'GET', url: '/api/v1/prelogin?account=ghost' });

    expect(unknown.statusCode).toBe(known.statusCode);
    expect(Object.keys(unknown.json().kdf).sort()).toEqual(Object.keys(known.json().kdf).sort());
    // Plausible cost, so a decoy cannot be spotted by its parameters.
    expect(unknown.json().kdf.memoryKiB).toBe(known.json().kdf.memoryKiB);
  });

  it('returns stable decoy parameters across requests', async () => {
    const first = await app.inject({ method: 'GET', url: '/api/v1/prelogin?account=ghost' });
    const second = await app.inject({ method: 'GET', url: '/api/v1/prelogin?account=ghost' });
    expect(first.json().kdf.saltB64).toBe(second.json().kdf.saltB64);
  });

  it('gives different decoys to different names', async () => {
    const a = await app.inject({ method: 'GET', url: '/api/v1/prelogin?account=ghost-one' });
    const b = await app.inject({ method: 'GET', url: '/api/v1/prelogin?account=ghost-two' });
    expect(a.json().kdf.saltB64).not.toBe(b.json().kdf.saltB64);
  });

  it('rejects a malformed account identifier', async () => {
    const res = await app.inject({ method: 'GET', url: '/api/v1/prelogin?account=%20' });
    expect(res.statusCode).toBe(400);
  });
});

describe('vault read and write', () => {
  it('round-trips the envelope byte-for-byte', async () => {
    await register();
    const res = await app.inject({ method: 'GET', url: '/api/v1/vault', headers: { authorization: basic('alice', SECRET) } });
    expect(res.statusCode).toBe(200);
    expect(res.json().envelope).toEqual(envelope());
    expect(res.json().version).toBe(1);
  });

  it('accepts a write at the current version and increments it', async () => {
    await register();
    const res = await app.inject({
      method: 'PUT',
      url: '/api/v1/vault',
      headers: { authorization: basic('alice', SECRET) },
      payload: { envelope: envelope({ updatedAt: '2026-02-02T00:00:00.000Z' }), expectedVersion: 1 },
    });
    expect(res.statusCode).toBe(200);
    expect(res.json().version).toBe(2);
  });

  it('rejects a stale write and hands back the winning envelope', async () => {
    await register();
    await app.inject({
      method: 'PUT',
      url: '/api/v1/vault',
      headers: { authorization: basic('alice', SECRET) },
      payload: { envelope: envelope({ vaultId: '22222222-2222-4222-8222-222222222222' }), expectedVersion: 1 },
    });

    // Second device still believes it is on version 1.
    const conflict = await app.inject({
      method: 'PUT',
      url: '/api/v1/vault',
      headers: { authorization: basic('alice', SECRET) },
      payload: { envelope: envelope(), expectedVersion: 1 },
    });

    expect(conflict.statusCode).toBe(409);
    expect(conflict.json().version).toBe(2);
    // The 409 carries the current envelope so the retry is one round trip.
    expect(conflict.json().envelope.vaultId).toBe('22222222-2222-4222-8222-222222222222');
  });

  it('never lets the version go backwards', async () => {
    await register();
    const auth = { authorization: basic('alice', SECRET) };
    for (const expected of [1, 2, 3]) {
      const res = await app.inject({ method: 'PUT', url: '/api/v1/vault', headers: auth, payload: { envelope: envelope(), expectedVersion: expected } });
      expect(res.json().version).toBe(expected + 1);
    }
    // Replaying an old version cannot roll the stored vault back.
    const replay = await app.inject({ method: 'PUT', url: '/api/v1/vault', headers: auth, payload: { envelope: envelope(), expectedVersion: 1 } });
    expect(replay.statusCode).toBe(409);

    const current = await app.inject({ method: 'GET', url: '/api/v1/vault', headers: auth });
    expect(current.json().version).toBe(4);
  });

  it('rejects a malformed expectedVersion', async () => {
    await register();
    for (const bad of [0, -1, 1.5, '1', null, undefined]) {
      const res = await app.inject({
        method: 'PUT',
        url: '/api/v1/vault',
        headers: { authorization: basic('alice', SECRET) },
        payload: { envelope: envelope(), expectedVersion: bad },
      });
      expect(res.statusCode).toBe(400);
    }
  });

  it('requires auth to write', async () => {
    await register();
    const res = await app.inject({ method: 'PUT', url: '/api/v1/vault', payload: { envelope: envelope(), expectedVersion: 1 } });
    expect(res.statusCode).toBe(401);
  });
});

describe('rate limiting', () => {
  it('blocks after repeated auth failures', async () => {
    await register();
    const config = loadConfig({ databasePath: ':memory:', authAttemptsPerWindow: 3 });
    const limited = buildApp({ config, store });
    await limited.ready();

    for (let i = 0; i < 3; i++) {
      const res = await limited.inject({ method: 'GET', url: '/api/v1/vault', headers: { authorization: basic('alice', OTHER_SECRET) } });
      expect(res.statusCode).toBe(401);
    }
    // Budget spent: even the correct secret is refused until the window rolls.
    const blocked = await limited.inject({ method: 'GET', url: '/api/v1/vault', headers: { authorization: basic('alice', SECRET) } });
    expect(blocked.statusCode).toBe(429);

    const prelogin = await limited.inject({ method: 'GET', url: '/api/v1/prelogin?account=alice' });
    expect(prelogin.statusCode).toBe(429);

    await limited.close();
  });
});

describe('live console', () => {
  it('records API activity and serves a JSON snapshot', async () => {
    const { ConsoleLog } = await import('../src/console-log.ts');
    const consoleLog = new ConsoleLog();
    const logged = buildApp({
      config: loadConfig({ databasePath: ':memory:' }),
      store,
      consoleLog,
    });
    await logged.ready();

    await logged.inject({ method: 'GET', url: '/api/v1/health' });
    await logged.inject({
      method: 'POST',
      url: '/api/v1/account',
      payload: { accountId: 'alice', authSecret: SECRET, envelope: envelope() },
    });

    const snap = await logged.inject({ method: 'GET', url: '/api/v1/console?format=json' });
    expect(snap.statusCode).toBe(200);
    const body = snap.json() as { entries: Array<{ message: string; statusCode: number }> };
    expect(body.entries.some((e) => e.message.includes('ready'))).toBe(true);
    expect(body.entries.some((e) => e.message === 'Health check' && e.statusCode === 200)).toBe(true);
    expect(body.entries.some((e) => e.message === 'Account registered' && e.statusCode === 201)).toBe(true);

    await logged.close();
  });
});

describe('Store.list — the dashboard roster', () => {
  it('is empty for a fresh store', () => {
    expect(new Store(':memory:').list()).toEqual([]);
  });

  it('returns accounts oldest first, at version 1', async () => {
    await app.inject({
      method: 'POST',
      url: '/api/v1/account',
      payload: { accountId: 'alice', authSecret: SECRET, envelope: envelope() },
    });
    await app.inject({
      method: 'POST',
      url: '/api/v1/account',
      payload: { accountId: 'bob', authSecret: OTHER_SECRET, envelope: envelope() },
    });

    const rows = store.list();
    expect(rows.map((r) => r.accountId)).toEqual(['alice', 'bob']);
    expect(rows.every((r) => r.version === 1)).toBe(true);
    expect(Date.parse(rows[0]!.createdAt)).not.toBeNaN();
  });

  it('honours the limit', async () => {
    await app.inject({
      method: 'POST',
      url: '/api/v1/account',
      payload: { accountId: 'alice', authSecret: SECRET, envelope: envelope() },
    });
    await app.inject({
      method: 'POST',
      url: '/api/v1/account',
      payload: { accountId: 'bob', authSecret: OTHER_SECRET, envelope: envelope() },
    });
    expect(store.list(1)).toHaveLength(1);
  });

  it('tracks version and updatedAt across a write', async () => {
    await app.inject({
      method: 'POST',
      url: '/api/v1/account',
      payload: { accountId: 'alice', authSecret: SECRET, envelope: envelope() },
    });
    const before = store.list()[0]!;

    await app.inject({
      method: 'PUT',
      url: '/api/v1/vault',
      headers: { authorization: basic('alice', SECRET) },
      payload: { envelope: envelope({ vaultId: '22222222-2222-4222-8222-222222222222' }), expectedVersion: 1 },
    });

    const after = store.list()[0]!;
    expect(after.version).toBe(2);
    expect(Date.parse(after.updatedAt)).toBeGreaterThanOrEqual(Date.parse(before.updatedAt));
  });

  // The regression that motivated CAST(envelope AS BLOB): SQLite's length()
  // over TEXT counts characters, and JSON.stringify leaves non-ASCII unescaped,
  // so a plain length() reports short for any envelope containing one.
  it('reports envelope size in bytes, not characters', () => {
    const fresh = new Store(':memory:');
    const stored = JSON.stringify({ note: 'zażółć gęślą jaźń — 日本語' });
    fresh.create({
      accountId: 'multibyte',
      verifierSalt: 'c2FsdA==',
      verifierHash: 'aGFzaA==',
      envelope: stored,
    });

    const row = fresh.list()[0]!;
    expect(row.envelopeBytes).toBe(Buffer.byteLength(stored, 'utf8'));
    expect(row.envelopeBytes).toBeGreaterThan(stored.length);
    fresh.close();
  });

  it('does not return verifier material', () => {
    const fresh = new Store(':memory:');
    fresh.create({
      accountId: 'alice',
      verifierSalt: 'c2FsdA==',
      verifierHash: 'aGFzaA==',
      envelope: '{}',
    });
    expect(JSON.stringify(fresh.list())).not.toContain('aGFzaA==');
    fresh.close();
  });
});
