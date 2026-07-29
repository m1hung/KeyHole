import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest';
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

/** The handlers fire on a short timer so the reply flushes first. */
const settle = () => new Promise((r) => setTimeout(r, 120));

beforeEach(() => {
  onStop = vi.fn<() => void>();
  onRestart = vi.fn<() => void>();
  app = buildControlApp({ config, token: TOKEN, onStop, onRestart });
});

afterEach(async () => {
  await app.close();
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
    expect(res.body).toContain('Server controls');
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
    expect(res.body).not.toContain('Server controls');
  });

  it('withholds the token from a tailscale-identified viewer', async () => {
    const res = await api.inject({
      method: 'GET',
      url: '/',
      headers: { 'tailscale-user-login': 'someone@example.com' },
    });
    expect(res.body).not.toContain(TOKEN);
  });

  it('renders no controls at all when the control plane is off', async () => {
    const off = buildApp({ config, store: new Store(':memory:') });
    const res = await off.inject({ method: 'GET', url: '/' });
    expect(res.body).not.toContain('Server controls');
    await off.close();
  });
});
