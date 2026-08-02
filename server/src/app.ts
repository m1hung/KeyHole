/**
 * HTTP surface.
 *
 * The whole protocol is four routes. The server is a versioned blob store with
 * compare-and-swap; all of the interesting logic — merging, conflict
 * resolution, encryption — lives on the client, because the client is the only
 * party that can read anything.
 *
 * Exported as a factory so tests can drive it via `app.inject()` without
 * binding a port.
 */

import Fastify, { type FastifyInstance, type FastifyRequest } from 'fastify';
import { statSync } from 'node:fs';
import {
  AttemptLimiter,
  decoyKdfParams,
  hashVerifier,
  newVerifierSalt,
  normaliseAccountId,
  parseAuthHeader,
  verifierMatches,
  type Credentials,
} from './auth.ts';
import { Store, type AccountRow } from './db.ts';
import type { ServerConfig } from './config.ts';
import { renderStatusPage } from './status-page.ts';
import {
  ConsoleLog,
  levelForStatus,
  shouldLogPath,
  summariseRequest,
} from './console-log.ts';

/** Minimal shape check. The server must not depend on understanding the payload. */
function looksLikeEnvelope(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const v = value as Record<string, unknown>;
  return (
    v['format'] === 'keyhole.vault' &&
    typeof v['formatVersion'] === 'number' &&
    typeof v['vaultId'] === 'string' &&
    typeof v['kdf'] === 'object' &&
    v['kdf'] !== null &&
    typeof v['wrappedKey'] === 'object' &&
    typeof v['payload'] === 'object'
  );
}

export interface BuildOptions {
  config: ServerConfig;
  store?: Store;
  logger?: boolean;
  /** Shared console buffer (tests can pass one to assert against). */
  consoleLog?: ConsoleLog;
  /**
   * Control-plane token, when one is running. Embedded in the dashboard for
   * genuinely local viewers only — see `isDirectLoopback`. Undefined leaves the
   * page exactly as it was.
   */
  controlToken?: string | undefined;
}

/**
 * Did this request come from this machine, without passing through a proxy?
 *
 * `request.ip` alone cannot answer that: `tailscale serve` connects over
 * loopback, so every proxied request also looks like 127.0.0.1. What separates
 * them is the forwarding headers a proxy adds. Anything carrying one is treated
 * as remote, and a header we do not know about would only ever cost a local
 * user their buttons — the failure is in the safe direction.
 */
/**
 * Size of the vault database, for the dashboard. Absent rather than wrong when
 * it cannot be read — an in-memory store has no file, and a stat failure is not
 * worth failing a page render over.
 */
function databaseBytes(path: string): number | undefined {
  if (path === ':memory:') return undefined;
  try {
    return statSync(path).size;
  } catch {
    return undefined;
  }
}

function isDirectLoopback(request: FastifyRequest): boolean {
  const forwardingHeaders = [
    'x-forwarded-for',
    'x-forwarded-host',
    'x-forwarded-proto',
    'forwarded',
    'tailscale-user-login',
    'tailscale-user-name',
  ];
  if (forwardingHeaders.some((h) => request.headers[h] !== undefined)) return false;

  const ip = request.ip;
  return ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1';
}

export function buildApp({
  config,
  store,
  logger = false,
  consoleLog,
  controlToken,
}: BuildOptions): FastifyInstance {
  const db = store ?? new Store(config.databasePath);
  const limiter = new AttemptLimiter(config.authAttemptsPerWindow, config.authWindowMs);
  const pepper = db.pepper();
  const liveLog = consoleLog ?? new ConsoleLog();

  const app = Fastify({ logger, bodyLimit: config.maxEnvelopeBytes });

  /**
   * CORS for the web app (and any other browser client on a different origin /
   * port). Without these headers the browser surfaces a useless "Failed to
   * fetch" even when the server is healthy.
   *
   * We reflect the request Origin rather than pinning a list: this host is
   * self-hosted, and Vite alone may land on 5173, 5174, …
   */
  app.addHook('onRequest', async (request, reply) => {
    const origin = request.headers.origin;
    if (typeof origin === 'string' && origin.length > 0) {
      reply.header('Access-Control-Allow-Origin', origin);
      reply.header('Vary', 'Origin');
    } else {
      reply.header('Access-Control-Allow-Origin', '*');
    }
    reply.header('Access-Control-Allow-Methods', 'GET, HEAD, POST, PUT, OPTIONS');
    reply.header('Access-Control-Allow-Headers', 'Authorization, Content-Type');
    reply.header('Access-Control-Max-Age', '86400');

    if (request.method === 'OPTIONS') {
      return reply.code(204).send();
    }
  });

  const sweeper = setInterval(() => limiter.sweep(), config.authWindowMs).unref();
  app.addHook('onClose', async () => {
    clearInterval(sweeper);
    if (!store) db.close();
  });

  app.addHook('onResponse', (request, reply, done) => {
    try {
      if (request.method === 'OPTIONS') {
        done();
        return;
      }
      const path = request.url;
      if (!shouldLogPath(path)) {
        done();
        return;
      }
      const statusCode = reply.statusCode;
      liveLog.push({
        level: levelForStatus(statusCode),
        method: request.method,
        path,
        statusCode,
        ms: Math.round(reply.elapsedTime * 10) / 10,
        ip: request.ip,
        message: summariseRequest(request.method, path, statusCode),
      });
    } catch {
      // Logging must never break a response.
    }
    done();
  });

  app.addHook('onReady', async () => {
    liveLog.push({
      level: 'info',
      method: '—',
      path: '/',
      statusCode: 200,
      ms: 0,
      ip: 'local',
      message: `Keyhole sync ready · registration ${config.allowRegistration ? 'open' : 'closed'}`,
    });
  });

  /** Resolve credentials. Distinguishes rate-limit from bad auth so clients
   *  see 429 instead of a misleading Unauthorized. */
  function authenticate(
    request: FastifyRequest,
  ): { ok: true; account: AccountRow } | { ok: false; reason: 'rate_limited' | 'unauthorized' } {
    const ip = request.ip;
    if (limiter.isBlocked(ip)) return { ok: false, reason: 'rate_limited' };

    const credentials: Credentials | null = parseAuthHeader(request.headers.authorization);
    if (!credentials) {
      limiter.recordFailure(ip);
      return { ok: false, reason: 'unauthorized' };
    }

    const account = db.get(credentials.accountId);
    if (!account) {
      // Still hash, so a missing account is not faster than a wrong secret.
      hashVerifier(credentials.secretB64, newVerifierSalt());
      limiter.recordFailure(ip);
      return { ok: false, reason: 'unauthorized' };
    }

    const candidate = hashVerifier(credentials.secretB64, account.verifierSalt);
    if (!verifierMatches(candidate, account.verifierHash)) {
      limiter.recordFailure(ip);
      return { ok: false, reason: 'unauthorized' };
    }

    limiter.recordSuccess(ip);
    return { ok: true, account };
  }

  // -------------------------------------------------------------------------

  /** Browser-friendly landing page — the API itself has no vault UI. */
  app.get('/', async (request, reply) => {
    const host = request.headers.host;
    // The token is withheld from anything that reached us through a proxy, so
    // a tailnet viewer gets a page with no controls and no credential to drive
    // them with. Their browser could not reach the control port regardless —
    // 127.0.0.1 there is their own machine — but the token should not travel.
    const local = isDirectLoopback(request);
    const html = renderStatusPage({
      port: config.port,
      accounts: db.accountCount(),
      allowRegistration: config.allowRegistration,
      // Show the address this request arrived on, so a page opened from another
      // device on the LAN does not tell the reader to use 127.0.0.1.
      origin: host ? `${request.protocol}://${host}` : undefined,
      control:
        controlToken !== undefined && local
          ? {
              token: controlToken,
              port: config.controlPort,
              allowRegistration: config.allowRegistration,
            }
          : undefined,
      uptimeSeconds: Math.floor(process.uptime()),
      machine: local
        ? {
            pid: process.pid,
            databasePath: config.databasePath,
            databaseBytes: databaseBytes(config.databasePath),
          }
        : undefined,
      // Same gate as `machine`, deliberately the same ternary: account ids are
      // the one piece of user-identifying data this server holds, and there
      // should be exactly one decision about who sees them.
      roster: local ? db.list(50) : undefined,
    });
    return reply.type('text/html; charset=utf-8').send(html);
  });

  app.get('/api/v1/health', async () => ({ ok: true, service: 'keyhole-sync', apiVersion: 1 }));

  /**
   * Live request console for the status page.
   *
   * SSE stream of recent activity (plus a JSON snapshot via `?format=json`).
   * Entries never include credentials or envelope bodies.
   */
  app.get('/api/v1/console', async (request, reply) => {
    const query = request.query as Record<string, unknown>;
    if (query['format'] === 'json') {
      return { entries: liveLog.snapshot() };
    }

    reply.hijack();
    reply.raw.writeHead(200, {
      'Content-Type': 'text/event-stream; charset=utf-8',
      'Cache-Control': 'no-cache, no-transform',
      Connection: 'keep-alive',
      'X-Accel-Buffering': 'no',
    });
    reply.raw.write(': connected\n\n');

    for (const entry of liveLog.snapshot()) {
      reply.raw.write(`data: ${JSON.stringify(entry)}\n\n`);
    }

    const unsubscribe = liveLog.subscribe((entry) => {
      reply.raw.write(`data: ${JSON.stringify(entry)}\n\n`);
    });

    const heartbeat = setInterval(() => {
      reply.raw.write(': ping\n\n');
    }, 15_000);
    heartbeat.unref();

    const cleanup = () => {
      clearInterval(heartbeat);
      unsubscribe();
    };
    request.raw.on('close', cleanup);
    request.raw.on('error', cleanup);
    return;
  });

  /**
   * KDF parameters for an account, so a fresh device can derive its auth
   * secret before it has any local state.
   *
   * Unauthenticated by necessity, and answers for unknown accounts too — see
   * `decoyKdfParams` for why. The CLIENT must reject parameters below its own
   * cost floor; a hostile server would otherwise serve cheap ones and harvest
   * a secret it could brute-force.
   */
  app.get('/api/v1/prelogin', async (request, reply) => {
    const query = request.query as Record<string, unknown>;
    const accountId = normaliseAccountId(query['account']);
    if (!accountId) return reply.code(400).send({ error: 'Invalid account identifier.' });

    if (limiter.isBlocked(request.ip)) {
      return reply.code(429).send({ error: 'Too many attempts. Try again shortly.' });
    }

    const account = db.get(accountId);
    if (!account) {
      limiter.recordFailure(request.ip);
      return reply.send({ kdf: decoyKdfParams(accountId, pepper) });
    }

    const envelope = JSON.parse(account.envelope) as Record<string, unknown>;
    return reply.send({ kdf: envelope['kdf'] });
  });

  /** Create an account by uploading its first envelope. */
  app.post('/api/v1/account', async (request, reply) => {
    if (!config.allowRegistration) {
      return reply.code(403).send({ error: 'Registration is disabled on this server.' });
    }

    const body = (request.body ?? {}) as Record<string, unknown>;
    const accountId = normaliseAccountId(body['accountId']);
    const authSecret = body['authSecret'];
    const envelope = body['envelope'];

    if (!accountId) {
      return reply.code(400).send({ error: 'accountId must be 3-64 chars of a-z, 0-9, dot, dash, underscore or @.' });
    }
    if (typeof authSecret !== 'string' || authSecret.length === 0 || authSecret.length > 512) {
      return reply.code(400).send({ error: 'authSecret missing or malformed.' });
    }
    if (!looksLikeEnvelope(envelope)) {
      return reply.code(400).send({ error: 'envelope is not a Keyhole vault file.' });
    }
    if (db.get(accountId)) {
      return reply.code(409).send({ error: 'That account already exists.' });
    }

    const verifierSalt = newVerifierSalt();
    const created = db.create({
      accountId,
      verifierSalt,
      verifierHash: hashVerifier(authSecret, verifierSalt),
      envelope: JSON.stringify(envelope),
    });

    return reply.code(201).send({ accountId, version: created.version, updatedAt: created.updatedAt });
  });

  app.get('/api/v1/vault', async (request, reply) => {
    const auth = authenticate(request);
    if (!auth.ok) {
      return auth.reason === 'rate_limited' ? tooMany(reply) : unauthorized(reply);
    }

    return reply.send({
      envelope: JSON.parse(auth.account.envelope) as unknown,
      version: auth.account.version,
      updatedAt: auth.account.updatedAt,
    });
  });

  /**
   * Replace the envelope, if the caller is working from the current version.
   *
   * A mismatch is not an error the user needs to see: it means another device
   * wrote first, so the client pulls, merges and retries. The conflicting
   * envelope is returned with the 409 so that retry costs one round trip
   * instead of two.
   */
  app.put('/api/v1/vault', async (request, reply) => {
    const auth = authenticate(request);
    if (!auth.ok) {
      return auth.reason === 'rate_limited' ? tooMany(reply) : unauthorized(reply);
    }

    const body = (request.body ?? {}) as Record<string, unknown>;
    const envelope = body['envelope'];
    const expectedVersion = body['expectedVersion'];
    const nextAuthSecret = body['authSecret'];

    if (!looksLikeEnvelope(envelope)) {
      return reply.code(400).send({ error: 'envelope is not a Keyhole vault file.' });
    }
    if (typeof expectedVersion !== 'number' || !Number.isInteger(expectedVersion) || expectedVersion < 1) {
      return reply.code(400).send({ error: 'expectedVersion must be a positive integer.' });
    }

    let verifier: { salt: string; hash: string } | undefined;
    if (nextAuthSecret !== undefined) {
      if (typeof nextAuthSecret !== 'string' || nextAuthSecret.length === 0 || nextAuthSecret.length > 512) {
        return reply.code(400).send({ error: 'authSecret missing or malformed.' });
      }
      const salt = newVerifierSalt();
      verifier = { salt, hash: hashVerifier(nextAuthSecret, salt) };
    }

    const updated = db.replaceEnvelope(
      auth.account.accountId,
      JSON.stringify(envelope),
      expectedVersion,
      verifier,
    );
    if (!updated) {
      const current = db.get(auth.account.accountId);
      return reply.code(409).send({
        error: 'Version conflict — another device wrote first. Pull, merge and retry.',
        version: current?.version,
        envelope: current ? (JSON.parse(current.envelope) as unknown) : undefined,
        updatedAt: current?.updatedAt,
      });
    }

    return reply.send({ version: updated.version, updatedAt: updated.updatedAt });
  });

  return app;
}

function unauthorized(reply: { code: (n: number) => { send: (b: unknown) => unknown } }): unknown {
  // One message for every failure mode: unknown account, wrong secret, and
  // malformed header are indistinguishable from outside.
  return reply.code(401).send({ error: 'Unauthorized.' });
}

function tooMany(reply: { code: (n: number) => { send: (b: unknown) => unknown } }): unknown {
  return reply.code(429).send({ error: 'Too many attempts. Try again shortly.' });
}
