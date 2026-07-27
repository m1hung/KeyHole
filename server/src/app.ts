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
}

export function buildApp({ config, store, logger = false }: BuildOptions): FastifyInstance {
  const db = store ?? new Store(config.databasePath);
  const limiter = new AttemptLimiter(config.authAttemptsPerWindow, config.authWindowMs);
  const pepper = db.pepper();

  const app = Fastify({ logger, bodyLimit: config.maxEnvelopeBytes });

  const sweeper = setInterval(() => limiter.sweep(), config.authWindowMs).unref();
  app.addHook('onClose', async () => {
    clearInterval(sweeper);
    if (!store) db.close();
  });

  /** Resolve credentials, or reply and return null. */
  function authenticate(request: FastifyRequest): AccountRow | null {
    const ip = request.ip;
    if (limiter.isBlocked(ip)) return null;

    const credentials: Credentials | null = parseAuthHeader(request.headers.authorization);
    if (!credentials) {
      limiter.recordFailure(ip);
      return null;
    }

    const account = db.get(credentials.accountId);
    if (!account) {
      // Still hash, so a missing account is not faster than a wrong secret.
      hashVerifier(credentials.secretB64, newVerifierSalt());
      limiter.recordFailure(ip);
      return null;
    }

    const candidate = hashVerifier(credentials.secretB64, account.verifierSalt);
    if (!verifierMatches(candidate, account.verifierHash)) {
      limiter.recordFailure(ip);
      return null;
    }

    limiter.recordSuccess(ip);
    return account;
  }

  // -------------------------------------------------------------------------

  app.get('/api/v1/health', async () => ({ ok: true, service: 'keyhole-sync', apiVersion: 1 }));

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
    const account = authenticate(request);
    if (!account) return unauthorized(reply);

    return reply.send({
      envelope: JSON.parse(account.envelope) as unknown,
      version: account.version,
      updatedAt: account.updatedAt,
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
    const account = authenticate(request);
    if (!account) return unauthorized(reply);

    const body = (request.body ?? {}) as Record<string, unknown>;
    const envelope = body['envelope'];
    const expectedVersion = body['expectedVersion'];

    if (!looksLikeEnvelope(envelope)) {
      return reply.code(400).send({ error: 'envelope is not a Keyhole vault file.' });
    }
    if (typeof expectedVersion !== 'number' || !Number.isInteger(expectedVersion) || expectedVersion < 1) {
      return reply.code(400).send({ error: 'expectedVersion must be a positive integer.' });
    }

    const updated = db.replaceEnvelope(account.accountId, JSON.stringify(envelope), expectedVersion);
    if (!updated) {
      const current = db.get(account.accountId);
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
