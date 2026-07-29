/**
 * Control plane — stop and restart, and nothing else.
 *
 * This is a second listener, separate from the API, and the separation is the
 * point. The API is a blob store: the worst a caller can do is store or read
 * ciphertext it already had credentials for. This one acts on the machine, so
 * it gets three defences the API does not need:
 *
 *  1. **Loopback only, not configurable.** `tailscale serve` (or any reverse
 *     proxy) fronts the API port. It does not front this one, so exposing the
 *     API to a tailnet does not carry the control plane along with it.
 *  2. **A bearer token**, not the vault credential. Loopback is not a trust
 *     boundary on a multi-user machine, and control over the server is a
 *     different power from reading a vault — it should not be implied by it.
 *  3. **Almost no CORS.** Only the dashboard's own local origin is allowed, so
 *     a page on any other site cannot drive these routes through a browser
 *     that happens to be running on this machine.
 *
 * There is deliberately no `start`: if the process is not running, nothing is
 * here to answer. Starting is the launcher's job, or systemd's.
 */

import Fastify, { type FastifyInstance, type FastifyRequest } from 'fastify';
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { chmodSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import type { ServerConfig } from './config.ts';

/**
 * Exit code meaning "bring me back". The unit file maps it with
 * RestartForceExitStatus so systemd restarts on it, and SuccessExitStatus so
 * the restart is not also recorded as a crash. A plain stop exits 0, which
 * leaves the service down — the distinction is the whole reason for a code.
 */
export const RESTART_EXIT_CODE = 75;

/**
 * Generate the control token and, when there is a real data directory, leave a
 * copy for anything else that needs it. 0600: on a shared machine the file is
 * the only thing standing between another local account and a shutdown switch.
 *
 * Regenerated per boot, so a token read once does not stay valid across a
 * restart.
 */
export function createControlToken(databasePath: string): { token: string; path?: string } {
  const token = randomBytes(32).toString('base64url');
  if (databasePath === ':memory:') return { token };

  const dir = dirname(databasePath);
  const path = join(dir, 'control-token');
  mkdirSync(dir, { recursive: true });
  // Create with the restrictive mode rather than fixing it afterwards; a
  // world-readable window, however brief, defeats the point.
  writeFileSync(path, `${token}\n`, { mode: 0o600 });
  chmodSync(path, 0o600);
  return { token, path };
}

/** Constant-time compare over digests, so differing lengths cannot leak. */
function tokenMatches(presented: string, expected: string): boolean {
  const a = createHash('sha256').update(presented).digest();
  const b = createHash('sha256').update(expected).digest();
  return timingSafeEqual(a, b);
}

function bearer(request: FastifyRequest): string | undefined {
  const header = request.headers.authorization;
  if (typeof header !== 'string') return undefined;
  const match = /^Bearer\s+(.+)$/i.exec(header.trim());
  return match?.[1];
}

export interface ControlOptions {
  config: ServerConfig;
  token: string;
  /** Called after the response has flushed. */
  onStop: () => void;
  onRestart: () => void;
  logger?: boolean;
  /** Injected in tests so assertions do not depend on a real clock. */
  now?: () => number;
}

export function buildControlApp({
  config,
  token,
  onStop,
  onRestart,
  logger = false,
  now = () => Date.now(),
}: ControlOptions): FastifyInstance {
  const app = Fastify({ logger, bodyLimit: 4096 });
  const startedAt = now();

  // The dashboard is served from the API port, so its fetch to this port is
  // cross-origin and would be blocked without this. Only those exact origins
  // are allowed: an attacker's page cannot forge its own Origin, and a
  // dashboard loaded through a proxy carries the proxy's origin, which is not
  // on this list — nor could its fetch reach here, since 127.0.0.1 on a remote
  // browser is that machine's own loopback.
  const allowedOrigins = new Set([
    `http://127.0.0.1:${config.port}`,
    `http://localhost:${config.port}`,
    `http://[::1]:${config.port}`,
  ]);

  app.addHook('onRequest', async (request, reply) => {
    const origin = request.headers.origin;
    if (typeof origin === 'string' && allowedOrigins.has(origin)) {
      reply.header('Access-Control-Allow-Origin', origin);
      reply.header('Vary', 'Origin');
      reply.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
      reply.header('Access-Control-Allow-Headers', 'Authorization, Content-Type');
    }
    // Any other Origin gets no CORS headers at all, so the browser discards
    // the response even if the request itself went through.

    if (request.method === 'OPTIONS') {
      return reply.code(204).send();
    }

    const presented = bearer(request);
    if (presented === undefined || !tokenMatches(presented, token)) {
      return reply.code(401).send({ error: 'unauthorized' });
    }
  });

  app.get('/control/v1/status', async () => ({
    ok: true,
    pid: process.pid,
    uptimeSeconds: Math.round((now() - startedAt) / 1000),
    apiPort: config.port,
    controlPort: config.controlPort,
    allowRegistration: config.allowRegistration,
    databasePath: config.databasePath,
  }));

  app.post('/control/v1/stop', async (_request, reply) => {
    // Reply first: the caller should learn it succeeded, which it cannot do if
    // the process is already gone.
    void reply.send({ ok: true, action: 'stop' });
    await reply;
    setTimeout(onStop, 50).unref();
  });

  app.post('/control/v1/restart', async (_request, reply) => {
    void reply.send({ ok: true, action: 'restart' });
    await reply;
    setTimeout(onRestart, 50).unref();
  });

  return app;
}
