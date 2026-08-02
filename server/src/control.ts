/**
 * Control plane — the things that act on the server rather than on a vault.
 *
 * Stop, restart, open or close registration, and download a snapshot of the
 * database. Deliberately not a general admin API: the roster the dashboard
 * shows is *not* here, because it is a read of derived facts rather than a
 * capability, and putting it here would mean nobody could see it without first
 * enabling a kill switch (KEYHOLE_CONTROL defaults to false).
 *
 * The line is what each route hands the caller:
 *
 *  - **Mutations** belong here. Registration is the setting DEPLOY.md calls the
 *    most important one on an internet-facing host.
 *  - **Bulk exports of the datastore** belong here too, even though a backup is
 *    a read. A file containing every verifier hash and every stored envelope is
 *    a capability, not a disclosure.
 *  - **Derived facts** — account ids, uptime, database size — go on the status
 *    page behind its loopback check, not here.
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
 *
 * No new environment variable gates any of this — `KEYHOLE_CONTROL` turns the
 * whole listener on or off, and always did.
 */

import Fastify, { type FastifyInstance, type FastifyRequest } from 'fastify';
import { createHash, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { chmodSync, mkdirSync, readFileSync, rmSync, statfsSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import type { ServerConfig } from './config.ts';
import type { Store } from './db.ts';

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
  /**
   * Flip registration. Returns the value now in force and whether it was
   * persisted — a read-only volume still permits the change for this process,
   * and the caller has to be able to say so.
   *
   * Injected rather than done here so this module keeps knowing nothing about
   * the filesystem, the same way it delegates process control.
   */
  setRegistration: (allow: boolean) => { allowRegistration: boolean; persisted: boolean };
  /** The same Store the API is using — a second one would be a second connection. */
  store: Store;
  logger?: boolean;
  /** Injected in tests so assertions do not depend on a real clock. */
  now?: () => number;
}

export function buildControlApp({
  config,
  token,
  onStop,
  onRestart,
  setRegistration,
  store,
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

  /**
   * A consistent snapshot of the vault database, as a download.
   *
   * On the control plane despite being a read: the file contains every
   * account's verifier hash and every stored envelope. That is a capability,
   * not a disclosure, and it belongs behind the same token as stop and restart.
   */
  app.get('/control/v1/backup', async (_request, reply) => {
    const dest = join(tmpdir(), `keyhole-backup-${randomUUID()}.sqlite`);

    // A truncated backup is worse than a failed one, because it looks like a
    // backup. Refuse up front rather than discovering it mid-write.
    if (config.databasePath !== ':memory:') {
      try {
        const need = statSync(config.databasePath).size * 1.2;
        const fs = statfsSync(tmpdir());
        if (fs.bavail * fs.bsize < need) {
          return reply.code(507).send({ error: 'Not enough free space in the temp directory.' });
        }
      } catch {
        // If we cannot measure, proceed — the finally below still cleans up.
      }
    }

    try {
      store.backupTo(dest);
      // Read into a Buffer rather than streaming: a stream would move cleanup
      // into close/error handlers on a path where getting it wrong leaves
      // copies of the vault database in the temp directory. The cost is holding
      // the file in memory, which for a personal sync server is megabytes.
      const bytes = readFileSync(dest);
      const stamp = new Date().toISOString().replace(/[:.]/g, '-');
      return reply
        .type('application/vnd.sqlite3')
        .header('Content-Disposition', `attachment; filename="keyhole-backup-${stamp}.sqlite"`)
        .send(bytes);
    } finally {
      rmSync(dest, { force: true });
    }
  });

  app.post('/control/v1/registration', async (request, reply) => {
    const body = request.body as { allow?: unknown } | undefined;
    // Strictly a boolean. `{"allow": "false"}` is the shape this route would
    // most plausibly ship broken: a truthy string would open registration while
    // the caller believed it was closing it.
    if (typeof body?.allow !== 'boolean') {
      return reply.code(400).send({ error: 'allow must be a boolean.' });
    }

    const result = setRegistration(body.allow);
    return reply.send({ ok: true, ...result });
  });

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
