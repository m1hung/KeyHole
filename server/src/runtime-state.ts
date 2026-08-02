/**
 * Settings changed at runtime, persisted beside the database.
 *
 * Only one setting lives here so far: whether registration is open. It exists
 * because a dashboard toggle that silently reverts on the next restart is a
 * footgun on the setting DEPLOY.md calls the most important one on an
 * internet-facing host.
 *
 * ## Precedence
 *
 * A symmetric rule fails in one direction or the other. If the file always
 * wins, someone sets `KEYHOLE_ALLOW_REGISTRATION=false` in compose, restarts,
 * and gets an open server because of a file they forgot six months ago. If the
 * environment always wins, closing registration from the dashboard silently
 * undoes itself on restart.
 *
 * So the rule is asymmetric, and only about what a *restart* infers:
 *
 *     effective = envAllow && persistedAllow
 *
 * | env    | persisted | boot result                                    |
 * |--------|-----------|------------------------------------------------|
 * | true   | absent    | open — no change for anyone not using the toggle |
 * | true   | false     | closed — a dashboard close survives a restart   |
 * | false  | anything  | closed — a file cannot reopen what compose shut |
 *
 * While the process runs the toggle is authoritative in both directions,
 * including reopening a server deployed closed: the caller holds a 0600
 * loopback token, which is strictly more privilege than editing compose.
 */

import { readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';

export interface RuntimeState {
  version: 1;
  allowRegistration: boolean;
  updatedAt: string;
}

/**
 * Where the file lives, or undefined when there is nowhere sensible to put it.
 * Mirrors `createControlToken`: an in-memory database means tests, and tests
 * must not touch the filesystem.
 */
export function runtimeStatePath(databasePath: string): string | undefined {
  if (databasePath === ':memory:') return undefined;
  return join(dirname(databasePath), 'runtime.json');
}

/**
 * Read persisted state. Returns undefined when absent, unreadable, or
 * malformed.
 *
 * A corrupt file must NOT be treated as "registration closed". With the control
 * plane off there would then be no in-band way to reopen the server — the
 * operator would have to find and delete a file nobody told them about. It is
 * loud on stderr instead, which journald and `docker compose logs` both pick up.
 */
export function readRuntimeState(databasePath: string): RuntimeState | undefined {
  const path = runtimeStatePath(databasePath);
  if (!path) return undefined;

  let raw: string;
  try {
    raw = readFileSync(path, 'utf8');
  } catch {
    return undefined; // Absent is the normal case, not an error.
  }

  try {
    const parsed = JSON.parse(raw) as Partial<RuntimeState>;
    if (typeof parsed?.allowRegistration !== 'boolean') {
      throw new Error('allowRegistration is not a boolean');
    }
    return {
      version: 1,
      allowRegistration: parsed.allowRegistration,
      updatedAt: typeof parsed.updatedAt === 'string' ? parsed.updatedAt : new Date(0).toISOString(),
    };
  } catch (err) {
    console.warn(
      `[keyhole] ignoring unreadable ${path}: ${
        err instanceof Error ? err.message : String(err)
      }. Registration falls back to KEYHOLE_ALLOW_REGISTRATION.`,
    );
    return undefined;
  }
}

/**
 * Persist the toggle. Returns false rather than throwing when it cannot be
 * saved — a read-only volume should still let the operator close registration
 * for the current process, as long as the UI admits it will not survive.
 *
 * Mode 0644, not 0600: this holds no secret, and a restrictive mode on a
 * non-secret invites the next reader to assume it is one. Contrast
 * `control-token`, which is 0600 because it genuinely is one.
 */
export function writeRuntimeState(databasePath: string, allowRegistration: boolean): boolean {
  const path = runtimeStatePath(databasePath);
  if (!path) return false;

  const state: RuntimeState = {
    version: 1,
    allowRegistration,
    updatedAt: new Date().toISOString(),
  };

  try {
    // Write-then-rename: a torn write here would be read back as corruption on
    // the next boot, and rename is atomic within a filesystem.
    const tmp = `${path}.tmp`;
    writeFileSync(tmp, `${JSON.stringify(state, null, 2)}\n`, { mode: 0o644 });
    renameSync(tmp, path);
    return true;
  } catch (err) {
    console.warn(
      `[keyhole] could not persist ${path}: ${err instanceof Error ? err.message : String(err)}`,
    );
    return false;
  }
}

/**
 * The boot-time rule. A pure function precisely so the truth table above can be
 * tested directly rather than inferred from process behaviour.
 */
export function effectiveAllowRegistration(envAllow: boolean, persistedAllow?: boolean): boolean {
  if (persistedAllow === undefined) return envAllow;
  return envAllow && persistedAllow;
}
