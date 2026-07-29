/** Deployment configuration. Everything has a working default except the data path. */

export interface ServerConfig {
  host: string;
  port: number;
  /** SQLite file path, or ':memory:' for tests. */
  databasePath: string;
  /**
   * Largest envelope accepted, in bytes. The extension refuses to store above
   * ~9 MB, so this is generous headroom rather than a real ceiling.
   */
  maxEnvelopeBytes: number;
  /** Failed auth attempts per IP before a cool-off. */
  authAttemptsPerWindow: number;
  authWindowMs: number;
  /** Allow new accounts to be created. Turn off once your own are set up. */
  allowRegistration: boolean;
  /**
   * Expose the stop/restart control plane on a second listener.
   *
   * Off by default, and deliberately so. The API surface above is a blob store
   * that cannot act on the machine it runs on; the control plane can. Turning
   * that on should be a decision someone made, not something inherited from a
   * default — the same reasoning that keeps the bind address explicit.
   */
  control: boolean;
  /**
   * Port for the control listener. Its *host* is not configurable: it is
   * always loopback. A control plane reachable from a network is a remote
   * shutdown switch for everyone's vault sync, and no environment variable
   * should be able to arrange that by accident.
   */
  controlPort: number;
}

function intFromEnv(name: string, fallback: number): number {
  const raw = process.env[name];
  if (raw === undefined || raw.trim() === '') return fallback;
  const parsed = Number(raw);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    throw new Error(`${name} must be a positive number, got ${JSON.stringify(raw)}`);
  }
  return Math.floor(parsed);
}

export function loadConfig(overrides: Partial<ServerConfig> = {}): ServerConfig {
  return {
    host: process.env['KEYHOLE_HOST'] ?? '0.0.0.0',
    port: intFromEnv('KEYHOLE_PORT', 8787),
    databasePath: process.env['KEYHOLE_DB'] ?? './data/keyhole.sqlite',
    maxEnvelopeBytes: intFromEnv('KEYHOLE_MAX_ENVELOPE_BYTES', 16 * 1024 * 1024),
    authAttemptsPerWindow: intFromEnv('KEYHOLE_AUTH_ATTEMPTS', 10),
    authWindowMs: intFromEnv('KEYHOLE_AUTH_WINDOW_MS', 60_000),
    // Default open so a fresh deploy is usable; the docs tell you to close it.
    allowRegistration: (process.env['KEYHOLE_ALLOW_REGISTRATION'] ?? 'true') !== 'false',
    // Opt-in, unlike everything else here: see ServerConfig.control.
    control: process.env['KEYHOLE_CONTROL'] === 'true',
    controlPort: intFromEnv('KEYHOLE_CONTROL_PORT', 8788),
    ...overrides,
  };
}
