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
    ...overrides,
  };
}
