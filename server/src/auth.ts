/**
 * Authentication.
 *
 * A device proves itself with the HKDF-derived sync auth secret from
 * `@keyhole/core` — 256 bits of uniformly random material, never the master
 * password itself, and useless for decrypting anything.
 */

import { createHmac, createHash, randomBytes, timingSafeEqual } from 'node:crypto';

/** Accepted account identifiers. Deliberately narrow: it ends up in a URL. */
const ACCOUNT_ID = /^[a-z0-9][a-z0-9._@-]{2,63}$/;

export function normaliseAccountId(raw: unknown): string | null {
  if (typeof raw !== 'string') return null;
  const id = raw.trim().toLowerCase();
  return ACCOUNT_ID.test(id) ? id : null;
}

/**
 * Hash a verifier for storage.
 *
 * A single salted SHA-256, NOT a memory-hard KDF — and that is deliberate.
 * Slow password hashes exist to blunt dictionary attacks on low-entropy human
 * input. This input is a 256-bit HKDF output with no structure to guess, so
 * iterating would cost every legitimate request real time while removing no
 * attack. The expensive Argon2id step already happened on the client, which is
 * exactly where it belongs.
 */
export function hashVerifier(secretB64: string, saltB64: string): string {
  return createHash('sha256')
    .update(Buffer.from(saltB64, 'base64'))
    .update(Buffer.from(secretB64, 'base64'))
    .digest('base64');
}

export function newVerifierSalt(): string {
  return randomBytes(16).toString('base64');
}

/** Constant-time verifier comparison. */
export function verifierMatches(candidate: string, stored: string): boolean {
  const a = Buffer.from(candidate, 'base64');
  const b = Buffer.from(stored, 'base64');
  // timingSafeEqual throws on length mismatch, which would itself leak.
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

// ---------------------------------------------------------------------------
// Credentials
// ---------------------------------------------------------------------------

export interface Credentials {
  accountId: string;
  secretB64: string;
}

/** Parse `Authorization: Basic base64(accountId:secret)`. */
export function parseAuthHeader(header: unknown): Credentials | null {
  if (typeof header !== 'string') return null;
  const [scheme, encoded] = header.split(' ');
  if (scheme?.toLowerCase() !== 'basic' || !encoded) return null;

  let decoded: string;
  try {
    decoded = Buffer.from(encoded, 'base64').toString('utf8');
  } catch {
    return null;
  }

  const separator = decoded.indexOf(':');
  if (separator === -1) return null;

  const accountId = normaliseAccountId(decoded.slice(0, separator));
  const secretB64 = decoded.slice(separator + 1);
  if (!accountId || secretB64.length === 0 || secretB64.length > 512) return null;
  return { accountId, secretB64 };
}

// ---------------------------------------------------------------------------
// Account-enumeration resistance
// ---------------------------------------------------------------------------

/**
 * Plausible KDF parameters for an account that does not exist.
 *
 * Prelogin has to be unauthenticated — you need the salt before you can derive
 * the secret that authenticates you. Answering 404 would therefore turn the
 * endpoint into an account-existence oracle. Instead we return parameters that
 * look exactly like a real account's, derived deterministically from a
 * server-held pepper so they stay stable across requests. A prober cannot
 * distinguish them; a real user just fails auth at the next step, as they
 * would with a wrong password.
 */
export function decoyKdfParams(accountId: string, pepper: Uint8Array): {
  algorithm: 'argon2id';
  memoryKiB: number;
  iterations: number;
  parallelism: number;
  saltB64: string;
  keyLength: number;
} {
  const salt = createHmac('sha256', pepper).update(accountId).digest().subarray(0, 16);
  return {
    algorithm: 'argon2id',
    // Mirrors core's `interactive` preset, so decoys are indistinguishable
    // from the overwhelmingly common real case.
    memoryKiB: 64 * 1024,
    iterations: 3,
    parallelism: 1,
    saltB64: salt.toString('base64'),
    keyLength: 32,
  };
}

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------

/**
 * Per-IP failed-attempt limiter, in memory.
 *
 * Online guessing against a 256-bit secret is hopeless anyway; this exists to
 * stop a prober hammering prelogin and to bound the cost of junk traffic. It
 * resets on restart, which is acceptable for a single-tenant self-hosted box.
 */
export class AttemptLimiter {
  private readonly hits = new Map<string, { count: number; resetAt: number }>();
  private readonly limit: number;
  private readonly windowMs: number;

  // Explicit fields rather than constructor parameter properties: Node runs
  // these sources through type stripping, which rejects that syntax outright.
  constructor(limit: number, windowMs: number) {
    this.limit = limit;
    this.windowMs = windowMs;
  }

  /** True when the caller has exceeded its budget. */
  isBlocked(key: string, now: number = Date.now()): boolean {
    const entry = this.hits.get(key);
    if (!entry || now >= entry.resetAt) return false;
    return entry.count >= this.limit;
  }

  recordFailure(key: string, now: number = Date.now()): void {
    const entry = this.hits.get(key);
    if (!entry || now >= entry.resetAt) {
      this.hits.set(key, { count: 1, resetAt: now + this.windowMs });
      return;
    }
    entry.count++;
  }

  recordSuccess(key: string): void {
    this.hits.delete(key);
  }

  /** Drop expired buckets so the map cannot grow without bound. */
  sweep(now: number = Date.now()): void {
    for (const [key, entry] of this.hits) {
      if (now >= entry.resetAt) this.hits.delete(key);
    }
  }
}
