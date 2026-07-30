/**
 * RFC 6238 TOTP. Uses WebCrypto HMAC — no third-party dependency.
 *
 * Secrets live encrypted inside the vault like any other field; codes are
 * derived on demand while unlocked and are never persisted.
 */

import { ValidationError } from './errors.ts';
import type { TotpConfig } from './types.ts';

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/** Decode RFC 4648 base32, tolerating lowercase, spaces and missing padding. */
export function base32Decode(input: string): Uint8Array {
  const clean = input.toUpperCase().replace(/[\s-]/g, '').replace(/=+$/, '');
  if (clean.length === 0) throw new ValidationError('TOTP secret is empty.');

  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const char of clean) {
    const index = BASE32_ALPHABET.indexOf(char);
    if (index === -1) throw new ValidationError('TOTP secret is not valid base32.');
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((value >>> bits) & 0xff);
    }
  }
  return new Uint8Array(out);
}

export interface TotpOptions {
  digits?: number;
  periodSeconds?: number;
  algorithm?: 'SHA-1' | 'SHA-256' | 'SHA-512';
}

export interface TotpCode {
  code: string;
  /** Seconds until this code rolls over. */
  secondsRemaining: number;
  periodSeconds: number;
}

export async function generateTotp(
  base32Secret: string,
  options: TotpOptions = {},
  atMs: number = Date.now(),
): Promise<TotpCode> {
  const digits = options.digits ?? 6;
  const period = options.periodSeconds ?? 30;
  const algorithm = options.algorithm ?? 'SHA-1';
  if (digits < 6 || digits > 10) throw new ValidationError('TOTP digits must be between 6 and 10.');
  if (period < 1) throw new ValidationError('TOTP period must be positive.');

  const secret = base32Decode(base32Secret);
  const counter = Math.floor(atMs / 1000 / period);

  // 8-byte big-endian counter. Split into two 32-bit halves because bitwise ops
  // in JS are 32-bit and would silently truncate a direct shift.
  const counterBytes = new Uint8Array(8);
  new DataView(counterBytes.buffer).setUint32(0, Math.floor(counter / 2 ** 32), false);
  new DataView(counterBytes.buffer).setUint32(4, counter >>> 0, false);

  const key = await globalThis.crypto.subtle.importKey(
    'raw',
    secret.slice().buffer as ArrayBuffer,
    { name: 'HMAC', hash: algorithm },
    false,
    ['sign'],
  );
  const mac = new Uint8Array(await globalThis.crypto.subtle.sign('HMAC', key, counterBytes.buffer as ArrayBuffer));
  secret.fill(0);

  // RFC 4226 dynamic truncation.
  const offset = mac[mac.length - 1]! & 0x0f;
  const binary =
    ((mac[offset]! & 0x7f) << 24) | ((mac[offset + 1]! & 0xff) << 16) | ((mac[offset + 2]! & 0xff) << 8) | (mac[offset + 3]! & 0xff);

  const code = (binary % 10 ** digits).toString().padStart(digits, '0');
  const secondsRemaining = period - Math.floor(atMs / 1000) % period;
  return { code, secondsRemaining, periodSeconds: period };
}

/** Parse an `otpauth://totp/...` URI into a secret plus options. */
export function parseOtpAuthUri(uri: string): { secret: string; options: TotpOptions; label: string } | null {
  let url: URL;
  try {
    url = new URL(uri);
  } catch {
    return null;
  }
  if (url.protocol !== 'otpauth:' || url.host.toLowerCase() !== 'totp') return null;

  const secret = url.searchParams.get('secret');
  if (!secret) return null;

  const digits = Number(url.searchParams.get('digits') ?? 6);
  const period = Number(url.searchParams.get('period') ?? 30);
  const rawAlg = (url.searchParams.get('algorithm') ?? 'SHA1').toUpperCase();
  const algorithm = rawAlg === 'SHA256' ? 'SHA-256' : rawAlg === 'SHA512' ? 'SHA-512' : 'SHA-1';

  return {
    secret,
    options: { digits, periodSeconds: period, algorithm },
    label: decodeURIComponent(url.pathname.replace(/^\//, '')),
  };
}

/**
 * Collapse TOTP options to `null` when they match the generateTotp defaults, so
 * existing entries stay indistinguishable from "never set a config".
 */
export function normalizeTotpConfig(options: TotpOptions | null | undefined): TotpConfig | null {
  if (!options) return null;
  const digits = options.digits ?? 6;
  const periodSeconds = options.periodSeconds ?? 30;
  const algorithm = options.algorithm ?? 'SHA-1';
  if (digits === 6 && periodSeconds === 30 && algorithm === 'SHA-1') return null;
  return { digits, periodSeconds, algorithm };
}
