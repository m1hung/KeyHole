/**
 * Have I Been Pwned k-anonymity helpers — pure, no I/O.
 *
 * Surfaces fetch `https://api.pwnedpasswords.com/range/{prefix}` themselves
 * (with `Add-Padding: true`) and pass the body here. Core never talks to the
 * network: that keeps the "no phone-home" contract enforceable at the module
 * boundary, and leaves the opt-in / host-permission story on each surface.
 */

import { bytesToHex } from './encoding.ts';

export interface RangeQuery {
  /** First 5 hex characters of the SHA-1 digest (uppercase). */
  prefix: string;
  /** Remaining 35 hex characters (uppercase). */
  suffix: string;
}

/** SHA-1 the password and split it for the HIBP range API. */
export async function hashForRangeQuery(password: string): Promise<RangeQuery> {
  const digest = await globalThis.crypto.subtle.digest('SHA-1', new TextEncoder().encode(password));
  const hex = bytesToHex(new Uint8Array(digest)).toUpperCase();
  return { prefix: hex.slice(0, 5), suffix: hex.slice(5) };
}

/**
 * Count how many times `suffix` appears in a HIBP range response body.
 *
 * Each line is `SUFFIX:COUNT`. Matching is case-insensitive; a missing suffix
 * is zero (not breached, or at least not in this dump).
 */
export function countFromRangeResponse(text: string, suffix: string): number {
  const target = suffix.toUpperCase();
  for (const line of text.split(/\r?\n/)) {
    if (line.length === 0) continue;
    const colon = line.indexOf(':');
    if (colon <= 0) continue;
    if (line.slice(0, colon).toUpperCase() !== target) continue;
    const count = Number(line.slice(colon + 1));
    return Number.isFinite(count) && count >= 0 ? count : 0;
  }
  return 0;
}
