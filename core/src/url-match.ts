/**
 * URL matching for autofill.
 *
 * This is a security boundary, not a convenience helper: a loose matcher hands
 * credentials to a lookalike domain. The rules are therefore deliberately
 * conservative.
 *
 *   NEVER substring-match hostnames. "github.com.evil.com".includes("github.com")
 *   is true, and that single mistake is a credential-theft bug.
 *
 * Matching is done on parsed URL components only, and subdomain matches must
 * land on a label boundary.
 */

import type { Entry } from './types.ts';

export type MatchStrength = 'exact' | 'host' | 'subdomain' | 'none';

/** How permissive host matching is. `host` is the default. */
export type MatchMode = 'exact' | 'host' | 'subdomain';

export interface ParsedTarget {
  origin: string;
  hostname: string;
  pathname: string;
  protocol: string;
}

/** Schemes we will ever autofill into. Anything else (file:, data:, chrome:) is refused. */
const ALLOWED_PROTOCOLS = new Set(['https:', 'http:']);

export function parseTarget(rawUrl: string): ParsedTarget | null {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    // Tolerate bare hosts stored by the user, e.g. "github.com".
    try {
      url = new URL(`https://${rawUrl}`);
    } catch {
      return null;
    }
  }
  if (!ALLOWED_PROTOCOLS.has(url.protocol)) return null;
  if (url.hostname.length === 0) return null;
  return {
    origin: url.origin,
    hostname: url.hostname.toLowerCase().replace(/\.$/, ''),
    pathname: url.pathname,
    protocol: url.protocol,
  };
}

/**
 * True when `candidate` is a subdomain of `base` — checked on a label boundary
 * so "notgithub.com" and "github.com.evil.com" both correctly fail against
 * "github.com".
 */
function isSubdomainOf(candidate: string, base: string): boolean {
  return candidate.length > base.length + 1 && candidate.endsWith(`.${base}`);
}

export function matchUrl(entryUrl: string, pageUrl: string, mode: MatchMode = 'host'): MatchStrength {
  const entry = parseTarget(entryUrl);
  const page = parseTarget(pageUrl);
  if (!entry || !page) return 'none';

  if (entry.origin === page.origin) return 'exact';
  if (mode === 'exact') return 'none';

  if (entry.hostname === page.hostname) return 'host';
  if (mode === 'host') return 'none';

  // Only the stored entry may act as the broader base. The reverse would let a
  // credential saved for accounts.example.com fill on example.com.
  if (isSubdomainOf(page.hostname, entry.hostname)) return 'subdomain';
  return 'none';
}

/** A match strength that actually matched. `findMatchingEntries` never yields 'none'. */
export type PositiveMatchStrength = Exclude<MatchStrength, 'none'>;

export interface EntryMatch {
  entry: Entry;
  strength: PositiveMatchStrength;
}

const RANK: Record<MatchStrength, number> = { exact: 3, host: 2, subdomain: 1, none: 0 };

/** All entries usable on `pageUrl`, best match first. */
export function findMatchingEntries(entries: readonly Entry[], pageUrl: string, mode: MatchMode = 'host'): EntryMatch[] {
  const page = parseTarget(pageUrl);
  if (!page) return [];

  const matches: EntryMatch[] = [];
  for (const entry of entries) {
    let best: MatchStrength = 'none';
    for (const url of entry.urls) {
      const strength = matchUrl(url, pageUrl, mode);
      if (RANK[strength] > RANK[best]) best = strength;
    }
    if (best !== 'none') matches.push({ entry, strength: best });
  }
  return matches.sort((a, b) => RANK[b.strength] - RANK[a.strength] || a.entry.title.localeCompare(b.entry.title));
}

/** Display host for UI ("github.com"), or the raw string if unparseable. */
export function displayHost(rawUrl: string): string {
  return parseTarget(rawUrl)?.hostname ?? rawUrl;
}
