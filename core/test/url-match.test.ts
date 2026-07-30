import { describe, expect, it } from 'vitest';
import { displayHost, findMatchingEntries, matchUrl, parseTarget } from '../src/url-match.ts';
import { createEntry, deleteEntry, emptyVaultData, restoreEntry } from '../src/vault.ts';
import type { Entry } from '../src/types.ts';

describe('parseTarget', () => {
  it('parses absolute URLs', () => {
    expect(parseTarget('https://github.com/login')).toMatchObject({
      origin: 'https://github.com',
      hostname: 'github.com',
      protocol: 'https:',
    });
  });

  it('accepts a bare host by assuming https', () => {
    expect(parseTarget('github.com')?.origin).toBe('https://github.com');
  });

  it('lowercases the host and strips a trailing dot', () => {
    expect(parseTarget('https://GitHub.COM./x')?.hostname).toBe('github.com');
  });

  it('refuses non-web schemes', () => {
    for (const url of ['file:///etc/passwd', 'javascript:alert(1)', 'data:text/html,x', 'chrome://settings']) {
      expect(parseTarget(url)).toBeNull();
    }
  });

  it('returns null on garbage', () => {
    expect(parseTarget('')).toBeNull();
    expect(parseTarget('   ')).toBeNull();
  });
});

describe('matchUrl — lookalike domain rejection', () => {
  // Each of these would pass a naive `includes()` check. None may match.
  const attacks = [
    'https://github.com.evil.com/login',
    'https://github.com.attacker.io',
    'https://notgithub.com',
    'https://github.co',
    'https://github.com-login.net',
    'https://evil.com/?next=https://github.com',
    'https://evil.com/#github.com',
    'https://xn--githb-8va.com',
  ];

  it.each(attacks)('does not match %s against github.com', (attacker) => {
    expect(matchUrl('https://github.com', attacker, 'subdomain')).toBe('none');
  });

  it('does not match a suffix that is not on a label boundary', () => {
    expect(matchUrl('https://example.com', 'https://badexample.com', 'subdomain')).toBe('none');
  });

  // The loosest mode must reject every one of the above too — a wider match mode
  // may widen who counts as the same site, never who counts as a lookalike.
  it.each(attacks)('does not match %s against github.com in domain mode', (attacker) => {
    expect(matchUrl('https://github.com', attacker, 'domain')).toBe('none');
  });

  it('does not pool tenants of a shared hosting domain in domain mode', () => {
    expect(matchUrl('https://alice.github.io', 'https://bob.github.io', 'domain')).toBe('none');
    expect(matchUrl('https://mine.vercel.app', 'https://theirs.vercel.app', 'domain')).toBe('none');
  });

  it('does not pool unrelated registrants under a ccTLD suffix in domain mode', () => {
    expect(matchUrl('https://mybank.co.uk', 'https://attacker.co.uk', 'domain')).toBe('none');
    expect(matchUrl('https://shop.com.au', 'https://evil.com.au', 'domain')).toBe('none');
  });

  it('refuses to widen when the namespace cannot be resolved safely', () => {
    // Unlisted ccTLD second level, IP literals, and intranet names all fall back
    // to same-host matching rather than guessing at a shared owner.
    expect(matchUrl('https://mybank.co.mz', 'https://attacker.co.mz', 'domain')).toBe('none');
    expect(matchUrl('http://10.0.0.5', 'http://10.0.0.6', 'domain')).toBe('none');
    expect(matchUrl('http://intranet.local', 'http://payroll.local', 'domain')).toBe('none');
  });
});

describe('matchUrl — legitimate matches', () => {
  it('matches an identical origin exactly', () => {
    expect(matchUrl('https://github.com/login', 'https://github.com/session')).toBe('exact');
  });

  it('matches the same host across ports/schemes at host strength', () => {
    expect(matchUrl('https://example.com', 'http://example.com')).toBe('host');
    expect(matchUrl('https://example.com', 'https://example.com:8443')).toBe('host');
  });

  it('matches a subdomain only in subdomain mode', () => {
    expect(matchUrl('https://github.com', 'https://gist.github.com', 'subdomain')).toBe('subdomain');
    expect(matchUrl('https://github.com', 'https://gist.github.com', 'host')).toBe('none');
    expect(matchUrl('https://github.com', 'https://gist.github.com', 'exact')).toBe('none');
  });

  it('does not widen a specific entry to its parent domain', () => {
    // An entry for accounts.google.com must not fill on google.com.
    expect(matchUrl('https://accounts.google.com', 'https://google.com', 'subdomain')).toBe('none');
  });

  describe('domain mode — same registrable domain, different host', () => {
    it('matches sibling hosts in either direction', () => {
      expect(matchUrl('https://accounts.example.com', 'https://billing.example.com', 'domain')).toBe('domain');
      expect(matchUrl('https://accounts.example.com', 'https://example.com', 'domain')).toBe('domain');
      expect(matchUrl('https://www.example.com', 'https://example.com', 'domain')).toBe('domain');
      expect(matchUrl('https://deep.a.example.co.uk', 'https://other.example.co.uk', 'domain')).toBe('domain');
    });

    it('is reported only when a stricter rule does not already apply', () => {
      expect(matchUrl('https://example.com/login', 'https://example.com/app', 'domain')).toBe('exact');
      expect(matchUrl('https://example.com', 'http://example.com', 'domain')).toBe('host');
      expect(matchUrl('https://example.com', 'https://gist.example.com', 'domain')).toBe('subdomain');
    });

    it('stays off in the stricter modes', () => {
      for (const mode of ['exact', 'host', 'subdomain'] as const) {
        expect(matchUrl('https://accounts.example.com', 'https://billing.example.com', mode)).toBe('none');
      }
    });
  });

  it('ignores the path entirely — a login page and an app page share an origin', () => {
    expect(matchUrl('https://example.com/a/b/c', 'https://example.com/x/y')).toBe('exact');
    expect(matchUrl('https://example.com', 'https://example.com/deep/path?q=1#h')).toBe('exact');
  });
});

describe('findMatchingEntries', () => {
  const build = (): Entry[] => {
    let data = emptyVaultData();
    data = createEntry(data, { title: 'GitHub Exact', urls: ['https://github.com/login'] }).data;
    data = createEntry(data, { title: 'GitHub Host', urls: ['http://github.com'] }).data;
    data = createEntry(data, { title: 'Unrelated', urls: ['https://example.org'] }).data;
    data = createEntry(data, { title: 'No URLs', urls: [] }).data;
    return data.entries;
  };

  it('returns only matching entries, best first', () => {
    const matches = findMatchingEntries(build(), 'https://github.com/login');
    expect(matches.map((m) => m.entry.title)).toEqual(['GitHub Exact', 'GitHub Host']);
    expect(matches[0]?.strength).toBe('exact');
    expect(matches[1]?.strength).toBe('host');
  });

  it('returns nothing for an unmatched page', () => {
    expect(findMatchingEntries(build(), 'https://unrelated.test')).toEqual([]);
  });

  it('returns nothing for an unparseable or non-web page URL', () => {
    expect(findMatchingEntries(build(), 'chrome://extensions')).toEqual([]);
    expect(findMatchingEntries(build(), '')).toEqual([]);
  });

  it('does not leak entries to a lookalike host', () => {
    expect(findMatchingEntries(build(), 'https://github.com.evil.com')).toEqual([]);
  });

  it('ranks same-site matches below every stricter match', () => {
    let data = emptyVaultData();
    data = createEntry(data, { title: 'Exact', urls: ['https://app.example.com/login'] }).data;
    data = createEntry(data, { title: 'Sibling', urls: ['https://accounts.example.com'] }).data;
    data = createEntry(data, { title: 'Parent', urls: ['https://example.com'] }).data;

    const matches = findMatchingEntries(data.entries, 'https://app.example.com/x', 'domain');
    expect(matches.map((m) => [m.entry.title, m.strength])).toEqual([
      ['Exact', 'exact'],
      ['Parent', 'subdomain'],
      ['Sibling', 'domain'],
    ]);
  });

  it('finds nothing extra in domain mode for an unrelated site', () => {
    expect(findMatchingEntries(build(), 'https://example.net', 'domain')).toEqual([]);
  });
});

describe('displayHost', () => {
  it('extracts the host, falling back to the raw input', () => {
    expect(displayHost('https://github.com/login?x=1')).toBe('github.com');
    expect(displayHost('not a url')).toBe('not a url');
  });
});

describe('trashed entries', () => {
  /**
   * The single most important consequence of soft delete: a deleted login must
   * never be offered for autofill again. The user's last word on it was "delete";
   * it is only still in the vault so they can change their mind.
   */
  it('are never offered, at any match strength', () => {
    let data = emptyVaultData();
    data = createEntry(data, { title: 'Live', urls: ['https://example.com'] }).data;
    data = createEntry(data, { title: 'Binned', urls: ['https://example.com'] }).data;
    const binnedId = data.entries[1]!.id;
    data = deleteEntry(data, binnedId);

    for (const mode of ['exact', 'host', 'subdomain', 'domain'] as const) {
      const titles = findMatchingEntries(data.entries, 'https://example.com/login', mode).map((m) => m.entry.title);
      expect(titles).toEqual(['Live']);
    }
  });

  it('are offered again once restored', () => {
    let data = emptyVaultData();
    data = createEntry(data, { title: 'Binned', urls: ['https://example.com'] }).data;
    const id = data.entries[0]!.id;

    expect(findMatchingEntries(deleteEntry(data, id).entries, 'https://example.com')).toEqual([]);
    expect(findMatchingEntries(restoreEntry(deleteEntry(data, id), id).entries, 'https://example.com')).toHaveLength(1);
  });
});
