import { describe, expect, it } from 'vitest';
import { displayHost, findMatchingEntries, matchUrl, parseTarget } from '../src/url-match.ts';
import { createEntry, emptyVaultData } from '../src/vault.ts';
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
});

describe('displayHost', () => {
  it('extracts the host, falling back to the raw input', () => {
    expect(displayHost('https://github.com/login?x=1')).toBe('github.com');
    expect(displayHost('not a url')).toBe('not a url');
  });
});
