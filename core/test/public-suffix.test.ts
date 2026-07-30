import { describe, expect, it } from 'vitest';
import { isSameSite, registrableDomain } from '../src/public-suffix.ts';

describe('registrableDomain', () => {
  it('resolves flat gTLDs to suffix + one label', () => {
    expect(registrableDomain('example.com')).toBe('example.com');
    expect(registrableDomain('accounts.example.com')).toBe('example.com');
    expect(registrableDomain('a.b.c.example.com')).toBe('example.com');
    expect(registrableDomain('example.dev')).toBe('example.dev');
    expect(registrableDomain('app.stripe.io')).toBe('stripe.io');
  });

  it('normalizes case and a trailing dot', () => {
    expect(registrableDomain('Mail.Example.COM.')).toBe('example.com');
  });

  it('honours listed multi-label suffixes', () => {
    expect(registrableDomain('www.bbc.co.uk')).toBe('bbc.co.uk');
    expect(registrableDomain('shop.example.com.au')).toBe('example.com.au');
    expect(registrableDomain('mail.example.co.jp')).toBe('example.co.jp');
  });

  it('treats multi-tenant hosts as suffixes, so tenants are not one site', () => {
    expect(registrableDomain('alice.github.io')).toBe('alice.github.io');
    expect(registrableDomain('bob.github.io')).toBe('bob.github.io');
    expect(registrableDomain('shop.myshopify.com')).toBe('shop.myshopify.com');
    expect(registrableDomain('team.atlassian.net')).toBe('team.atlassian.net');
  });

  it('returns null for a bare public suffix', () => {
    for (const host of ['com', 'co.uk', 'github.io', 'com.au']) {
      expect(registrableDomain(host)).toBeNull();
    }
  });

  it('returns null for hosts with no registrable domain at all', () => {
    for (const host of ['', '   ', 'localhost', 'db', '127.0.0.1', '::1', 'example..com', '1.2.3.4']) {
      expect(registrableDomain(host)).toBeNull();
    }
  });

  it('returns null inside reserved and internal namespaces', () => {
    for (const host of ['box.local', 'svc.internal', 'app.test', 'files.lan', 'x.corp']) {
      expect(registrableDomain(host)).toBeNull();
    }
  });

  // Layer 3 of public-suffix.ts: catch suffixes the list is missing rather than
  // pooling unrelated registrants into one "site".
  describe('fail-closed guards for unlisted suffixes', () => {
    it('refuses a registry-generic base label', () => {
      // co.mz is a real public suffix that the curated list does not carry, so
      // the generic base label is all that stands between two Mozambican banks.
      expect(registrableDomain('bank.co.mz')).toBeNull();
      expect(registrableDomain('other.co.mz')).toBeNull();
      expect(registrableDomain('x.gov.somewhere')).toBeNull();
    });

    it('refuses a two-letter base label under a two-letter ccTLD', () => {
      // Italian province domains: comune.mi.it and other.mi.it share no owner.
      expect(registrableDomain('comune.mi.it')).toBeNull();
      expect(registrableDomain('site.rm.it')).toBeNull();
      // Still fine one level up, where the base label is the registration.
      expect(registrableDomain('www.example.it')).toBe('example.it');
    });
  });
});

describe('isSameSite', () => {
  it('is true across hosts of one registrable domain', () => {
    expect(isSameSite('accounts.example.com', 'billing.example.com')).toBe(true);
    expect(isSameSite('www.example.com', 'example.com')).toBe(true);
    expect(isSameSite('example.com', 'www.example.com')).toBe(true);
    expect(isSameSite('a.b.example.co.uk', 'c.example.co.uk')).toBe(true);
  });

  it('is false for different registrable domains', () => {
    expect(isSameSite('example.com', 'example.net')).toBe(false);
    expect(isSameSite('example.com', 'notexample.com')).toBe(false);
    expect(isSameSite('github.com', 'github.co')).toBe(false);
    expect(isSameSite('example.com', 'example.com.evil.com')).toBe(false);
  });

  it('is false between tenants of a shared host', () => {
    expect(isSameSite('alice.github.io', 'bob.github.io')).toBe(false);
    expect(isSameSite('a.co.uk', 'b.co.uk')).toBe(false);
    expect(isSameSite('a.vercel.app', 'b.vercel.app')).toBe(false);
    expect(isSameSite('a.ngrok-free.app', 'b.ngrok-free.app')).toBe(false);
  });

  it('is false whenever either side is unresolvable', () => {
    expect(isSameSite('localhost', 'localhost')).toBe(false);
    expect(isSameSite('127.0.0.1', '127.0.0.1')).toBe(false);
    expect(isSameSite('co.uk', 'co.uk')).toBe(false);
    expect(isSameSite('example.com', '')).toBe(false);
  });
});
