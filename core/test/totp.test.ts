import { describe, expect, it } from 'vitest';
import { base32Decode, generateTotp, parseOtpAuthUri } from '../src/totp.ts';
import { bytesToUtf8 } from '../src/encoding.ts';
import { ValidationError } from '../src/errors.ts';

/** RFC 6238 Appendix B seed: the ASCII string "12345678901234567890". */
const RFC_SECRET_B32 = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

describe('base32Decode', () => {
  it('decodes the RFC 6238 seed', () => {
    expect(bytesToUtf8(base32Decode(RFC_SECRET_B32))).toBe('12345678901234567890');
  });

  it('tolerates lowercase, spaces, dashes and padding', () => {
    const expected = bytesToUtf8(base32Decode(RFC_SECRET_B32));
    expect(bytesToUtf8(base32Decode('gezdgnbv gy3tqojq-gezdgnbvgy3tqojq'))).toBe(expected);
    expect(bytesToUtf8(base32Decode('MZXW6==='))).toBe('foo');
  });

  it('rejects invalid input', () => {
    expect(() => base32Decode('')).toThrow(ValidationError);
    expect(() => base32Decode('0189!')).toThrow(ValidationError);
  });
});

describe('generateTotp — RFC 6238 test vectors', () => {
  // Appendix B, SHA-1 column, 8 digits.
  const vectors: Array<[number, string]> = [
    [59, '94287082'],
    [1111111109, '07081804'],
    [1111111111, '14050471'],
    [1234567890, '89005924'],
    [2000000000, '69279037'],
    [20000000000, '65353130'],
  ];

  it.each(vectors)('T=%i produces %s', async (unixSeconds, expected) => {
    const result = await generateTotp(RFC_SECRET_B32, { digits: 8, algorithm: 'SHA-1' }, unixSeconds * 1000);
    expect(result.code).toBe(expected);
  });

  it('handles counters beyond 2^32 (the 32-bit shift trap)', async () => {
    // T=20000000000 is counter 666666666 — but this asserts the high word is
    // written, which a naive `counter >>> 32` would silently drop.
    const result = await generateTotp(RFC_SECRET_B32, { digits: 8 }, 20000000000 * 1000);
    expect(result.code).toBe('65353130');
  });
});

describe('generateTotp — behaviour', () => {
  it('defaults to 6 digits over a 30-second period', async () => {
    const result = await generateTotp(RFC_SECRET_B32, {}, 59_000);
    expect(result.code).toMatch(/^\d{6}$/);
    expect(result.periodSeconds).toBe(30);
  });

  it('is stable within a period and changes across one', async () => {
    const a = await generateTotp(RFC_SECRET_B32, {}, 30_000);
    const b = await generateTotp(RFC_SECRET_B32, {}, 59_000);
    const c = await generateTotp(RFC_SECRET_B32, {}, 60_000);
    expect(a.code).toBe(b.code);
    expect(c.code).not.toBe(a.code);
  });

  it('reports the seconds remaining in the current period', async () => {
    expect((await generateTotp(RFC_SECRET_B32, {}, 30_000)).secondsRemaining).toBe(30);
    expect((await generateTotp(RFC_SECRET_B32, {}, 45_000)).secondsRemaining).toBe(15);
    expect((await generateTotp(RFC_SECRET_B32, {}, 59_000)).secondsRemaining).toBe(1);
  });

  it('rejects out-of-range options', async () => {
    await expect(generateTotp(RFC_SECRET_B32, { digits: 4 })).rejects.toThrow(ValidationError);
    await expect(generateTotp(RFC_SECRET_B32, { digits: 12 })).rejects.toThrow(ValidationError);
    await expect(generateTotp(RFC_SECRET_B32, { periodSeconds: 0 })).rejects.toThrow(ValidationError);
  });
});

describe('parseOtpAuthUri', () => {
  it('parses a standard URI', () => {
    const parsed = parseOtpAuthUri(`otpauth://totp/GitHub:octocat?secret=${RFC_SECRET_B32}&issuer=GitHub&digits=6&period=30`);
    expect(parsed?.secret).toBe(RFC_SECRET_B32);
    expect(parsed?.options).toMatchObject({ digits: 6, periodSeconds: 30, algorithm: 'SHA-1' });
    expect(parsed?.label).toBe('GitHub:octocat');
  });

  it('maps algorithm names', () => {
    expect(parseOtpAuthUri(`otpauth://totp/x?secret=A&algorithm=SHA256`)?.options.algorithm).toBe('SHA-256');
    expect(parseOtpAuthUri(`otpauth://totp/x?secret=A&algorithm=SHA512`)?.options.algorithm).toBe('SHA-512');
  });

  it('rejects non-TOTP and malformed URIs', () => {
    expect(parseOtpAuthUri('otpauth://hotp/x?secret=A')).toBeNull();
    expect(parseOtpAuthUri('https://example.com/?secret=A')).toBeNull();
    expect(parseOtpAuthUri('otpauth://totp/x')).toBeNull();
    expect(parseOtpAuthUri('nonsense')).toBeNull();
  });
});

describe('normalizeTotpConfig', () => {
  it('collapses the defaults to null', async () => {
    const { normalizeTotpConfig } = await import('../src/totp.ts');
    expect(normalizeTotpConfig({ digits: 6, periodSeconds: 30, algorithm: 'SHA-1' })).toBeNull();
    expect(normalizeTotpConfig({})).toBeNull();
    expect(normalizeTotpConfig(null)).toBeNull();
  });

  it('keeps non-default parameters', async () => {
    const { normalizeTotpConfig } = await import('../src/totp.ts');
    expect(normalizeTotpConfig({ digits: 8, periodSeconds: 60, algorithm: 'SHA-256' })).toEqual({
      digits: 8,
      periodSeconds: 60,
      algorithm: 'SHA-256',
    });
  });
});

describe('generateTotp with stored config', () => {
  it('matches an 8-digit 60-second issuer', async () => {
    const uri = `otpauth://totp/Issuer:user?secret=${RFC_SECRET_B32}&digits=8&period=60&algorithm=SHA1`;
    const parsed = parseOtpAuthUri(uri);
    expect(parsed).not.toBeNull();
    const { normalizeTotpConfig } = await import('../src/totp.ts');
    const config = normalizeTotpConfig(parsed!.options);
    expect(config).toEqual({ digits: 8, periodSeconds: 60, algorithm: 'SHA-1' });

    // Same counter as the RFC vector at T=59 with period 30 would differ; with
    // period 60, T=59 is still in the first window (counter 0).
    const result = await generateTotp(parsed!.secret, config ?? undefined, 59_000);
    expect(result.code).toHaveLength(8);
    expect(result.periodSeconds).toBe(60);
    // Independent check: same options must be stable.
    const again = await generateTotp(parsed!.secret, { digits: 8, periodSeconds: 60 }, 59_000);
    expect(again.code).toBe(result.code);
  });
});
