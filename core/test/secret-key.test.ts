import { describe, expect, it } from 'vitest';
import {
  SECRET_KEY_BYTES,
  formatSecret,
  generateSecretKeyBytes,
  isWellFormedSecret,
  parseSecret,
} from '../src/secret-key.ts';
import { randomBytes } from '../src/crypto.ts';
import { ValidationError } from '../src/errors.ts';
import { timingSafeEqual } from '../src/encoding.ts';

const KEY = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 255]);

describe('formatting', () => {
  it('round-trips every byte value', () => {
    for (let trial = 0; trial < 200; trial += 1) {
      const raw = randomBytes(SECRET_KEY_BYTES);
      expect(timingSafeEqual(parseSecret('secret-key', formatSecret('secret-key', raw)), raw)).toBe(true);
    }
  });

  it('round-trips the all-zero and all-ones keys', () => {
    for (const raw of [new Uint8Array(SECRET_KEY_BYTES), new Uint8Array(SECRET_KEY_BYTES).fill(0xff)]) {
      expect(timingSafeEqual(parseSecret('recovery-code', formatSecret('recovery-code', raw)), raw)).toBe(true);
    }
  });

  it('produces a stable, grouped, prefixed rendering', () => {
    const formatted = formatSecret('secret-key', KEY);
    expect(formatted).toMatch(/^KH2SK(-[0-9A-HJKMNP-TV-Z]{4}){7}$/);
    // Regenerating must not drift: the kit is printed once and typed back later.
    expect(formatSecret('secret-key', KEY)).toBe(formatted);
  });

  it('uses a different prefix per kind, and never collides', () => {
    expect(formatSecret('secret-key', KEY)).toMatch(/^KH2SK-/);
    expect(formatSecret('recovery-code', KEY)).toMatch(/^KH2RC-/);
    expect(formatSecret('secret-key', KEY)).not.toBe(formatSecret('recovery-code', KEY));
  });

  it('refuses to format the wrong number of bytes', () => {
    expect(() => formatSecret('secret-key', randomBytes(15))).toThrow(ValidationError);
  });
});

describe('transcription tolerance', () => {
  const formatted = formatSecret('secret-key', KEY);

  it('accepts lower case, missing dashes, and stray whitespace', () => {
    for (const variant of [
      formatted.toLowerCase(),
      formatted.replace(/-/g, ''),
      `  ${formatted}\n`,
      formatted.replace(/-/g, ' - '),
    ]) {
      expect(timingSafeEqual(parseSecret('secret-key', variant), KEY)).toBe(true);
    }
  });

  it('folds the glyphs people actually confuse on paper', () => {
    // O/0 and I/L/1 are the pairs a reader mixes up; both must land on the same key.
    const raw = new Uint8Array(SECRET_KEY_BYTES);
    const canonical = formatSecret('secret-key', raw);
    const confused = canonical.replace(/0/g, 'O');
    expect(confused).not.toBe(canonical);
    expect(timingSafeEqual(parseSecret('secret-key', confused), raw)).toBe(true);
  });
});

describe('error reporting', () => {
  const formatted = formatSecret('secret-key', KEY);

  it('names the mix-up when the two kit halves are swapped', () => {
    const recovery = formatSecret('recovery-code', KEY);
    expect(() => parseSecret('secret-key', recovery)).toThrow(/looks like your Recovery Code/);
    expect(() => parseSecret('recovery-code', formatted)).toThrow(/looks like your Secret Key/);
  });

  it('reports a single-character typo as a typo, not as a wrong key', () => {
    // This is the whole point of the checksum: without it this case is
    // indistinguishable from a wrong master password.
    const body = formatted.slice('KH2SK-'.length);
    let mutated = '';
    for (const char of body) {
      if (char === '-') continue;
      const swapped = char === '0' ? '9' : '0';
      mutated = formatted.replace(char, swapped);
      break;
    }
    expect(() => parseSecret('secret-key', mutated)).toThrow(/typo/);
  });

  it('catches transposed characters, which a plain sum would not', () => {
    const chars = formatted.replace(/-/g, '').slice('KH2SK'.length).split('');
    let found = 0;
    for (let i = 0; i + 1 < chars.length; i += 1) {
      if (chars[i] === chars[i + 1]) continue;
      const swapped = [...chars];
      [swapped[i], swapped[i + 1]] = [swapped[i + 1]!, swapped[i]!];
      expect(isWellFormedSecret('secret-key', `KH2SK${swapped.join('')}`)).toBe(false);
      found += 1;
      if (found === 5) break;
    }
    expect(found).toBeGreaterThan(0);
  });

  it('rejects the wrong length with an actionable message', () => {
    expect(() => parseSecret('secret-key', `${formatted}A`)).toThrow(/characters after the prefix/);
    expect(() => parseSecret('secret-key', formatted.slice(0, -1))).toThrow(/characters after the prefix/);
  });

  it('rejects characters outside the alphabet', () => {
    // U is excluded from Crockford Base32; mutate the body, not the KH2SK prefix.
    const body = formatted.slice('KH2SK'.length);
    expect(() => parseSecret('secret-key', `KH2SK${body.replace(/[0-9A-Z]/, 'U')}`)).toThrow(/not a character/);
  });

  it('rejects a missing or foreign prefix', () => {
    expect(() => parseSecret('secret-key', formatted.replace('KH2SK', 'KH3SK'))).toThrow(/starts with KH2SK/);
    expect(() => parseSecret('secret-key', '')).toThrow(/Enter your Secret Key/);
  });
});

describe('generation', () => {
  it('produces distinct, well-formed keys', () => {
    const seen = new Set<string>();
    for (let i = 0; i < 50; i += 1) {
      const formatted = formatSecret('secret-key', generateSecretKeyBytes());
      expect(isWellFormedSecret('secret-key', formatted)).toBe(true);
      seen.add(formatted);
    }
    expect(seen.size).toBe(50);
  });
});
