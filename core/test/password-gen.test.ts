import { describe, expect, it } from 'vitest';
import {
  DEFAULT_GENERATOR_OPTIONS,
  MAX_LENGTH,
  MIN_LENGTH,
  SYMBOLS,
  estimateStrength,
  generatePassphrase,
  generatePassword,
  generatorEntropyBits,
  generatorPoolSize,
  strengthFromBits,
} from '../src/password-gen.ts';
import { ValidationError } from '../src/errors.ts';
import type { GeneratorOptions } from '../src/types.ts';

const opts = (patch: Partial<GeneratorOptions> = {}): GeneratorOptions => ({ ...DEFAULT_GENERATOR_OPTIONS, ...patch });

describe('generatePassword', () => {
  it('honours the requested length', () => {
    for (const length of [MIN_LENGTH, 16, 32, 64, MAX_LENGTH]) {
      expect(generatePassword(opts({ length }))).toHaveLength(length);
    }
  });

  it('includes at least one character from every enabled class', () => {
    // Probabilistic on a naive implementation; guaranteed by the seeding step.
    for (let i = 0; i < 200; i += 1) {
      const pw = generatePassword(opts({ length: MIN_LENGTH }));
      expect(pw).toMatch(/[a-z]/);
      expect(pw).toMatch(/[A-Z]/);
      expect(pw).toMatch(/[0-9]/);
      expect(pw).toMatch(/[^a-zA-Z0-9]/);
    }
  });

  it('uses only the enabled classes', () => {
    const digitsOnly = generatePassword(opts({ lowercase: false, uppercase: false, symbols: false, length: 32 }));
    expect(digitsOnly).toMatch(/^[0-9]{32}$/);

    const noSymbols = generatePassword(opts({ symbols: false, length: 64 }));
    expect(noSymbols).toMatch(/^[a-zA-Z0-9]{64}$/);
  });

  it('draws symbols only from the compatibility set', () => {
    const allowed = new Set(SYMBOLS);
    for (let i = 0; i < 100; i += 1) {
      const pw = generatePassword(
        opts({ length: 64, lowercase: false, uppercase: false, digits: false, symbols: true }),
      );
      for (const ch of pw) expect(allowed.has(ch)).toBe(true);
    }
  });

  it('excludes ambiguous glyphs when asked', () => {
    for (let i = 0; i < 100; i += 1) {
      expect(generatePassword(opts({ excludeAmbiguous: true, length: 64 }))).not.toMatch(/[0O1lI5S8B|`'"]/);
    }
  });

  it('does not repeat', () => {
    const generated = new Set(Array.from({ length: 500 }, () => generatePassword(opts({ length: 20 }))));
    expect(generated.size).toBe(500);
  });

  it('does not place classes in a predictable order', () => {
    // Without the shuffle, position 0 would always be lowercase.
    const firstChars = new Set(Array.from({ length: 300 }, () => generatePassword(opts({ length: 8 }))[0]));
    const classes = new Set<string>();
    for (const c of firstChars) {
      if (/[a-z]/.test(c!)) classes.add('lower');
      else if (/[A-Z]/.test(c!)) classes.add('upper');
      else if (/[0-9]/.test(c!)) classes.add('digit');
      else classes.add('symbol');
    }
    expect(classes.size).toBe(4);
  });

  it('distributes characters roughly uniformly', () => {
    // Guards against modulo bias. With ~10k digit draws, a biased implementation
    // shows a visible skew across the 10 buckets.
    const counts = new Map<string, number>();
    for (let i = 0; i < 200; i += 1) {
      for (const ch of generatePassword(opts({ length: 50, lowercase: false, uppercase: false, symbols: false }))) {
        counts.set(ch, (counts.get(ch) ?? 0) + 1);
      }
    }
    expect(counts.size).toBe(10);
    const expected = 10_000 / 10;
    for (const count of counts.values()) {
      expect(Math.abs(count - expected) / expected).toBeLessThan(0.2);
    }
  });

  it('rejects invalid options', () => {
    expect(() => generatePassword(opts({ length: MIN_LENGTH - 1 }))).toThrow(ValidationError);
    expect(() => generatePassword(opts({ length: MAX_LENGTH + 1 }))).toThrow(ValidationError);
    expect(() => generatePassword(opts({ length: 20.5 }))).toThrow(ValidationError);
    expect(() =>
      generatePassword(opts({ lowercase: false, uppercase: false, digits: false, symbols: false })),
    ).toThrow(ValidationError);
  });

  it('rejects a length too short to hold every required class', () => {
    expect(() => generatePassword(opts({ length: 8, lowercase: true, uppercase: true, digits: true, symbols: true }))).not.toThrow();
    // 4 classes cannot fit into 3 characters — but MIN_LENGTH already blocks this,
    // so verify the guard directly via an out-of-range length.
    expect(() => generatePassword(opts({ length: 3 }))).toThrow(ValidationError);
  });
});

describe('generatePassphrase', () => {
  const wordlist = Array.from({ length: 2048 }, (_, i) => `word${i}`);

  it('produces the requested number of words', () => {
    expect(generatePassphrase(wordlist, 5).split('-')).toHaveLength(5);
    expect(generatePassphrase(wordlist, 8, ' ').split(' ')).toHaveLength(8);
  });

  it('rejects a too-small wordlist or bad length', () => {
    expect(() => generatePassphrase(['a', 'b'], 5)).toThrow(ValidationError);
    expect(() => generatePassphrase(wordlist, 2)).toThrow(ValidationError);
    expect(() => generatePassphrase(wordlist, 25)).toThrow(ValidationError);
  });
});

describe('estimateStrength', () => {
  it('scores an empty password as zero', () => {
    expect(estimateStrength('')).toMatchObject({ bits: 0, score: 0, crackTimeDisplay: 'instantly' });
  });

  it('ranks longer passwords higher at a fixed charset', () => {
    expect(estimateStrength('kdmfoqzl').bits).toBeLessThan(estimateStrength('kdmfoqzlanciwbeu').bits);
  });

  it('ranks a broader charset higher at a fixed length', () => {
    expect(estimateStrength('kdmfoqzlanciwbeu').bits).toBeLessThan(estimateStrength('kD3$fQzLaNc!wBeU').bits);
  });

  it('scores a repeated unit near the unit itself, never below it', () => {
    // The estimate must stay monotonic: appending copies cannot reduce strength.
    const unit = estimateStrength('aB3$xY9!');
    const repeated = estimateStrength('aB3$xY9!'.repeat(4));
    expect(repeated.bits).toBeGreaterThanOrEqual(unit.bits);
    expect(repeated.bits).toBeLessThan(unit.bits * 1.5);
  });

  it('penalises repetition', () => {
    expect(estimateStrength('aaaaaaaaaaaaaaaaaaaa').bits).toBeLessThan(estimateStrength('kdmfoqzlanciwbeur').bits);
    expect(estimateStrength('abababababababababab').bits).toBeLessThan(estimateStrength('kdmfoqzlanciwbeur').bits);
  });

  it('penalises keyboard and numeric runs', () => {
    expect(estimateStrength('qwerty123456').bits).toBeLessThan(estimateStrength('xkqvnr849271').bits);
  });

  it('rates a generated default as excellent', () => {
    const result = estimateStrength(generatePassword(DEFAULT_GENERATOR_OPTIONS));
    expect(result.score).toBe(4);
    expect(result.bits).toBeGreaterThan(100);
  });

  it('produces a monotonic score/label pairing', () => {
    const labels = ['very weak', 'weak', 'fair', 'strong', 'excellent'];
    for (const pw of ['a', 'abc123', 'abcdef123456', 'aB3$xY9!qW2@', generatePassword(DEFAULT_GENERATOR_OPTIONS)]) {
      const r = estimateStrength(pw);
      expect(labels[r.score]).toBe(r.label);
    }
  });

  it('reports a human-readable crack time', () => {
    expect(estimateStrength('a').crackTimeDisplay).toBe('instantly');
    expect(estimateStrength(generatePassword(DEFAULT_GENERATOR_OPTIONS)).crackTimeDisplay).toBe(
      'longer than the age of the universe',
    );
  });
});

describe('generator entropy (exact, not inferred)', () => {
  const allClasses: GeneratorOptions = {
    length: 20,
    lowercase: true,
    uppercase: true,
    digits: true,
    symbols: true,
    excludeAmbiguous: false,
  };

  it('derives the pool from the real character sets', () => {
    // Tied to SYMBOLS, so narrowing the symbol set updates the reported entropy
    // instead of silently drifting from what the generator actually does.
    expect(generatorPoolSize(allClasses)).toBe(26 + 26 + 10 + SYMBOLS.length);
    expect(generatorEntropyBits(allClasses)).toBeCloseTo(20 * Math.log2(26 + 26 + 10 + SYMBOLS.length), 6);
  });

  it('tracks each enabled class', () => {
    const only = (patch: Partial<GeneratorOptions>): GeneratorOptions => ({
      ...allClasses,
      lowercase: false,
      uppercase: false,
      digits: false,
      symbols: false,
      ...patch,
    });
    expect(generatorPoolSize(only({ lowercase: true }))).toBe(26);
    expect(generatorPoolSize(only({ digits: true }))).toBe(10);
    expect(generatorPoolSize(only({ symbols: true }))).toBe(SYMBOLS.length);
    expect(generatorPoolSize(only({ lowercase: true, digits: true }))).toBe(36);
  });

  it('shrinks when ambiguous characters are excluded', () => {
    const plain = generatorPoolSize(allClasses);
    const filtered = generatorPoolSize({ ...allClasses, excludeAmbiguous: true });
    expect(filtered).toBeLessThan(plain);
    expect(generatorEntropyBits({ ...allClasses, excludeAmbiguous: true })).toBeLessThan(
      generatorEntropyBits(allClasses),
    );
  });

  it('scales with length and handles degenerate options', () => {
    expect(generatorEntropyBits({ ...allClasses, length: 40 })).toBeCloseTo(
      2 * generatorEntropyBits(allClasses),
      6,
    );
    const noClasses = { ...allClasses, lowercase: false, uppercase: false, digits: false, symbols: false };
    expect(generatorEntropyBits(noClasses)).toBe(0);
  });

  it('does not overstate the way inference does', () => {
    // The regression this guards: estimateStrength credits any non-alphanumeric
    // with a 33-symbol pool, which overstates the 8-symbol generated password.
    const password = generatePassword(allClasses);
    const inferred = estimateStrength(password).bits;
    const exact = generatorEntropyBits(allClasses);
    expect(exact).toBeLessThan(inferred);
    expect(inferred - exact).toBeGreaterThan(5); // ~8.8 bits at the default length
  });

  it('stays within a bit of the true class-constrained entropy', () => {
    // generatePassword guarantees one char per class, so the reachable space is
    // slightly smaller than pool^length. Confirm the documented "<1 bit" claim.
    const { length } = allClasses;
    const pool = generatorPoolSize(allClasses);
    const classSizes = [26, 26, 10, SYMBOLS.length];
    // Inclusion-exclusion: fraction of strings containing every class.
    let valid = 0;
    for (let mask = 0; mask < 16; mask += 1) {
      let excluded = 0;
      let bits = 0;
      for (let i = 0; i < 4; i += 1) {
        if (mask & (1 << i)) {
          excluded += classSizes[i]!;
          bits += 1;
        }
      }
      valid += (bits % 2 === 0 ? 1 : -1) * Math.pow((pool - excluded) / pool, length);
    }
    const trueBits = length * Math.log2(pool) + Math.log2(valid);
    expect(generatorEntropyBits(allClasses) - trueBits).toBeLessThan(1);
  });
});

describe('strengthFromBits', () => {
  it('labels a known entropy figure the same way inference would', () => {
    expect(strengthFromBits(0).label).toBe('very weak');
    expect(strengthFromBits(35).label).toBe('weak');
    expect(strengthFromBits(50).label).toBe('fair');
    expect(strengthFromBits(70).label).toBe('strong');
    expect(strengthFromBits(128).label).toBe('excellent');
  });

  it('rounds to one decimal and clamps negatives', () => {
    expect(strengthFromBits(122.5555).bits).toBe(122.6);
    expect(strengthFromBits(-5).bits).toBe(0);
  });
});
