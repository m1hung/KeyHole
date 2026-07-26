/**
 * Password generation and strength estimation.
 *
 * Every random choice goes through `crypto.getRandomValues` with rejection
 * sampling. `Math.random()` appears nowhere in this file, and the modulo-bias
 * shortcut (`rand % charset.length`) is deliberately avoided — with a 70-odd
 * character set that bias is small but it is free to eliminate.
 */

import { randomBytes } from './crypto.ts';
import { ValidationError } from './errors.ts';
import type { GeneratorOptions } from './types.ts';

const LOWERCASE = 'abcdefghijklmnopqrstuvwxyz';
const UPPERCASE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const DIGITS = '0123456789';
/**
 * Compatibility-first symbol set. Deliberately excludes glyphs that sites and
 * form filters commonly reject or mishandle: `<>[]{};:,.?=+\'"` and friends.
 * Entropy loss vs the old 27-symbol set is ~1.7 bits per symbol character —
 * negligible next to length.
 */
export const SYMBOLS = '!@#$%^&*';
/** Glyphs that are easy to confuse when transcribed by hand. */
const AMBIGUOUS = new Set('0O1lI5S8B|`\'"');

export const MIN_LENGTH = 8;
export const MAX_LENGTH = 128;

export const DEFAULT_GENERATOR_OPTIONS: GeneratorOptions = {
  length: 20,
  lowercase: true,
  uppercase: true,
  digits: true,
  symbols: true,
  excludeAmbiguous: false,
};

interface CharClass {
  readonly enabled: boolean;
  readonly chars: string;
}

function buildClasses(options: GeneratorOptions): string[] {
  const classes: CharClass[] = [
    { enabled: options.lowercase, chars: LOWERCASE },
    { enabled: options.uppercase, chars: UPPERCASE },
    { enabled: options.digits, chars: DIGITS },
    { enabled: options.symbols, chars: SYMBOLS },
  ];
  return classes
    .filter((c) => c.enabled)
    .map((c) => (options.excludeAmbiguous ? [...c.chars].filter((ch) => !AMBIGUOUS.has(ch)).join('') : c.chars))
    .filter((chars) => chars.length > 0);
}

/**
 * Uniform random index in [0, max) via rejection sampling.
 *
 * Draws 4 bytes and discards any draw landing in the final partial bucket, so
 * every index is exactly equally likely. The discard probability is under
 * 1-in-50-million for any charset we use, so the loop effectively never repeats.
 */
function randomIndex(max: number): number {
  if (max <= 0) throw new ValidationError('randomIndex requires a positive bound.');
  const limit = Math.floor(0xffffffff / max) * max;
  for (;;) {
    const b = randomBytes(4);
    const value = ((b[0]! << 24) >>> 0) + (b[1]! << 16) + (b[2]! << 8) + b[3]!;
    if (value < limit) return value % max;
  }
}

/** Fisher-Yates using the same unbiased source. */
function shuffle<T>(items: T[]): T[] {
  for (let i = items.length - 1; i > 0; i -= 1) {
    const j = randomIndex(i + 1);
    const a = items[i]!;
    const b = items[j]!;
    items[i] = b;
    items[j] = a;
  }
  return items;
}

export function generatePassword(options: GeneratorOptions = DEFAULT_GENERATOR_OPTIONS): string {
  const { length } = options;
  if (!Number.isInteger(length) || length < MIN_LENGTH || length > MAX_LENGTH) {
    throw new ValidationError(`Password length must be an integer between ${MIN_LENGTH} and ${MAX_LENGTH}.`);
  }

  const classes = buildClasses(options);
  if (classes.length === 0) {
    throw new ValidationError('Enable at least one character class.');
  }
  if (classes.length > length) {
    throw new ValidationError('Password length is shorter than the number of required character classes.');
  }

  // Seed one character per enabled class so the result always satisfies the
  // requested composition, then fill the remainder from the union.
  const pool = classes.join('');
  const chars: string[] = classes.map((cls) => cls[randomIndex(cls.length)]!);
  while (chars.length < length) {
    chars.push(pool[randomIndex(pool.length)]!);
  }

  // Without this, the first N characters would always be one-per-class in a
  // fixed order — a meaningful reduction in real entropy.
  return shuffle(chars).join('');
}

/** Size of the character pool `generatePassword` draws from for these options. */
export function generatorPoolSize(options: GeneratorOptions): number {
  return buildClasses(options).join('').length;
}

/**
 * Entropy of a password produced by `generatePassword` with these options.
 *
 * Prefer this over `estimateStrength` whenever the password was just generated.
 * `estimateStrength` has to *infer* the pool from the characters it can see, and
 * it credits any non-alphanumeric character with a 33-symbol pool. That was
 * roughly right for the original 27-symbol set, but the set is now 8 characters,
 * so inference overstates a generated password by ~9 bits at the default length.
 * Here the exact pool is known, so no inference is needed.
 *
 * Slight upper bound: `generatePassword` guarantees one character from each
 * enabled class, which trims the reachable output space a little. The gap is far
 * below one bit at any usable length (see the test asserting it), and erring
 * high by <1 bit is preferable to the alternative of erring low and nagging the
 * user about a password that is genuinely fine.
 */
export function generatorEntropyBits(options: GeneratorOptions): number {
  const poolSize = generatorPoolSize(options);
  if (poolSize === 0 || options.length <= 0) return 0;
  return options.length * Math.log2(poolSize);
}

/** Diceware-style passphrase. `wordlist` should hold >= 2048 distinct words. */
export function generatePassphrase(wordlist: readonly string[], words = 5, separator = '-'): string {
  if (wordlist.length < 128) throw new ValidationError('Wordlist is too small to be useful.');
  if (words < 3 || words > 24) throw new ValidationError('Passphrase length must be between 3 and 24 words.');
  return Array.from({ length: words }, () => wordlist[randomIndex(wordlist.length)]!).join(separator);
}

// ---------------------------------------------------------------------------
// Strength
// ---------------------------------------------------------------------------

export interface StrengthResult {
  /** Shannon entropy in bits, based on observed character classes. */
  bits: number;
  score: 0 | 1 | 2 | 3 | 4;
  label: 'very weak' | 'weak' | 'fair' | 'strong' | 'excellent';
  /** Order-of-magnitude offline crack time at 10^11 guesses/sec. */
  crackTimeDisplay: string;
}

/**
 * Entropy from the character classes actually present.
 *
 * This is a *generator-oriented* estimate: it is accurate for random strings
 * and deliberately optimistic for human-chosen ones ("Password1!" scores far
 * better than it deserves). We compensate with a penalty pass for the obvious
 * patterns, but the honest framing in the UI is "entropy if random" — a full
 * dictionary/L33t analysis would mean shipping zxcvbn's ~400 KB of word lists,
 * which is not worth it inside an extension bundle.
 */
export function estimateStrength(password: string): StrengthResult {
  if (password.length === 0) {
    return { bits: 0, score: 0, label: 'very weak', crackTimeDisplay: 'instantly' };
  }
  return strengthFromBits(entropyBits(password));
}

/**
 * Score and label an entropy figure that is already known exactly.
 *
 * Lets a caller holding a precise value — `generatorEntropyBits` for a
 * freshly generated password — render the same meter and wording as the
 * inferred path, instead of round-tripping through `estimateStrength` and
 * inheriting its pool-size guess.
 */
export function strengthFromBits(rawBits: number): StrengthResult {
  const bits = Math.round(Math.max(rawBits, 0) * 10) / 10;
  const { score, label } = classify(bits);
  return { bits, score, label, crackTimeDisplay: crackTime(bits) };
}

const SEQUENCES = /(?:abc|bcd|cde|def|123|234|345|456|567|678|789|qwe|wer|ert|asd)/i;

function entropyBits(password: string): number {
  // A string that is one unit repeated ("abcabcabc") carries barely more
  // information than the unit itself: an attacker guesses the unit, then the
  // repeat count. Scoring it as unit + log2(repeats) keeps the estimate
  // monotonic — multiplying penalties together instead would rank the repeated
  // string *below* its own unit, which is incoherent.
  const repeated = /^(.+?)\1+$/.exec(password);
  if (repeated) {
    const unit = repeated[1]!;
    return entropyBits(unit) + Math.log2(password.length / unit.length);
  }

  let poolSize = 0;
  if (/[a-z]/.test(password)) poolSize += 26;
  if (/[A-Z]/.test(password)) poolSize += 26;
  if (/[0-9]/.test(password)) poolSize += 10;
  if (/[^a-zA-Z0-9]/.test(password)) poolSize += 33;

  let bits = password.length * Math.log2(Math.max(poolSize, 2));

  // A small alphabet relative to length means the real search space is well
  // below the pool-size estimate.
  const unique = new Set(password).size;
  if (unique <= 2) bits *= 0.35;
  else if (unique / password.length < 0.4) bits *= 0.65;

  if (SEQUENCES.test(password)) bits *= 0.75;
  return bits;
}

function classify(bits: number): { score: StrengthResult['score']; label: StrengthResult['label'] } {
  if (bits < 28) return { score: 0, label: 'very weak' };
  if (bits < 40) return { score: 1, label: 'weak' };
  if (bits < 60) return { score: 2, label: 'fair' };
  if (bits < 80) return { score: 3, label: 'strong' };
  return { score: 4, label: 'excellent' };
}

/** Assumes 10^11 guesses/sec — a well-funded offline attacker against a fast hash. */
function crackTime(bits: number): string {
  const seconds = Math.pow(2, bits - 1) / 1e11;
  if (seconds < 1) return 'instantly';
  const units: Array<[number, string]> = [
    [60, 'seconds'],
    [60, 'minutes'],
    [24, 'hours'],
    [365, 'days'],
    [1000, 'years'],
  ];
  let value = seconds;
  let unit = 'seconds';
  for (const [factor, nextUnit] of units) {
    if (value < factor) break;
    value /= factor;
    unit = nextUnit;
  }
  if (unit === 'years' && value >= 1000) return 'longer than the age of the universe';
  return `${value < 10 ? value.toFixed(1) : Math.round(value).toLocaleString()} ${unit}`;
}
