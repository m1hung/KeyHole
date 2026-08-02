/**
 * Secret Key and Recovery Code encoding.
 *
 * These are the two halves of the Recovery Kit, and they are the only secrets
 * Keyhole ever asks a human to read off paper and type back in. That single fact
 * drives every decision in this file.
 *
 * WHY A CHECKSUM. Without one, a mistyped Secret Key is indistinguishable from a
 * wrong master password: both surface as a failed GCM tag, because the tag is the
 * only verifier we have (see crypto.ts). "Wrong master password" shown to someone
 * who typed their password correctly and fat-fingered one character of a 28-character
 * key is a genuinely bad failure — they will conclude the vault is corrupt. The
 * checksum lets us say "that Secret Key has a typo in it" *before* spending 105 ms
 * on Argon2id and then lying about the cause.
 *
 * WHY CROCKFORD BASE32. It drops I, L, O and U from the alphabet, so the glyph
 * pairs people actually confuse on paper (1/I/l, 0/O) cannot both be valid, and
 * decoding folds the confusable ones onto their intended digit rather than
 * rejecting them. U is excluded so no four-character group can spell an English
 * obscenity, which matters when the kit is printed and handed to a family member.
 *
 * WHY DISTINCT PREFIXES. The Secret Key and the Recovery Code are the same length
 * and the same alphabet, sit side by side on one printed page, and are used in
 * different fields. `KH2SK` vs `KH2RC` makes swapping them a named error instead of
 * a decryption failure. The `2` is the vault format version: a future format can
 * mint `KH3SK` and old software will refuse it by name.
 *
 * NOT A SECURITY BOUNDARY. The checksum is typo detection, not authentication —
 * it is unkeyed and anyone can compute it. It says nothing about whether the key
 * is *correct*, only that it was transcribed intact. Correctness is still proved
 * the one place it can be: the GCM tag.
 */

import { randomBytes } from './crypto.ts';
import { ValidationError } from './errors.ts';

/**
 * 128 bits. This is a *second factor* protecting an already-Argon2id-hardened
 * envelope, not a standalone key, so it is sized to make offline search hopeless
 * rather than to match the 256-bit VEK. It is also transcribed by hand, and every
 * extra byte is another chance to typo.
 */
export const SECRET_KEY_BYTES = 16;

/** Crockford Base32: no I, L, O or U. */
const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

/** Confusable glyphs folded onto what the reader meant. */
const ALIASES: Record<string, string> = { I: '1', L: '1', O: '0' };

/** Characters per printed group. 28 encoded characters divide evenly into 7 groups. */
const GROUP = 4;

/** 10 bits of CRC-16 residue. Enough to catch transcription errors, small enough to stay in one group. */
const CHECK_BITS = 10;

/** 128 key bits + 10 check bits, rounded up to a 5-bit boundary. */
const ENCODED_CHARS = Math.ceil((SECRET_KEY_BYTES * 8 + CHECK_BITS) / 5);

export type SecretKind = 'secret-key' | 'recovery-code';

const PREFIX: Record<SecretKind, string> = {
  'secret-key': 'KH2SK',
  'recovery-code': 'KH2RC',
};

const LABEL: Record<SecretKind, string> = {
  'secret-key': 'Secret Key',
  'recovery-code': 'Recovery Code',
};

// ---------------------------------------------------------------------------
// Checksum
// ---------------------------------------------------------------------------

/**
 * CRC-16/CCITT-FALSE, truncated to `CHECK_BITS`.
 *
 * Chosen over a plain sum because it catches transpositions — swapping two
 * characters is the most common transcription error a sum cannot see.
 */
function crc16(bytes: Uint8Array): number {
  let crc = 0xffff;
  for (const byte of bytes) {
    crc ^= byte << 8;
    for (let bit = 0; bit < 8; bit += 1) {
      crc = (crc & 0x8000) !== 0 ? ((crc << 1) ^ 0x1021) & 0xffff : (crc << 1) & 0xffff;
    }
  }
  return crc & ((1 << CHECK_BITS) - 1);
}

// ---------------------------------------------------------------------------
// Generation
// ---------------------------------------------------------------------------

/** Fresh random Secret Key / Recovery Code material. Caller must zeroize. */
export function generateSecretKeyBytes(): Uint8Array {
  return randomBytes(SECRET_KEY_BYTES);
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

/**
 * Render raw bytes as the grouped, prefixed string that goes on the Recovery Kit,
 * e.g. `KH2SK-1A2B-3C4D-...`.
 */
export function formatSecret(kind: SecretKind, raw: Uint8Array): string {
  if (raw.length !== SECRET_KEY_BYTES) {
    throw new ValidationError(`Expected ${SECRET_KEY_BYTES} bytes, got ${raw.length}.`);
  }

  let acc = 0;
  let bits = 0;
  let body = '';

  const push = (value: number, width: number): void => {
    acc = (acc << width) | value;
    bits += width;
    while (bits >= 5) {
      bits -= 5;
      body += ALPHABET[(acc >>> bits) & 31];
      acc &= (1 << bits) - 1;
    }
  };

  for (const byte of raw) push(byte, 8);
  push(crc16(raw), CHECK_BITS);
  // Pad the final partial group with zero bits so the length is fixed.
  if (bits > 0) body += ALPHABET[(acc << (5 - bits)) & 31];

  const groups: string[] = [];
  for (let i = 0; i < body.length; i += GROUP) groups.push(body.slice(i, i + GROUP));
  return `${PREFIX[kind]}-${groups.join('-')}`;
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

/**
 * Parse a Secret Key / Recovery Code back to bytes.
 *
 * Tolerant of everything that is a transcription artefact rather than a mistake:
 * lower case, missing or extra dashes, surrounding whitespace, and the confusable
 * glyphs folded by `ALIASES`. Strict about everything else — and note that a
 * checksum failure is reported as a *typo*, never as a wrong key, because that is
 * the only thing it actually proves.
 */
export function parseSecret(kind: SecretKind, input: string): Uint8Array {
  const label = LABEL[kind];
  const prefix = PREFIX[kind];

  const cleaned = input.replace(/[\s-]/g, '').toUpperCase();
  if (cleaned.length === 0) {
    throw new ValidationError(`Enter your ${label}.`);
  }

  // Check the *other* kind first so the common mix-up gets a name.
  for (const [otherKind, otherPrefix] of Object.entries(PREFIX)) {
    if (otherKind !== kind && cleaned.startsWith(otherPrefix)) {
      throw new ValidationError(`That looks like your ${LABEL[otherKind as SecretKind]}, not your ${label}.`);
    }
  }
  if (!cleaned.startsWith(prefix)) {
    throw new ValidationError(`A ${label} starts with ${prefix}-.`);
  }

  const body = cleaned.slice(prefix.length);
  if (body.length !== ENCODED_CHARS) {
    throw new ValidationError(
      `A ${label} has ${ENCODED_CHARS} characters after the prefix; this one has ${body.length}.`,
    );
  }

  let acc = 0;
  let bits = 0;
  const bytes = new Uint8Array(SECRET_KEY_BYTES);
  let written = 0;

  for (const char of body) {
    const symbol = ALIASES[char] ?? char;
    const value = ALPHABET.indexOf(symbol);
    if (value === -1) {
      throw new ValidationError(`"${char}" is not a character a ${label} can contain.`);
    }
    acc = (acc << 5) | value;
    bits += 5;
    while (bits >= 8 && written < SECRET_KEY_BYTES) {
      bits -= 8;
      bytes[written] = (acc >>> bits) & 0xff;
      written += 1;
      acc &= (1 << bits) - 1;
    }
  }

  // What remains is the checksum followed by the zero padding bits.
  const padBits = ENCODED_CHARS * 5 - SECRET_KEY_BYTES * 8 - CHECK_BITS;
  const expectedCheck = (acc >>> padBits) & ((1 << CHECK_BITS) - 1);
  const padding = acc & ((1 << padBits) - 1);

  if (padding !== 0 || expectedCheck !== crc16(bytes)) {
    throw new ValidationError(`That ${label} has a typo in it — check it against your Recovery Kit.`);
  }

  return bytes;
}

/** True when `input` parses cleanly. For live field validation, never for auth. */
export function isWellFormedSecret(kind: SecretKind, input: string): boolean {
  try {
    parseSecret(kind, input);
    return true;
  } catch {
    return false;
  }
}
