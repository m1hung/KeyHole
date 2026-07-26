/**
 * Typed errors. Callers must be able to distinguish "wrong password" from
 * "corrupt file" from "unsupported version" without string-matching, and none
 * of these messages may leak plaintext or key material.
 */

export class KeyholeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }
}

/**
 * Thrown when GCM authentication fails. This is deliberately the *only* signal
 * for a bad master password — we do not run a separate password check, so an
 * attacker learns nothing beyond "the tag did not verify".
 */
export class DecryptionError extends KeyholeError {
  constructor(message = 'Decryption failed: wrong master password or corrupted vault.') {
    super(message);
  }
}

/** The envelope is not a Keyhole vault, or failed schema validation. */
export class VaultFormatError extends KeyholeError {}

/** The envelope is a Keyhole vault, but from a version this build cannot read. */
export class UnsupportedVersionError extends KeyholeError {}

/** An operation required an unlocked vault. */
export class VaultLockedError extends KeyholeError {
  constructor(message = 'Vault is locked.') {
    super(message);
  }
}

/** Caller-supplied input failed a precondition (weak password, bad generator opts, ...). */
export class ValidationError extends KeyholeError {}
