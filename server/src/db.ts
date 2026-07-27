/**
 * Storage. Uses `node:sqlite`, which ships with Node — no native module to
 * compile, which matters for a thing people self-host on arbitrary hardware.
 *
 * The server stores the vault envelope as an opaque string. It never parses
 * the payload, never holds a key, and could not decrypt anything if it tried.
 * What it unavoidably *does* see is the envelope's public header: vault id,
 * format version, KDF parameters and timestamps. That is documented rather
 * than hidden, because a sync server that claims to see nothing at all would
 * be lying.
 */

import { DatabaseSync } from 'node:sqlite';
import { randomBytes } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

export interface AccountRow {
  accountId: string;
  verifierSalt: string;
  verifierHash: string;
  envelope: string;
  version: number;
  createdAt: string;
  updatedAt: string;
}

const SCHEMA = `
  PRAGMA journal_mode = WAL;
  PRAGMA foreign_keys = ON;

  CREATE TABLE IF NOT EXISTS accounts (
    account_id    TEXT PRIMARY KEY,
    verifier_salt TEXT NOT NULL,
    verifier_hash TEXT NOT NULL,
    envelope      TEXT NOT NULL,
    -- Monotonic. Every accepted write increments it; it never decreases, which
    -- is what lets a client detect a server trying to roll it back.
    version       INTEGER NOT NULL,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
  );
`;

export class Store {
  private readonly db: DatabaseSync;

  constructor(path: string) {
    if (path !== ':memory:') mkdirSync(dirname(path), { recursive: true });
    this.db = new DatabaseSync(path);
    this.db.exec(SCHEMA);
  }

  close(): void {
    this.db.close();
  }

  /**
   * Server-wide secret used to fabricate stable decoy KDF parameters for
   * accounts that do not exist. Generated once and persisted, so an attacker
   * cannot tell a real account from a fake one by watching the salt change.
   */
  pepper(): Uint8Array {
    const row = this.db.prepare('SELECT value FROM meta WHERE key = ?').get('pepper') as
      | { value: string }
      | undefined;
    if (row) return Buffer.from(row.value, 'base64');

    const fresh = randomBytes(32);
    this.db.prepare('INSERT INTO meta (key, value) VALUES (?, ?)').run('pepper', fresh.toString('base64'));
    return fresh;
  }

  get(accountId: string): AccountRow | undefined {
    const row = this.db.prepare('SELECT * FROM accounts WHERE account_id = ?').get(accountId) as
      | Record<string, string | number>
      | undefined;
    if (!row) return undefined;
    return {
      accountId: String(row['account_id']),
      verifierSalt: String(row['verifier_salt']),
      verifierHash: String(row['verifier_hash']),
      envelope: String(row['envelope']),
      version: Number(row['version']),
      createdAt: String(row['created_at']),
      updatedAt: String(row['updated_at']),
    };
  }

  create(account: Omit<AccountRow, 'version' | 'createdAt' | 'updatedAt'>): AccountRow {
    const now = new Date().toISOString();
    this.db
      .prepare(
        `INSERT INTO accounts (account_id, verifier_salt, verifier_hash, envelope, version, created_at, updated_at)
         VALUES (?, ?, ?, ?, 1, ?, ?)`,
      )
      .run(account.accountId, account.verifierSalt, account.verifierHash, account.envelope, now, now);
    return { ...account, version: 1, createdAt: now, updatedAt: now };
  }

  /**
   * Compare-and-swap the envelope.
   *
   * Returns undefined when `expectedVersion` does not match, which is the
   * conflict signal: another device wrote first, and this client must pull,
   * merge and retry. Doing the check inside the UPDATE's WHERE clause makes it
   * atomic — two simultaneous writers cannot both succeed.
   */
  replaceEnvelope(accountId: string, envelope: string, expectedVersion: number): AccountRow | undefined {
    const now = new Date().toISOString();
    const result = this.db
      .prepare(
        `UPDATE accounts SET envelope = ?, version = version + 1, updated_at = ?
         WHERE account_id = ? AND version = ?`,
      )
      .run(envelope, now, accountId, expectedVersion);

    if (result.changes === 0) return undefined;
    return this.get(accountId);
  }
}
