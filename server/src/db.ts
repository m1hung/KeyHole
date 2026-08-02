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

/** One row of the dashboard roster. No credential material, by construction. */
export interface AccountSummary {
  accountId: string;
  version: number;
  createdAt: string;
  updatedAt: string;
  /**
   * Size of the stored envelope in bytes.
   *
   * Measured with `length(CAST(envelope AS BLOB))`, not `length(envelope)`:
   * SQLite's length() over TEXT counts characters, and JSON.stringify does not
   * escape non-ASCII, so any envelope containing a multi-byte character would
   * otherwise report short. (octet_length() would say this more clearly but
   * needs SQLite 3.43+, which the engines floor does not guarantee.)
   */
  envelopeBytes: number;
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

  /**
   * Write a consistent snapshot of the whole database to `destination`.
   *
   * WAL mode means copying the `.sqlite` file out from under a running server
   * can miss committed data — `VACUUM INTO` is SQLite's own answer, needs no
   * downtime, and produces a single file with no `-wal`/`-shm` beside it.
   *
   * `node:sqlite` is synchronous, so this blocks the event loop for roughly a
   * full read-and-write of the database. That is what makes the snapshot
   * trivially consistent — nothing else in this process can interleave a write
   * — and also the reason a large database will stall requests while it runs.
   *
   * The destination must not already exist; SQLite refuses to overwrite, and
   * the backup route relies on that rather than checking separately.
   */
  backupTo(destination: string): void {
    this.db.prepare('VACUUM INTO ?').run(destination);
  }

  /** How many accounts are enrolled — for the status page only. */
  accountCount(): number {
    const row = this.db.prepare('SELECT COUNT(*) AS n FROM accounts').get() as { n: number };
    return Number(row.n);
  }

  /**
   * Enrolled accounts, for the dashboard's roster.
   *
   * Deliberately does not select the verifier salt or hash: a list method that
   * returned them would eventually get rendered by accident. `limit` is not a
   * pagination story, it is a ceiling — measuring every envelope means reading
   * every envelope, and they can be 16 MB each.
   */
  list(limit = 100): AccountSummary[] {
    const rows = this.db
      .prepare(
        `SELECT account_id, version, created_at, updated_at,
                length(CAST(envelope AS BLOB)) AS envelope_bytes
         FROM accounts ORDER BY created_at ASC LIMIT ?`,
      )
      .all(limit) as Record<string, string | number>[];

    return rows.map((row) => ({
      accountId: String(row['account_id']),
      version: Number(row['version']),
      createdAt: String(row['created_at']),
      updatedAt: String(row['updated_at']),
      envelopeBytes: Number(row['envelope_bytes']),
    }));
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
   *
   * Optional verifier rotation: used when a device overwrites the account with
   * a different vault (new KDF salt → new auth secret).
   */
  replaceEnvelope(
    accountId: string,
    envelope: string,
    expectedVersion: number,
    verifier?: { salt: string; hash: string },
  ): AccountRow | undefined {
    const now = new Date().toISOString();
    if (verifier) {
      const result = this.db
        .prepare(
          `UPDATE accounts
           SET envelope = ?, version = version + 1, updated_at = ?,
               verifier_salt = ?, verifier_hash = ?
           WHERE account_id = ? AND version = ?`,
        )
        .run(envelope, now, verifier.salt, verifier.hash, accountId, expectedVersion);
      if (result.changes === 0) return undefined;
      return this.get(accountId);
    }

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
