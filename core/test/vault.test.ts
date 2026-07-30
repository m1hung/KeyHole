import { beforeAll, describe, expect, it } from 'vitest';
import {
  changeMasterPassword,
  createEntry,
  createFolder,
  createVault,
  deleteEntry,
  deleteEntries,
  purgeEntry,
  purgeExpiredTrash,
  restoreEntry,
  trashedEntries,
  deleteFolder,
  emptyVaultData,
  getEntry,
  saveVault,
  searchEntries,
  unlockVault,
  updateEntry,
  updateSettings,
} from '../src/vault.ts';
import { DecryptionError, UnsupportedVersionError, ValidationError, VaultFormatError } from '../src/errors.ts';
import { PASSWORD_HISTORY_LIMIT, TRASH_RETENTION_DAYS, MAX_ATTACHMENT_BYTES, type VaultFile } from '../src/types.ts';
import { bytesToB64 } from '../src/encoding.ts';
import { randomBytes } from '../src/crypto.ts';
import { parseVaultData } from '../src/validation.ts';

const PASSWORD = 'correct horse battery staple';
const WRONG = 'correct horse battery stapl3';

describe('vault lifecycle', () => {
  it('creates → adds an entry → locks → unlocks → reads the entry back', async () => {
    const { file, session } = await createVault(PASSWORD);
    const { data } = createEntry(session.data, {
      title: 'GitHub',
      username: 'octocat',
      password: 's3cr3t-p@ssw0rd',
      urls: ['https://github.com/login'],
      notes: 'recovery codes in the safe',
      tags: ['dev'],
    });
    session.data = data;
    const saved = await saveVault(session, file);

    // Lock == drop the session entirely. Only `saved` survives.
    const reopened = await unlockVault(saved, PASSWORD);
    expect(reopened.data.entries).toHaveLength(1);
    const entry = reopened.data.entries[0]!;
    expect(entry.title).toBe('GitHub');
    expect(entry.username).toBe('octocat');
    expect(entry.password).toBe('s3cr3t-p@ssw0rd');
    expect(entry.notes).toBe('recovery codes in the safe');
  });

  it('never writes plaintext into the envelope', async () => {
    const { file, session } = await createVault(PASSWORD);
    session.data = createEntry(session.data, {
      title: 'Bank of Test',
      username: 'jdoe@example.com',
      password: 'HIGHLY-IDENTIFIABLE-SECRET-42',
      notes: 'sensitive note text',
    }).data;
    const saved = await saveVault(session, file);

    const serialized = JSON.stringify(saved);
    for (const secret of ['HIGHLY-IDENTIFIABLE-SECRET-42', 'jdoe@example.com', 'Bank of Test', 'sensitive note text', PASSWORD]) {
      expect(serialized).not.toContain(secret);
    }
  });

  it('rejects the wrong master password with DecryptionError', async () => {
    const { file } = await createVault(PASSWORD);
    await expect(unlockVault(file, WRONG)).rejects.toThrow(DecryptionError);
  });

  it('fails closed: a wrong password yields no partial data', async () => {
    const { file, session } = await createVault(PASSWORD);
    session.data = createEntry(session.data, { title: 'Secret', password: 'p' }).data;
    const saved = await saveVault(session, file);

    const result = await unlockVault(saved, WRONG).catch((e: unknown) => e);
    expect(result).toBeInstanceOf(DecryptionError);
    expect(result).not.toHaveProperty('data');
  });

  it('enforces a minimum master password length', async () => {
    await expect(createVault('short')).rejects.toThrow(ValidationError);
  });

  it('gives every vault a distinct id and salt', async () => {
    const a = await createVault(PASSWORD);
    const b = await createVault(PASSWORD);
    expect(a.file.vaultId).not.toBe(b.file.vaultId);
    expect(a.file.kdf.saltB64).not.toBe(b.file.kdf.saltB64);
    // Same password, different salt ⇒ ciphertexts must not correlate.
    expect(a.file.wrappedKey.ctB64).not.toBe(b.file.wrappedKey.ctB64);
  });

  it('rotates the payload nonce on every save', async () => {
    const { file, session } = await createVault(PASSWORD);
    const first = await saveVault(session, file);
    const second = await saveVault(session, first);
    expect(first.payload.ivB64).not.toBe(second.payload.ivB64);
    expect(first.payload.ctB64).not.toBe(second.payload.ctB64);
  });

  it('does not re-run the KDF on save', async () => {
    const { file, session } = await createVault(PASSWORD);
    const saved = await saveVault(session, file);
    expect(saved.kdf).toEqual(file.kdf);
    expect(saved.wrappedKey).toEqual(file.wrappedKey);
  });

  it('refuses to save a session into a different vault file', async () => {
    const a = await createVault(PASSWORD);
    const b = await createVault(PASSWORD);
    await expect(saveVault(a.session, b.file)).rejects.toThrow(ValidationError);
  });
});

describe('tamper resistance', () => {
  let file: VaultFile;
  beforeAll(async () => {
    const created = await createVault(PASSWORD);
    created.session.data = createEntry(created.session.data, { title: 'X', password: 'y' }).data;
    file = await saveVault(created.session, created.file);
  });

  it('detects a downgraded KDF cost', async () => {
    const tampered = { ...file, kdf: { ...file.kdf, memoryKiB: 1024, iterations: 1 } };
    await expect(unlockVault(tampered, PASSWORD)).rejects.toThrow();
  });

  it('detects a swapped vault id', async () => {
    const tampered = { ...file, vaultId: '99999999-9999-4999-8999-999999999999' };
    await expect(unlockVault(tampered, PASSWORD)).rejects.toThrow(DecryptionError);
  });

  it('detects a wrapped key spliced in from another vault', async () => {
    const other = await createVault(PASSWORD);
    const tampered = { ...file, wrappedKey: other.file.wrappedKey };
    await expect(unlockVault(tampered, PASSWORD)).rejects.toThrow(DecryptionError);
  });

  it('detects a payload spliced in from another vault', async () => {
    const other = await createVault(PASSWORD);
    const tampered = { ...file, payload: other.file.payload };
    await expect(unlockVault(tampered, PASSWORD)).rejects.toThrow(DecryptionError);
  });

  it('detects a corrupted payload', async () => {
    const tampered = { ...file, payload: { ...file.payload, ctB64: bytesToB64(randomBytes(128)) } };
    await expect(unlockVault(tampered, PASSWORD)).rejects.toThrow(DecryptionError);
  });

  it('rejects a non-Keyhole file', async () => {
    await expect(unlockVault({ hello: 'world' }, PASSWORD)).rejects.toThrow(VaultFormatError);
    await expect(unlockVault(null, PASSWORD)).rejects.toThrow(VaultFormatError);
    await expect(unlockVault('not json', PASSWORD)).rejects.toThrow(VaultFormatError);
  });

  it('rejects unknown fields in the envelope', async () => {
    await expect(unlockVault({ ...file, backdoor: true }, PASSWORD)).rejects.toThrow(VaultFormatError);
  });

  it('rejects a newer format version with an actionable error', async () => {
    const future = { ...file, formatVersion: 99 };
    const err = await unlockVault(future, PASSWORD).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(UnsupportedVersionError);
    expect((err as Error).message).toMatch(/newer version of Keyhole/);
  });

  /**
   * A newer *payload* is opened, not refused — the envelope is what must match.
   * Refusing here used to mean that one device writing a new schema locked every
   * device that had not updated out of the vault.
   */
  describe('a payload written by a newer build', () => {
    /** Build a v-next payload the only way it can legitimately exist: encrypted. */
    const writeFutureVault = async (mutate: (data: Record<string, unknown>) => Record<string, unknown>) => {
      const created = await createVault(PASSWORD);
      created.session.data = mutate({
        ...created.session.data,
        schemaVersion: 42,
      }) as unknown as typeof created.session.data;
      return saveVault(created.session, created.file);
    };

    it('opens, and reports how far ahead it is', async () => {
      const saved = await writeFutureVault((data) => data);
      const session = await unlockVault(saved, PASSWORD);
      expect(session.foreignSchemaVersion).toBe(42);
      // Not relabelled as ours: the next reader must not be told the extra fields
      // it cannot see are absent.
      expect(session.data.schemaVersion).toBe(42);
    });

    it('reports null for a schema this build knows', async () => {
      const { session } = await createVault(PASSWORD);
      expect(session.foreignSchemaVersion).toBeNull();
    });

    it('preserves fields it does not understand across a save', async () => {
      const saved = await writeFutureVault((data) => ({
        ...data,
        entries: [
          {
            id: '11111111-1111-4111-8111-111111111111',
            kind: 'login',
            title: 'Written by v-next',
            username: 'someone',
            password: 'secret',
            urls: ['https://example.com'],
            notes: '',
            tags: [],
            folderId: null,
            totpSecret: null,
            createdAt: '2026-01-01T00:00:00.000Z',
            updatedAt: '2026-01-01T00:00:00.000Z',
            passwordUpdatedAt: '2026-01-01T00:00:00.000Z',
            // The point of the test: this build has never heard of either.
            history: [{ password: 'previous-one', changedAt: '2025-06-01T00:00:00.000Z' }],
            deletedAt: null,
          },
        ],
        futureTopLevelKey: { anything: true },
      }));

      const session = await unlockVault(saved, PASSWORD);
      const entry = session.data.entries[0] as unknown as Record<string, unknown>;
      expect(entry['title']).toBe('Written by v-next');
      expect(entry['history']).toEqual([{ password: 'previous-one', changedAt: '2025-06-01T00:00:00.000Z' }]);
      expect(entry['deletedAt']).toBeNull();

      // Round-trip through this build: an older reader must not strip what a newer
      // writer put there, or syncing through a stale device destroys data.
      const resaved = await saveVault(session, saved);
      const reopened = await unlockVault(resaved, PASSWORD);
      const reopenedEntry = reopened.data.entries[0] as unknown as Record<string, unknown>;
      expect(reopenedEntry['history']).toEqual([{ password: 'previous-one', changedAt: '2025-06-01T00:00:00.000Z' }]);
      expect((reopened.data as unknown as Record<string, unknown>)['futureTopLevelKey']).toEqual({ anything: true });
      expect(reopened.foreignSchemaVersion).toBe(42);
    });

    it('still rejects a payload that is actually malformed', async () => {
      // Tolerating extra keys must not mean tolerating a broken known field.
      const saved = await writeFutureVault((data) => ({
        ...data,
        entries: [{ id: 'not-a-uuid', title: 5 }],
      }));
      await expect(unlockVault(saved, PASSWORD)).rejects.toThrow(VaultFormatError);
    });
  });
});

describe('change master password', () => {
  it('re-keys the vault and invalidates the old password', async () => {
    const NEW = 'a-completely-different-master-passphrase';
    const created = await createVault(PASSWORD);
    created.session.data = createEntry(created.session.data, {
      title: 'Preserved',
      password: 'keep-me',
    }).data;
    const original = await saveVault(created.session, created.file);

    const { file: rekeyed } = await changeMasterPassword(original, PASSWORD, NEW);

    await expect(unlockVault(rekeyed, PASSWORD)).rejects.toThrow(DecryptionError);
    const unlocked = await unlockVault(rekeyed, NEW);
    expect(unlocked.data.entries[0]?.password).toBe('keep-me');
  });

  it('rotates salt, wrapped key and payload', async () => {
    const created = await createVault(PASSWORD);
    const { file: rekeyed } = await changeMasterPassword(created.file, PASSWORD, 'another-good-master-password');
    expect(rekeyed.kdf.saltB64).not.toBe(created.file.kdf.saltB64);
    expect(rekeyed.wrappedKey.ctB64).not.toBe(created.file.wrappedKey.ctB64);
    expect(rekeyed.payload.ctB64).not.toBe(created.file.payload.ctB64);
    expect(rekeyed.vaultId).toBe(created.file.vaultId);
  });

  it('requires the current password', async () => {
    const { file } = await createVault(PASSWORD);
    await expect(changeMasterPassword(file, WRONG, 'a-new-master-password-here')).rejects.toThrow(DecryptionError);
  });

  it('enforces the strength floor on the new password', async () => {
    const { file } = await createVault(PASSWORD);
    await expect(changeMasterPassword(file, PASSWORD, 'weak')).rejects.toThrow(ValidationError);
  });
});

describe('entry CRUD', () => {
  it('creates, updates and deletes without mutating the input', () => {
    const original = emptyVaultData();
    const { data: added, entry } = createEntry(original, { title: 'Site', password: 'a' });
    expect(original.entries).toHaveLength(0); // input untouched
    expect(added.entries).toHaveLength(1);
    expect(entry.kind).toBe('login');

    const updated = updateEntry(added, entry.id, { title: 'Renamed', password: 'b' });
    expect(added.entries[0]?.title).toBe('Site');
    expect(getEntry(updated, entry.id)?.title).toBe('Renamed');

    // Deleting is now reversible: the entry stays, marked, until it is purged.
    const deleted = deleteEntry(updated, entry.id);
    expect(deleted.entries).toHaveLength(1);
    expect(deleted.entries[0]?.deletedAt).not.toBeNull();
    expect(updated.entries[0]?.deletedAt).toBeNull();

    const purged = purgeEntry(deleted, entry.id);
    expect(purged.entries).toHaveLength(0);
    expect(deleted.entries).toHaveLength(1);
  });

  it('creates a secure note with kind note', () => {
    const { entry } = createEntry(emptyVaultData(), { title: 'Safe deposit', kind: 'note', notes: 'box 12' });
    expect(entry.kind).toBe('note');
    expect(entry.password).toBe('');
  });

  it('defaults missing kind to login when parsing vault data', () => {
    const raw = {
      schemaVersion: 1,
      entries: [
        {
          id: '11111111-1111-4111-8111-111111111111',
          title: 'Legacy',
          username: 'a',
          password: 'b',
          urls: [],
          notes: '',
          tags: [],
          folderId: null,
          totpSecret: null,
          createdAt: '2026-01-01T00:00:00.000Z',
          updatedAt: '2026-01-01T00:00:00.000Z',
          passwordUpdatedAt: '2026-01-01T00:00:00.000Z',
        },
      ],
      folders: [],
      settings: {
        autoLockMinutes: 15,
        clipboardClearSeconds: 30,
        generator: {
          length: 20,
          lowercase: true,
          uppercase: true,
          digits: true,
          symbols: true,
          excludeAmbiguous: false,
        },
        theme: 'system' as const,
        lockOnHide: false,
      },
      updatedAt: '2026-01-01T00:00:00.000Z',
    };
    expect(parseVaultData(raw).entries[0]?.kind).toBe('login');
  });

  it('tracks passwordUpdatedAt only when the password actually changes', async () => {
    const { data, entry } = createEntry(emptyVaultData(), { title: 'S', password: 'original' });
    await new Promise((r) => setTimeout(r, 5));

    const renamed = updateEntry(data, entry.id, { title: 'Renamed' });
    expect(getEntry(renamed, entry.id)?.passwordUpdatedAt).toBe(entry.passwordUpdatedAt);

    const rotated = updateEntry(data, entry.id, { password: 'rotated' });
    expect(getEntry(rotated, entry.id)?.passwordUpdatedAt).not.toBe(entry.passwordUpdatedAt);
  });

  it('rejects an empty title', () => {
    expect(() => createEntry(emptyVaultData(), { title: '   ' })).toThrow(ValidationError);
  });

  it('rejects operations on an unknown id', () => {
    expect(() => updateEntry(emptyVaultData(), 'nope', { title: 'x' })).toThrow(ValidationError);
    expect(() => deleteEntry(emptyVaultData(), 'nope')).toThrow(ValidationError);
  });

  it('orphans entries instead of deleting them when a folder is removed', () => {
    const { data: withFolder, folder } = createFolder(emptyVaultData(), 'Work');
    const { data } = createEntry(withFolder, { title: 'In folder', folderId: folder.id });
    const after = deleteFolder(data, folder.id);
    expect(after.folders).toHaveLength(0);
    expect(after.entries).toHaveLength(1);
    expect(after.entries[0]?.folderId).toBeNull();
  });

  it('persists settings changes through a lock/unlock cycle', async () => {
    const { file, session } = await createVault(PASSWORD);
    session.data = updateSettings(session.data, { autoLockMinutes: 3, clipboardClearSeconds: 10 });
    const saved = await saveVault(session, file);
    const reopened = await unlockVault(saved, PASSWORD);
    expect(reopened.data.settings.autoLockMinutes).toBe(3);
    expect(reopened.data.settings.clipboardClearSeconds).toBe(10);
  });
});

describe('search', () => {
  const build = () => {
    let data = emptyVaultData();
    data = createEntry(data, { title: 'GitHub', username: 'octocat', urls: ['https://github.com'], tags: ['dev'] }).data;
    data = createEntry(data, { title: 'Gitlab', username: 'fox', urls: ['https://gitlab.com'], tags: ['dev'] }).data;
    data = createEntry(data, { title: 'Bank', username: 'jdoe', password: 'uniquepassword123', notes: 'secret memo' }).data;
    return data;
  };

  it('matches title, username, url and tag', () => {
    const data = build();
    expect(searchEntries(data, 'git').map((e) => e.title)).toEqual(['GitHub', 'Gitlab']);
    expect(searchEntries(data, 'octocat').map((e) => e.title)).toEqual(['GitHub']);
    expect(searchEntries(data, 'gitlab.com').map((e) => e.title)).toEqual(['Gitlab']);
    expect(searchEntries(data, 'dev')).toHaveLength(2);
  });

  it('never matches on password or login notes', () => {
    const data = build();
    expect(searchEntries(data, 'uniquepassword123')).toHaveLength(0);
    expect(searchEntries(data, 'secret memo')).toHaveLength(0);
  });

  it('matches notes on secure-note entries only', () => {
    let data = emptyVaultData();
    data = createEntry(data, { title: 'Wifi', kind: 'note', notes: 'router passphrase north-wind' }).data;
    data = createEntry(data, { title: 'Bank', password: 'x', notes: 'router passphrase north-wind' }).data;
    expect(searchEntries(data, 'north-wind').map((e) => e.title)).toEqual(['Wifi']);
  });

  it('returns everything, sorted, for an empty query', () => {
    expect(searchEntries(build(), '  ').map((e) => e.title)).toEqual(['Bank', 'GitHub', 'Gitlab']);
  });

  it('is case-insensitive', () => {
    expect(searchEntries(build(), 'GITHUB')).toHaveLength(1);
  });

  it('matches custom field labels but never their values', () => {
    let data = emptyVaultData();
    data = createEntry(data, {
      title: 'Bank',
      customFields: [
        {
          id: '11111111-1111-4111-8111-111111111111',
          label: 'PIN hint',
          value: 'mothers-maiden-secret',
          secret: true,
        },
      ],
    }).data;
    expect(searchEntries(data, 'pin hint').map((e) => e.title)).toEqual(['Bank']);
    expect(searchEntries(data, 'mothers-maiden-secret')).toHaveLength(0);
  });
});

describe('cross-surface interoperability', () => {
  /**
   * Swift synthesises `encodeIfPresent` for optional properties, so the iOS build
   * omits `folderId` / `totpSecret` rather than writing an explicit null. Requiring
   * them present made every vault iOS saved unreadable here — almost no entry has a
   * TOTP secret — so absent and null must both be accepted.
   */
  it('accepts an entry whose null-valued keys were omitted, as iOS writes them', () => {
    const iosStyleEntry = {
      id: '11111111-1111-4111-8111-111111111111',
      kind: 'login',
      title: 'Saved on iPhone',
      username: 'someone',
      password: 'secret',
      urls: ['https://example.com'],
      notes: '',
      tags: [],
      createdAt: '2026-01-01T00:00:00.000Z',
      updatedAt: '2026-01-01T00:00:00.000Z',
      passwordUpdatedAt: '2026-01-01T00:00:00.000Z',
      // folderId and totpSecret deliberately absent.
    };
    const data = parseVaultData({
      schemaVersion: 2,
      entries: [iosStyleEntry],
      folders: [],
      tombstones: [],
      settings: emptyVaultData().settings,
      updatedAt: '2026-01-01T00:00:00.000Z',
    });
    expect(data.entries[0]?.folderId).toBeNull();
    expect(data.entries[0]?.totpSecret).toBeNull();
  });

  it('still rejects those keys when they carry the wrong type', () => {
    const base = {
      schemaVersion: 2,
      folders: [],
      tombstones: [],
      settings: emptyVaultData().settings,
      updatedAt: '2026-01-01T00:00:00.000Z',
    };
    const entry = {
      id: '11111111-1111-4111-8111-111111111111',
      kind: 'login',
      title: 'Bad',
      username: '',
      password: '',
      urls: [],
      notes: '',
      tags: [],
      createdAt: '2026-01-01T00:00:00.000Z',
      updatedAt: '2026-01-01T00:00:00.000Z',
      passwordUpdatedAt: '2026-01-01T00:00:00.000Z',
      folderId: 42,
    };
    expect(() => parseVaultData({ ...base, entries: [entry] })).toThrow(VaultFormatError);
  });
});

describe('round-trip fidelity', () => {
  it('preserves unicode, newlines and long values', async () => {
    const { file, session } = await createVault(PASSWORD);
    const notes = 'line 1\nline 2\t🔐 emoji\n"quotes" & <tags>\\backslash';
    const password = 'ü'.repeat(200) + '🔑';
    session.data = createEntry(session.data, { title: '日本語 タイトル', password, notes }).data;

    const reopened = await unlockVault(await saveVault(session, file), PASSWORD);
    expect(reopened.data.entries[0]?.notes).toBe(notes);
    expect(reopened.data.entries[0]?.password).toBe(password);
    expect(reopened.data.entries[0]?.title).toBe('日本語 タイトル');
  });

  it('survives JSON serialization of the envelope', async () => {
    const { file, session } = await createVault(PASSWORD);
    session.data = createEntry(session.data, { title: 'Export me', password: 'p@ss' }).data;
    const saved = await saveVault(session, file);

    // Exactly what export→import does.
    const reloaded = JSON.parse(JSON.stringify(saved)) as unknown;
    const unlocked = await unlockVault(reloaded, PASSWORD);
    expect(unlocked.data.entries[0]?.password).toBe('p@ss');
  });

  it('handles a vault with many entries', async () => {
    const { file, session } = await createVault(PASSWORD);
    let data = session.data;
    for (let i = 0; i < 500; i += 1) {
      data = createEntry(data, { title: `Entry ${i}`, username: `user${i}`, password: `pw-${i}` }).data;
    }
    session.data = data;
    const reopened = await unlockVault(await saveVault(session, file), PASSWORD);
    expect(reopened.data.entries).toHaveLength(500);
    expect(reopened.data.entries[499]?.password).toBe('pw-499');
  });
});

describe('password history', () => {
  it('keeps the superseded password when one is replaced', () => {
    const { data, entry } = createEntry(emptyVaultData(), { title: 'Bank', password: 'first' });
    expect(entry.history).toEqual([]);

    const rotated = updateEntry(data, entry.id, { password: 'second' });
    const history = getEntry(rotated, entry.id)?.history ?? [];
    expect(history.map((h) => h.password)).toEqual(['first']);
    expect(getEntry(rotated, entry.id)?.password).toBe('second');
  });

  it('records nothing when the password is unchanged or absent', () => {
    const { data, entry } = createEntry(emptyVaultData(), { title: 'Bank', password: 'same' });
    const renamed = updateEntry(data, entry.id, { title: 'Bank renamed' });
    expect(getEntry(renamed, entry.id)?.history).toEqual([]);

    const rewritten = updateEntry(data, entry.id, { password: 'same' });
    expect(getEntry(rewritten, entry.id)?.history).toEqual([]);

    // An entry that never had a password has nothing to remember.
    const { data: noteData, entry: note } = createEntry(emptyVaultData(), { title: 'Note', kind: 'note' });
    const given = updateEntry(noteData, note.id, { password: 'first-ever' });
    expect(getEntry(given, note.id)?.history).toEqual([]);
  });

  it('keeps newest first and caps the list', () => {
    let data = createEntry(emptyVaultData(), { title: 'Rotated often', password: 'pw-0' }).data;
    const id = data.entries[0]!.id;
    for (let i = 1; i <= PASSWORD_HISTORY_LIMIT + 5; i += 1) {
      data = updateEntry(data, id, { password: `pw-${i}` });
    }
    const history = getEntry(data, id)?.history ?? [];
    expect(history).toHaveLength(PASSWORD_HISTORY_LIMIT);
    // Newest supersession first, oldest dropped off the end.
    expect(history[0]?.password).toBe(`pw-${PASSWORD_HISTORY_LIMIT + 4}`);
    expect(history.map((h) => h.password)).not.toContain('pw-0');
  });

  it('survives a save/unlock round trip', async () => {
    const { file, session } = await createVault(PASSWORD);
    session.data = createEntry(session.data, { title: 'Bank', password: 'first' }).data;
    const id = session.data.entries[0]!.id;
    session.data = updateEntry(session.data, id, { password: 'second' });

    const reopened = await unlockVault(await saveVault(session, file), PASSWORD);
    expect(reopened.data.entries[0]?.history.map((h) => h.password)).toEqual(['first']);
  });
});

describe('trash', () => {
  const build = () => {
    const { data, entry } = createEntry(emptyVaultData(), {
      title: 'Binned',
      password: 'p',
      urls: ['https://example.com'],
    });
    return { data: deleteEntry(data, entry.id), id: entry.id };
  };

  it('hides trashed entries from search but lists them in the trash', () => {
    const { data, id } = build();
    expect(searchEntries(data, '')).toHaveLength(0);
    expect(searchEntries(data, 'Binned')).toHaveLength(0);
    expect(trashedEntries(data).map((e) => e.id)).toEqual([id]);
  });

  it('restores an entry back into the list', () => {
    const { data, id } = build();
    const restored = restoreEntry(data, id);
    expect(searchEntries(restored, '')).toHaveLength(1);
    expect(trashedEntries(restored)).toHaveLength(0);
    expect(getEntry(restored, id)?.deletedAt).toBeNull();
  });

  it('is idempotent in both directions', () => {
    const { data, id } = build();
    expect(deleteEntry(data, id)).toBe(data);
    const restored = restoreEntry(data, id);
    expect(restoreEntry(restored, id)).toBe(restored);
  });

  it('purges only what has sat past the retention window', () => {
    const { data, id } = build();
    const dayMs = 24 * 60 * 60 * 1000;
    const deletedAtMs = Date.parse(getEntry(data, id)!.deletedAt!);

    // One day short of the window: still restorable.
    const early = purgeExpiredTrash(data, deletedAtMs + (TRASH_RETENTION_DAYS - 1) * dayMs);
    expect(early.entries).toHaveLength(1);
    expect(early.tombstones).toHaveLength(0);

    // Past it: gone, with a tombstone so peers do not resurrect it.
    const swept = purgeExpiredTrash(data, deletedAtMs + (TRASH_RETENTION_DAYS + 1) * dayMs);
    expect(swept.entries).toHaveLength(0);
    expect(swept.tombstones.map((t) => t.id)).toEqual([id]);
  });

  it('leaves live entries alone no matter how old', () => {
    const { data } = createEntry(emptyVaultData(), { title: 'Ancient', password: 'p' });
    const swept = purgeExpiredTrash(data, Date.now() + 10 * 365 * 24 * 60 * 60 * 1000);
    expect(swept).toBe(data);
  });
});

describe('deleteEntries', () => {
  const three = () => {
    let data = emptyVaultData();
    const ids: string[] = [];
    for (const title of ['A', 'B', 'C']) {
      const result = createEntry(data, { title, password: 'p' });
      data = result.data;
      ids.push(result.entry.id);
    }
    return { data, ids };
  };

  it('bins exactly the named entries, in one stamp', () => {
    const { data, ids } = three();
    const binned = deleteEntries(data, [ids[0]!, ids[2]!]);

    expect(trashedEntries(binned).map((e) => e.title).sort()).toEqual(['A', 'C']);
    expect(getEntry(binned, ids[1]!)?.deletedAt).toBeNull();
    // One user action, one moment — not N timestamps milliseconds apart.
    expect(getEntry(binned, ids[0]!)!.deletedAt).toBe(getEntry(binned, ids[2]!)!.deletedAt);
  });

  it('skips unknown and already-trashed ids instead of failing the batch', () => {
    const { data, ids } = three();
    const first = deleteEntry(data, ids[0]!);
    // A is already gone and the uuid is a stranger; B must still be binned.
    const binned = deleteEntries(first, [ids[0]!, ids[1]!, 'not-a-real-id']);

    expect(trashedEntries(binned).map((e) => e.title).sort()).toEqual(['A', 'B']);
    // The earlier deletion keeps its own timestamp rather than being re-stamped.
    expect(getEntry(binned, ids[0]!)!.deletedAt).toBe(getEntry(first, ids[0]!)!.deletedAt);
  });

  it('is a no-op when nothing would change', () => {
    const { data, ids } = three();
    expect(deleteEntries(data, [])).toBe(data);
    expect(deleteEntries(data, ['nope'])).toBe(data);
    const binned = deleteEntries(data, ids);
    expect(deleteEntries(binned, ids)).toBe(binned);
  });

  it('leaves the deleted entries restorable and searchable again', () => {
    const { data, ids } = three();
    const binned = deleteEntries(data, ids);
    expect(searchEntries(binned, '')).toHaveLength(0);
    expect(searchEntries(restoreEntry(binned, ids[1]!), '')).toHaveLength(1);
    // No tombstones: a bulk trash is reversible, unlike purge.
    expect(binned.tombstones).toHaveLength(0);
  });
});

describe('schema 4 fields', () => {
  it('defaults totpConfig, customFields, attachments and breachCheckEnabled on a schema-3 payload', () => {
    const raw = {
      schemaVersion: 3,
      entries: [
        {
          id: '11111111-1111-4111-8111-111111111111',
          kind: 'login',
          title: 'Legacy v3',
          username: 'a',
          password: 'b',
          urls: [],
          notes: '',
          tags: [],
          folderId: null,
          totpSecret: null,
          createdAt: '2026-01-01T00:00:00.000Z',
          updatedAt: '2026-01-01T00:00:00.000Z',
          passwordUpdatedAt: '2026-01-01T00:00:00.000Z',
          history: [],
          deletedAt: null,
        },
      ],
      folders: [],
      tombstones: [],
      settings: {
        autoLockMinutes: 15,
        clipboardClearSeconds: 30,
        generator: {
          length: 20,
          lowercase: true,
          uppercase: true,
          digits: true,
          symbols: true,
          excludeAmbiguous: false,
        },
        theme: 'system',
        lockOnHide: false,
      },
      updatedAt: '2026-01-01T00:00:00.000Z',
    };
    const data = parseVaultData(raw);
    expect(data.entries[0]?.totpConfig).toBeNull();
    expect(data.entries[0]?.customFields).toEqual([]);
    expect(data.entries[0]?.attachments).toEqual([]);
    expect(data.settings.breachCheckEnabled).toBe(false);
  });

  it('stores totpConfig and custom fields through create/update', () => {
    const { data, entry } = createEntry(emptyVaultData(), {
      title: 'With extras',
      totpSecret: 'JBSWY3DPEHPK3PXP',
      totpConfig: { digits: 8, periodSeconds: 60, algorithm: 'SHA-1' },
      customFields: [
        {
          id: '22222222-2222-4222-8222-222222222222',
          label: 'Security question',
          value: 'blue',
          secret: false,
        },
      ],
    });
    expect(entry.totpConfig?.digits).toBe(8);
    expect(entry.customFields[0]?.label).toBe('Security question');

    const updated = updateEntry(data, entry.id, {
      customFields: [
        {
          id: '22222222-2222-4222-8222-222222222222',
          label: 'Security question',
          value: 'green',
          secret: false,
        },
      ],
    });
    expect(getEntry(updated, entry.id)?.customFields[0]?.value).toBe('green');
  });

  it('refuses an attachment over the per-file budget', () => {
    expect(() =>
      createEntry(emptyVaultData(), {
        title: 'Too big',
        attachments: [
          {
            id: '33333333-3333-4333-8333-333333333333',
            name: 'huge.bin',
            mimeType: 'application/octet-stream',
            sizeBytes: MAX_ATTACHMENT_BYTES + 1,
            dataB64: 'AA==',
          },
        ],
      }),
    ).toThrow(ValidationError);
  });
});
