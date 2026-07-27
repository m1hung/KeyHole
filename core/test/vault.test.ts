import { beforeAll, describe, expect, it } from 'vitest';
import {
  changeMasterPassword,
  createEntry,
  createFolder,
  createVault,
  deleteEntry,
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
import type { VaultFile } from '../src/types.ts';
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

  it('rejects a newer payload schema version', async () => {
    // Reached only after successful decryption, so it must be built legitimately.
    const created = await createVault(PASSWORD);
    created.session.data = { ...created.session.data, schemaVersion: 42 };
    const saved = await saveVault(created.session, created.file);
    await expect(unlockVault(saved, PASSWORD)).rejects.toThrow(UnsupportedVersionError);
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

    const deleted = deleteEntry(updated, entry.id);
    expect(deleted.entries).toHaveLength(0);
    expect(updated.entries).toHaveLength(1);
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
