import { describe, expect, it } from 'vitest';
import { applyMigration, parseBitwardenJson, parseCsvMigration, parseMigrationPayload } from '../src/migrate.ts';
import { createEntry, createFolder, emptyVaultData } from '../src/vault.ts';

describe('parseBitwardenJson', () => {
  it('imports folders, logins, and notes', () => {
    const result = parseBitwardenJson(
      JSON.stringify({
        encrypted: false,
        folders: [{ id: 'f1', name: 'Work' }],
        items: [
          {
            type: 1,
            name: 'GitHub',
            folderId: 'f1',
            notes: 'dev',
            login: {
              username: 'me',
              password: 'secret',
              totp: 'otpauth://totp/GitHub?secret=JBSWY3DPEHPK3PXP',
              uris: [{ uri: 'https://github.com' }],
            },
          },
          { type: 2, name: 'Wifi', notes: 'hunter2', folderId: null },
          { type: 3, name: 'Visa', notes: 'skip me' },
        ],
      }),
    );
    expect(result.format).toBe('bitwarden-json');
    expect(result.folders).toEqual([{ name: 'Work', sourceId: 'f1' }]);
    expect(result.entries).toHaveLength(2);
    expect(result.entries[0]).toMatchObject({
      title: 'GitHub',
      username: 'me',
      password: 'secret',
      urls: ['https://github.com'],
      sourceFolderId: 'f1',
    });
    expect(result.entries[1]).toMatchObject({ title: 'Wifi', kind: 'note' });
    expect(result.warnings.some((w) => w.includes('Visa'))).toBe(true);
  });

  it('rejects encrypted exports', () => {
    expect(() => parseBitwardenJson(JSON.stringify({ encrypted: true, items: [] }))).toThrow(/Encrypted/);
  });
});

describe('parseCsvMigration', () => {
  it('imports Bitwarden-style CSV', () => {
    const csv = [
      'folder,type,name,notes,login_uri,login_username,login_password,login_totp',
      'Personal,login,Example,,https://example.com,user,pass,',
      ',note,Secret,body,,,,',
    ].join('\n');
    const result = parseCsvMigration(csv);
    expect(result.folders.map((f) => f.name)).toEqual(['Personal']);
    expect(result.entries).toHaveLength(2);
    expect(result.entries[0]).toMatchObject({
      title: 'Example',
      username: 'user',
      password: 'pass',
      urls: ['https://example.com'],
      sourceFolderName: 'Personal',
    });
    expect(result.entries[1]).toMatchObject({ title: 'Secret', kind: 'note', notes: 'body' });
  });

  it('imports Chrome-style CSV', () => {
    const csv = 'name,url,username,password\nSite,https://a.test,u,p\n';
    const result = parseCsvMigration(csv);
    expect(result.entries[0]).toMatchObject({ title: 'Site', urls: ['https://a.test'], username: 'u', password: 'p' });
  });
});

describe('applyMigration', () => {
  it('creates folders once and links entries', () => {
    const migration = parseMigrationPayload(
      JSON.stringify({
        encrypted: false,
        folders: [{ id: 'f1', name: 'Work' }],
        items: [
          {
            type: 1,
            name: 'A',
            folderId: 'f1',
            login: { username: 'u', password: 'p', uris: [] },
          },
        ],
      }),
    );
    const applied = applyMigration(emptyVaultData(), migration, { createFolder, createEntry });
    expect(applied.folderCount).toBe(1);
    expect(applied.entryCount).toBe(1);
    expect(applied.data.folders[0]?.name).toBe('Work');
    expect(applied.data.entries[0]?.folderId).toBe(applied.data.folders[0]?.id);
  });
});
