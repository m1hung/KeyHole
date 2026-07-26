import { describe, expect, it } from 'vitest';
import { compareEnvelopes, decideSync, pickCanonical } from '../src/sync.ts';
import type { VaultFile } from '../src/types.ts';
import { FORMAT_VERSION, VAULT_FORMAT_ID } from '../src/types.ts';

function envelope(patch: Partial<VaultFile> & Pick<VaultFile, 'vaultId' | 'updatedAt'>): VaultFile {
  return {
    format: VAULT_FORMAT_ID,
    formatVersion: FORMAT_VERSION,
    createdAt: '2026-01-01T00:00:00.000Z',
    kdf: {
      algorithm: 'argon2id',
      memoryKiB: 65536,
      iterations: 3,
      parallelism: 1,
      saltB64: 'AAAAAAAAAAAAAAAAAAAAAA==',
      keyLength: 32,
    },
    wrappedKey: { ivB64: 'AAAAAAAAAAAA', ctB64: 'wrap' },
    payload: { ivB64: 'BBBBBBBBBBBB', ctB64: 'payload-a' },
    ...patch,
  };
}

describe('compareEnvelopes', () => {
  it('flags different vault ids as unrelated', () => {
    const a = envelope({ vaultId: 'aaa', updatedAt: '2026-01-02T00:00:00.000Z' });
    const b = envelope({ vaultId: 'bbb', updatedAt: '2026-01-03T00:00:00.000Z' });
    expect(compareEnvelopes(a, b)).toBe('unrelated');
  });

  it('orders by updatedAt when payloads differ', () => {
    const older = envelope({ vaultId: 'v1', updatedAt: '2026-01-02T00:00:00.000Z' });
    const newer = envelope({
      vaultId: 'v1',
      updatedAt: '2026-01-03T00:00:00.000Z',
      payload: { ivB64: 'CCCCCCCCCCCC', ctB64: 'payload-b' },
    });
    expect(compareEnvelopes(older, newer)).toBe('b-newer');
    expect(compareEnvelopes(newer, older)).toBe('a-newer');
  });

  it('treats identical timestamp + payload as same', () => {
    const a = envelope({ vaultId: 'v1', updatedAt: '2026-01-02T00:00:00.000Z' });
    const b = envelope({ vaultId: 'v1', updatedAt: '2026-01-02T00:00:00.000Z' });
    expect(compareEnvelopes(a, b)).toBe('same');
  });

  it('treats identical timestamp with different payload as divergent', () => {
    const a = envelope({ vaultId: 'v1', updatedAt: '2026-01-02T00:00:00.000Z' });
    const b = envelope({
      vaultId: 'v1',
      updatedAt: '2026-01-02T00:00:00.000Z',
      payload: { ivB64: 'CCCCCCCCCCCC', ctB64: 'payload-b' },
    });
    expect(compareEnvelopes(a, b)).toBe('divergent');
  });
});

describe('decideSync / pickCanonical', () => {
  const local = envelope({ vaultId: 'v1', updatedAt: '2026-01-03T00:00:00.000Z' });
  const olderRemote = envelope({
    vaultId: 'v1',
    updatedAt: '2026-01-02T00:00:00.000Z',
    payload: { ivB64: 'CCCCCCCCCCCC', ctB64: 'old' },
  });
  const newerRemote = envelope({
    vaultId: 'v1',
    updatedAt: '2026-01-04T00:00:00.000Z',
    payload: { ivB64: 'DDDDDDDDDDDD', ctB64: 'new' },
  });

  it('pushes when local is newer', () => {
    const d = decideSync(local, olderRemote);
    expect(d.action).toBe('push-local');
    expect(pickCanonical(local, olderRemote, d)).toBe(local);
  });

  it('adopts when remote is newer', () => {
    const d = decideSync(local, newerRemote);
    expect(d.action).toBe('adopt-remote');
    expect(pickCanonical(local, newerRemote, d)).toBe(newerRemote);
  });

  it('noops when equal', () => {
    const twin = envelope({ vaultId: 'v1', updatedAt: local.updatedAt });
    const d = decideSync(local, twin);
    expect(d.action).toBe('noop');
    expect(pickCanonical(local, twin, d)).toBe(local);
  });

  it('refuses unrelated vaults and returns no canonical', () => {
    const other = envelope({ vaultId: 'other', updatedAt: '2026-01-09T00:00:00.000Z' });
    const d = decideSync(local, other);
    expect(d.action).toBe('refuse');
    expect(pickCanonical(local, other, d)).toBeNull();
  });

  it('surfaces divergent timestamps as conflict', () => {
    const clash = envelope({
      vaultId: 'v1',
      updatedAt: local.updatedAt,
      payload: { ivB64: 'XXXXXXXXXXXX', ctB64: 'clash' },
    });
    const d = decideSync(local, clash);
    expect(d.action).toBe('conflict');
    expect(pickCanonical(local, clash, d)).toBeNull();
  });
});
