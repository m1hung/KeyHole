import { describe, expect, it } from 'vitest';
import { mergeVaultData, TOMBSTONE_TTL_DAYS } from '../src/sync.ts';
import {
  createEntry,
  createFolder,
  deleteEntry,
  deleteFolder,
  emptyVaultData,
  purgeEntry,
  restoreEntry,
  updateEntry,
} from '../src/vault.ts';
import { SCHEMA_VERSION, type VaultData } from '../src/types.ts';

const DAY_MS = 24 * 60 * 60 * 1000;

/** Build a vault whose entries have controlled timestamps. */
function vault(mutate: (d: VaultData) => VaultData = (d) => d): VaultData {
  return mutate(emptyVaultData());
}

function withTimes(data: VaultData, id: string, updatedAt: string): VaultData {
  return { ...data, entries: data.entries.map((e) => (e.id === id ? { ...e, updatedAt } : e)) };
}

const titles = (d: VaultData) => d.entries.map((e) => e.title).sort();

describe('mergeVaultData — keeping data', () => {
  it('unions entries that exist on only one side', () => {
    const { data: a } = createEntry(emptyVaultData(), { title: 'Only on A' });
    const { data: b } = createEntry(emptyVaultData(), { title: 'Only on B' });

    expect(titles(mergeVaultData(a, b).data)).toEqual(['Only on A', 'Only on B']);
  });

  it('keeps the newer version when both sides edited the same entry', () => {
    const { data: base, entry } = createEntry(emptyVaultData(), { title: 'Bank', password: 'old' });
    const older = withTimes(updateEntry(base, entry.id, { password: 'from-a' }), entry.id, '2026-01-01T00:00:00.000Z');
    const newer = withTimes(updateEntry(base, entry.id, { password: 'from-b' }), entry.id, '2026-06-01T00:00:00.000Z');

    expect(mergeVaultData(older, newer).data.entries[0]?.password).toBe('from-b');
    // Symmetric: argument order must not change the outcome.
    expect(mergeVaultData(newer, older).data.entries[0]?.password).toBe('from-b');
  });

  it('never drops an entry just because the other side has not seen it', () => {
    const { data: a } = createEntry(emptyVaultData(), { title: 'Precious', password: 'secret' });
    const merged = mergeVaultData(a, emptyVaultData()).data;
    expect(merged.entries).toHaveLength(1);
    expect(merged.entries[0]?.password).toBe('secret');
  });
});

describe('mergeVaultData — deletions', () => {
  it('propagates a deletion instead of resurrecting the entry', () => {
    const { data: base, entry } = createEntry(emptyVaultData(), { title: 'Retired' });
    const deleted = purgeEntry(base, entry.id);

    // `base` still has it; without tombstones the union would bring it back.
    expect(mergeVaultData(deleted, base).data.entries).toHaveLength(0);
    expect(mergeVaultData(base, deleted).data.entries).toHaveLength(0);
  });

  it('keeps an entry edited AFTER the other device deleted it', () => {
    const { data: base, entry } = createEntry(emptyVaultData(), { title: 'Contested' });
    const deleted = purgeEntry(base, entry.id);
    // The edit is newer than the tombstone, so the user's later intent wins.
    const edited = withTimes(updateEntry(base, entry.id, { password: 'still wanted' }), entry.id, '2099-01-01T00:00:00.000Z');

    const merged = mergeVaultData(deleted, edited).data;
    expect(merged.entries).toHaveLength(1);
    expect(merged.entries[0]?.password).toBe('still wanted');
  });

  it('deletes a folder across devices and unfiles its entries rather than losing them', () => {
    const { data: withFolder, folder } = createFolder(emptyVaultData(), 'Work');
    const { data: base } = createEntry(withFolder, { title: 'Filed', folderId: folder.id });
    const removed = deleteFolder(base, folder.id);

    const merged = mergeVaultData(removed, base).data;
    expect(merged.folders).toHaveLength(0);
    expect(merged.entries).toHaveLength(1);
    expect(merged.entries[0]?.folderId).toBeNull();
  });

  it('expires tombstones once they are older than the TTL', () => {
    const { data: base, entry } = createEntry(emptyVaultData(), { title: 'Ancient' });
    const deleted = purgeEntry(base, entry.id);
    const wayLater = Date.now() + (TOMBSTONE_TTL_DAYS + 1) * DAY_MS;

    const merged = mergeVaultData(deleted, deleted, wayLater).data;
    expect(merged.tombstones).toHaveLength(0);
  });

  it('collapses duplicate tombstones for the same id, keeping the newest', () => {
    const { data: base, entry } = createEntry(emptyVaultData(), { title: 'Gone' });
    const a = purgeEntry(base, entry.id);
    const b = purgeEntry(base, entry.id);

    expect(mergeVaultData(a, b).data.tombstones).toHaveLength(1);
  });
});

describe('mergeVaultData — convergence', () => {
  it('is symmetric for a realistic divergence', () => {
    const { data: seed, entry: shared } = createEntry(emptyVaultData(), { title: 'Shared' });
    const { data: seeded, entry: doomed } = createEntry(seed, { title: 'Doomed' });

    const deviceA = createEntry(withTimes(seeded, shared.id, '2026-03-01T00:00:00.000Z'), { title: 'A only' }).data;
    const deviceB = purgeEntry(createEntry(seeded, { title: 'B only' }).data, doomed.id);

    const ab = mergeVaultData(deviceA, deviceB).data;
    const ba = mergeVaultData(deviceB, deviceA).data;
    expect(JSON.stringify(ab)).toBe(JSON.stringify(ba));
    expect(titles(ab)).toEqual(['A only', 'B only', 'Shared']);
  });

  it('converges on identical timestamps rather than each side keeping its own', () => {
    const { data: base, entry } = createEntry(emptyVaultData(), { title: 'Tie' });
    const stamp = '2026-05-05T00:00:00.000Z';
    const a = withTimes(updateEntry(base, entry.id, { password: 'aaa' }), entry.id, stamp);
    const b = withTimes(updateEntry(base, entry.id, { password: 'bbb' }), entry.id, stamp);

    expect(mergeVaultData(a, b).data.entries[0]?.password).toBe(mergeVaultData(b, a).data.entries[0]?.password);
  });

  it('is idempotent — merging a result with itself changes nothing', () => {
    const { data: a } = createEntry(emptyVaultData(), { title: 'One' });
    const { data: b } = createEntry(emptyVaultData(), { title: 'Two' });
    const once = mergeVaultData(a, b).data;
    const twice = mergeVaultData(once, once).data;
    expect(JSON.stringify(twice)).toBe(JSON.stringify(once));
  });

  it('re-merging an already-merged vault with an old peer does not resurrect', () => {
    const { data: base, entry } = createEntry(emptyVaultData(), { title: 'Zombie' });
    const deleted = purgeEntry(base, entry.id);
    const merged = mergeVaultData(deleted, base).data;
    // A third device still carrying the old copy syncs later.
    expect(mergeVaultData(merged, base).data.entries).toHaveLength(0);
  });
});

describe('mergeVaultData — settings and metadata', () => {
  it('takes settings wholesale from the more recently written vault', () => {
    const a: VaultData = { ...emptyVaultData(), updatedAt: '2026-01-01T00:00:00.000Z' };
    a.settings = { ...a.settings, autoLockMinutes: 5 };
    const b: VaultData = { ...emptyVaultData(), updatedAt: '2026-09-09T00:00:00.000Z' };
    b.settings = { ...b.settings, autoLockMinutes: 42 };

    expect(mergeVaultData(a, b).data.settings.autoLockMinutes).toBe(42);
    expect(mergeVaultData(b, a).data.settings.autoLockMinutes).toBe(42);
  });

  it('reports what it did', () => {
    const { data: base, entry } = createEntry(emptyVaultData(), { title: 'Kept' });
    const deletedSide = purgeEntry(createEntry(base, { title: 'Extra' }).data, entry.id);

    const { stats } = mergeVaultData(base, deletedSide);
    expect(stats.entriesDeleted).toBe(1);
    expect(stats.entriesKept).toBe(1);
    expect(stats.tombstones).toBe(1);
  });

  it('stamps the current schema version', () => {
    expect(mergeVaultData(vault(), vault()).data.schemaVersion).toBe(SCHEMA_VERSION);
  });

  it('survives an unparseable timestamp without losing the entry', () => {
    const { data: base, entry } = createEntry(emptyVaultData(), { title: 'Corrupt clock' });
    const broken = withTimes(base, entry.id, 'not-a-date');
    const merged = mergeVaultData(broken, emptyVaultData()).data;
    expect(merged.entries).toHaveLength(1);
  });
});

describe('mergeVaultData — password history', () => {
  /**
   * The trap this feature would otherwise walk into. Every other field is
   * last-write-wins, so a whole-entry LWW merge keeps one device's row and drops
   * the other's — destroying exactly the old password history exists to keep.
   */
  it('keeps both rows when two devices rotate the same password', () => {
    const { data: base, entry } = createEntry(emptyVaultData(), { title: 'Shared', password: 'original' });

    const onPhone = updateEntry(base, entry.id, { password: 'from-the-phone' });
    const onDesktop = updateEntry(base, entry.id, { password: 'from-the-desktop' });

    const merged = mergeVaultData(onPhone, onDesktop).data;
    const history = merged.entries[0]?.history ?? [];
    const passwords = history.map((h) => h.password);

    // 'original' is recorded by both sides; each side's own supersession is
    // recorded by only one. All of it must survive.
    expect(passwords).toContain('original');
    expect(new Set(passwords).size).toBe(passwords.length);
    expect(merged.entries[0]?.password).toMatch(/^from-the-(phone|desktop)$/);
  });

  it('is symmetric, like every other merge rule', () => {
    const { data: base, entry } = createEntry(emptyVaultData(), { title: 'Shared', password: 'original' });
    const a = updateEntry(base, entry.id, { password: 'a-side' });
    const b = updateEntry(base, entry.id, { password: 'b-side' });

    expect(JSON.stringify(mergeVaultData(a, b).data)).toBe(JSON.stringify(mergeVaultData(b, a).data));
  });

  it('does not duplicate a row both devices already agree on', () => {
    const { data: base, entry } = createEntry(emptyVaultData(), { title: 'Shared', password: 'original' });
    const rotated = updateEntry(base, entry.id, { password: 'rotated' });

    // Both devices hold the same history; merging must not double it.
    const merged = mergeVaultData(rotated, rotated).data;
    expect(merged.entries[0]?.history).toHaveLength(1);
  });
});

describe('mergeVaultData — trash', () => {
  it('merges a soft delete as an ordinary edit, with no tombstone', () => {
    const { data: base, entry } = createEntry(emptyVaultData(), { title: 'Binned' });
    // Dated explicitly: creating and deleting inside one millisecond is a tie, and
    // ties are decided by content rather than by intent (see below).
    const trashed = withTimes(deleteEntry(base, entry.id), entry.id, '2099-01-01T00:00:00.000Z');

    const merged = mergeVaultData(trashed, base).data;
    // Still present — deleting no longer destroys anything on other devices.
    expect(merged.entries).toHaveLength(1);
    expect(merged.entries[0]?.deletedAt).not.toBeNull();
    expect(merged.tombstones).toHaveLength(0);
  });

  /**
   * On an exact timestamp tie the entry stays live. That follows this file's rule
   * — when in doubt, keep the data — and it is the recoverable direction: the user
   * can delete again, but cannot un-destroy.
   */
  it('keeps the entry live when a delete ties with an edit', () => {
    const { data: base, entry } = createEntry(emptyVaultData(), { title: 'Tied' });
    const trashed = deleteEntry(base, entry.id);
    const sameInstant = withTimes(trashed, entry.id, base.entries[0]!.updatedAt);

    const merged = mergeVaultData(sameInstant, base).data;
    expect(merged.entries[0]?.deletedAt).toBeNull();
  });

  it('lets a later restore win over an earlier delete', () => {
    const { data: base, entry } = createEntry(emptyVaultData(), { title: 'Rescued' });
    const trashed = deleteEntry(base, entry.id);
    const restored = withTimes(restoreEntry(trashed, entry.id), entry.id, '2099-01-01T00:00:00.000Z');

    for (const merged of [mergeVaultData(trashed, restored).data, mergeVaultData(restored, trashed).data]) {
      expect(merged.entries[0]?.deletedAt).toBeNull();
    }
  });
});
