import { describe, expect, it } from 'vitest';
import { analyzeVaultHealth, groupIssuesByEntry } from '../src/health.ts';
import { createEntry, deleteEntry, emptyVaultData } from '../src/vault.ts';

describe('analyzeVaultHealth', () => {
  it('flags reused, weak, empty, and stale passwords', () => {
    let data = emptyVaultData();
    data = createEntry(data, { title: 'A', password: 'shared-secret-value' }).data;
    data = createEntry(data, { title: 'B', password: 'shared-secret-value' }).data;
    data = createEntry(data, { title: 'C', password: '1' }).data;
    data = createEntry(data, { title: 'D', password: '' }).data;

    const old = new Date(Date.now() - 400 * 24 * 60 * 60 * 1000).toISOString();
    data = {
      ...data,
      entries: data.entries.map((e) =>
        e.title === 'A' ? { ...e, passwordUpdatedAt: old } : e,
      ),
    };

    const report = analyzeVaultHealth(data);
    expect(report.loginCount).toBe(4);
    expect(report.issues.some((i) => i.kind === 'reused' && i.title === 'A')).toBe(true);
    expect(report.issues.some((i) => i.kind === 'reused' && i.title === 'B')).toBe(true);
    expect(report.issues.some((i) => i.kind === 'weak' && i.title === 'C')).toBe(true);
    expect(report.issues.some((i) => i.kind === 'empty' && i.title === 'D')).toBe(true);
    expect(report.issues.some((i) => i.kind === 'stale' && i.title === 'A')).toBe(true);
  });
});

describe('analyzeVaultHealth — what "empty" actually says', () => {
  const detailFor = (username: string, password: string): string | undefined => {
    const data = createEntry(emptyVaultData(), { title: 'T', username, password }).data;
    return analyzeVaultHealth(data).issues.find((i) => i.kind === 'empty')?.detail;
  };

  it('names the username too when both fields are empty', () => {
    // Saying only "No password stored." over a blank username reads as a wrong
    // diagnosis, which is how a scan loses the user's trust.
    expect(detailFor('', '')).toBe('No username or password stored.');
    expect(detailFor('me@example.test', '')).toBe('No password stored.');
  });

  it('reports a missing username on its own, as its own kind', () => {
    const data = createEntry(emptyVaultData(), {
      title: 'Token',
      username: '',
      password: 'C9!wq2-Ledger_Trout_49xz',
    }).data;
    const { issues } = analyzeVaultHealth(data);
    expect(issues.map((i) => [i.kind, i.detail])).toEqual([['no username', 'No username stored.']]);
  });

  it('never reports a missing username twice for an entry that is empty anyway', () => {
    // The `empty` finding already names both fields. A second row would inflate
    // the finding count against one broken entry — and the entry count that the
    // batch actions are sized by must stay honest.
    const data = createEntry(emptyVaultData(), { title: 'Stub', username: '', password: '' }).data;
    const { issues } = analyzeVaultHealth(data);
    expect(issues.map((i) => i.kind)).toEqual(['empty']);
    expect(issues[0]?.detail).toBe('No username or password stored.');
  });

  it('leaves a complete login alone', () => {
    const data = createEntry(emptyVaultData(), {
      title: 'Fine',
      username: 'me@example.test',
      password: 'C9!wq2-Ledger_Trout_49xz',
    }).data;
    expect(analyzeVaultHealth(data).issues).toEqual([]);
  });
});

describe('groupIssuesByEntry', () => {
  it('gives one row per entry however many findings it has', () => {
    let data = emptyVaultData();
    // Usernames present so this stays a test about password findings only.
    data = createEntry(data, { title: 'A', username: 'a@example.test', password: '1' }).data;
    data = createEntry(data, { title: 'B', username: 'b@example.test', password: '1' }).data;

    const old = new Date(Date.now() - 400 * 24 * 60 * 60 * 1000).toISOString();
    data = { ...data, entries: data.entries.map((e) => (e.title === 'A' ? { ...e, passwordUpdatedAt: old } : e)) };

    const report = analyzeVaultHealth(data);
    const grouped = groupIssuesByEntry(report.issues);

    // A is weak, reused and stale; B is weak and reused. Five findings, two entries —
    // and a bulk action must be sized by the second number, not the first.
    expect(report.issues.length).toBe(5);
    expect(grouped.length).toBe(2);

    const a = grouped.find((g) => g.title === 'A')!;
    expect(a.entryId).toBe(data.entries[0]!.id);
    expect(a.issues.length).toBe(3);
    expect([...a.kinds].sort()).toEqual(['reused', 'stale', 'weak']);
    // Worst-first ordering from the report survives grouping.
    expect(a.kinds[0]).toBe('reused');
  });

  it('returns nothing for a clean report', () => {
    expect(groupIssuesByEntry([])).toEqual([]);
  });
});

describe('analyzeVaultHealth — trash', () => {
  it('ignores trashed entries entirely', () => {
    let data = emptyVaultData();
    data = createEntry(data, { title: 'Live', password: 'shared-weak' }).data;
    data = createEntry(data, { title: 'Binned', password: 'shared-weak' }).data;

    // While both are live they are reused; once one is binned, neither is.
    expect(analyzeVaultHealth(data).issues.some((i) => i.kind === 'reused')).toBe(true);

    const trashed = deleteEntry(data, data.entries[1]!.id);
    const report = analyzeVaultHealth(trashed);
    expect(report.loginCount).toBe(1);
    expect(report.issues.some((i) => i.kind === 'reused')).toBe(false);
    expect(report.issues.every((i) => i.title !== 'Binned')).toBe(true);
  });
});
