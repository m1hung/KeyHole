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

describe('groupIssuesByEntry', () => {
  it('gives one row per entry however many findings it has', () => {
    let data = emptyVaultData();
    data = createEntry(data, { title: 'A', password: '1' }).data;
    data = createEntry(data, { title: 'B', password: '1' }).data;

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
