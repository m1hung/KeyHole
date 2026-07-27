import { describe, expect, it } from 'vitest';
import { analyzeVaultHealth } from '../src/health.ts';
import { createEntry, emptyVaultData } from '../src/vault.ts';

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
