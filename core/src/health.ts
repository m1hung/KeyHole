/**
 * Offline vault health checks — run only while the vault is unlocked.
 * Never phones home; never persists analysis results.
 */

import { estimateStrength } from './password-gen.ts';
import type { Entry, VaultData } from './types.ts';

export type HealthIssueKind = 'reused' | 'weak' | 'stale' | 'empty';

export interface HealthIssue {
  kind: HealthIssueKind;
  entryId: string;
  title: string;
  detail: string;
}

export interface VaultHealthReport {
  issues: HealthIssue[];
  checkedAt: string;
  loginCount: number;
}

const STALE_MS = 365 * 24 * 60 * 60 * 1000; // 1 year
const WEAK_MAX_SCORE = 1; // very weak / weak

export function analyzeVaultHealth(data: VaultData, nowMs = Date.now()): VaultHealthReport {
  const logins = data.entries.filter((e) => e.kind === 'login');
  const issues: HealthIssue[] = [];

  const byPassword = new Map<string, Entry[]>();
  for (const entry of logins) {
    if (entry.password.length === 0) {
      issues.push({
        kind: 'empty',
        entryId: entry.id,
        title: entry.title,
        detail: 'No password stored.',
      });
      continue;
    }
    const group = byPassword.get(entry.password) ?? [];
    group.push(entry);
    byPassword.set(entry.password, group);

    const strength = estimateStrength(entry.password);
    if (strength.score <= WEAK_MAX_SCORE) {
      issues.push({
        kind: 'weak',
        entryId: entry.id,
        title: entry.title,
        detail: `Password looks ${strength.label} (~${strength.bits} bits).`,
      });
    }

    const updated = Date.parse(entry.passwordUpdatedAt);
    if (Number.isFinite(updated) && nowMs - updated > STALE_MS) {
      const years = Math.floor((nowMs - updated) / (365 * 24 * 60 * 60 * 1000));
      issues.push({
        kind: 'stale',
        entryId: entry.id,
        title: entry.title,
        detail: years <= 1 ? 'Password not changed in over a year.' : `Password not changed in ~${years} years.`,
      });
    }
  }

  for (const [, group] of byPassword) {
    if (group.length < 2) continue;
    for (const entry of group) {
      issues.push({
        kind: 'reused',
        entryId: entry.id,
        title: entry.title,
        detail: `Same password as ${group.length - 1} other login${group.length - 1 === 1 ? '' : 's'}.`,
      });
    }
  }

  const order: Record<HealthIssueKind, number> = { empty: 0, reused: 1, weak: 2, stale: 3 };
  issues.sort((a, b) => order[a.kind] - order[b.kind] || a.title.localeCompare(b.title));

  return {
    issues,
    checkedAt: new Date(nowMs).toISOString(),
    loginCount: logins.length,
  };
}
