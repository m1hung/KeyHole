/**
 * Offline vault health checks — run only while the vault is unlocked.
 * Never phones home; never persists analysis results.
 */

import { estimateStrength } from './password-gen.ts';
import type { Entry, VaultData } from './types.ts';

export type HealthIssueKind = 'reused' | 'weak' | 'stale' | 'empty' | 'no username';

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

/** Every finding against one entry, so a report can be acted on per entry. */
export interface EntryFindings {
  entryId: string;
  title: string;
  /** Distinct kinds on this entry, worst first. */
  kinds: HealthIssueKind[];
  issues: HealthIssue[];
}

const STALE_MS = 365 * 24 * 60 * 60 * 1000; // 1 year
const WEAK_MAX_SCORE = 1; // very weak / weak

export function analyzeVaultHealth(data: VaultData, nowMs = Date.now()): VaultHealthReport {
  // Trashed entries are excluded: nagging about the strength of a password the
  // user has already deleted is noise, and it would inflate the reuse counts.
  const logins = data.entries.filter((e) => e.kind === 'login' && e.deletedAt === null);
  const issues: HealthIssue[] = [];

  const byPassword = new Map<string, Entry[]>();
  for (const entry of logins) {
    if (entry.password.length === 0) {
      issues.push({
        kind: 'empty',
        entryId: entry.id,
        title: entry.title,
        /* Name every field that is actually empty. Reporting only the password on
           an entry that is missing both reads as a wrong diagnosis — you look at
           a blank username, are told about a password, and stop trusting the
           scan. A missing username is not a finding on its own (plenty of real
           logins have none: API tokens, PINs, wifi keys), but when the entry is
           empty anyway it is part of an honest description of what is there. */
        detail:
          entry.username.length === 0 ? 'No username or password stored.' : 'No password stored.',
      });
      continue;
    }
    /* Only reached when a password IS stored — an entry missing both is already
       described by the `empty` finding above, and reporting it twice would inflate
       the finding count against a single broken entry. */
    if (entry.username.length === 0) {
      issues.push({
        kind: 'no username',
        entryId: entry.id,
        title: entry.title,
        detail: 'No username stored.',
      });
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

  /* Mildest last: a login with no username still works, it is just incomplete —
     unlike a reused or weak password, which is a live exposure. */
  const order: Record<HealthIssueKind, number> = {
    empty: 0,
    reused: 1,
    weak: 2,
    stale: 3,
    'no username': 4,
  };
  issues.sort((a, b) => order[a.kind] - order[b.kind] || a.title.localeCompare(b.title));

  return {
    issues,
    checkedAt: new Date(nowMs).toISOString(),
    loginCount: logins.length,
  };
}

/**
 * Collapse a report's flat issue list to one row per entry.
 *
 * A single login is routinely weak *and* reused *and* stale, so the flat list
 * names it three times. That is fine to read and wrong to select: a checkbox per
 * issue lets "3 selected" mean one password, and a bulk delete would then destroy
 * far less — or far more — than the count implied. Anything that acts on findings
 * collectively acts on this shape instead, where the count is a count of entries.
 *
 * Input order is preserved (`analyzeVaultHealth` sorts worst-first), so an entry
 * sits at its most serious finding.
 */
export function groupIssuesByEntry(issues: readonly HealthIssue[]): EntryFindings[] {
  const byEntry = new Map<string, EntryFindings>();
  for (const issue of issues) {
    const existing = byEntry.get(issue.entryId);
    if (existing) {
      existing.issues.push(issue);
      if (!existing.kinds.includes(issue.kind)) existing.kinds.push(issue.kind);
      continue;
    }
    byEntry.set(issue.entryId, {
      entryId: issue.entryId,
      // The title travels with the issue, so grouping needs no vault access.
      title: issue.title,
      kinds: [issue.kind],
      issues: [issue],
    });
  }
  return [...byEntry.values()];
}
