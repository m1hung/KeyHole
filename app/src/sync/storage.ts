/**
 * Sync server URL + account id persistence (web app — localStorage).
 *
 * Stores only baseUrl and accountId — never the auth secret.
 */

import type { SyncConfig } from '@keyhole/shared';

const STORAGE_KEY = 'keyhole.sync.v1';

export function loadSyncConfig(): SyncConfig | null {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as Partial<SyncConfig>;
    if (typeof parsed.baseUrl !== 'string' || typeof parsed.accountId !== 'string') return null;
    if (parsed.baseUrl.length === 0 || parsed.accountId.length === 0) return null;
    return { baseUrl: parsed.baseUrl.replace(/\/+$/, ''), accountId: parsed.accountId.trim().toLowerCase() };
  } catch {
    return null;
  }
}

export function saveSyncConfig(config: SyncConfig): void {
  localStorage.setItem(
    STORAGE_KEY,
    JSON.stringify({
      baseUrl: config.baseUrl.replace(/\/+$/, ''),
      accountId: config.accountId.trim().toLowerCase(),
    }),
  );
}
