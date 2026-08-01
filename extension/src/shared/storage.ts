/**
 * chrome.storage.local adapter.
 *
 * Holds only the encrypted envelope — the same `VaultFile` format the web app
 * exports, so a vault moves between the two by export/import with no
 * conversion.
 *
 * SIZE LIMIT: chrome.storage.local caps at 10 MB without the `unlimitedStorage`
 * permission. The envelope is roughly 1.4 KB empty and grows ~250 bytes per
 * entry after base64 expansion, so 10 MB is on the order of 40,000 entries.
 * We check before writing rather than letting a quota error corrupt state.
 */

import { parseVaultFile, type VaultFile } from '@keyhole/core';

const VAULT_KEY = 'keyhole.vault.v1';
const SETTINGS_KEY = 'keyhole.local.v1';

/** Chrome's documented per-extension quota for storage.local. */
const QUOTA_BYTES = 10 * 1024 * 1024;
/** Refuse writes above this so the user hits a clear error, not a silent failure. */
const WRITE_CEILING = QUOTA_BYTES * 0.9;

export async function loadVaultFile(): Promise<VaultFile | null> {
  const stored = await chrome.storage.local.get(VAULT_KEY);
  const raw = stored[VAULT_KEY] as unknown;
  if (raw === undefined || raw === null) return null;
  try {
    return parseVaultFile(raw);
  } catch {
    console.warn('Stored vault failed schema validation.');
    return null;
  }
}

export async function saveVaultFile(file: VaultFile): Promise<void> {
  const size = JSON.stringify(file).length;
  if (size > WRITE_CEILING) {
    throw new Error(`Vault is too large for extension storage (${(size / 1024 / 1024).toFixed(1)} MB of 10 MB).`);
  }
  await chrome.storage.local.set({ [VAULT_KEY]: file });
}

export async function hasVault(): Promise<boolean> {
  const stored = await chrome.storage.local.get(VAULT_KEY);
  return stored[VAULT_KEY] !== undefined;
}

// ---------------------------------------------------------------------------
// Non-secret local preferences
// ---------------------------------------------------------------------------

export interface LocalPrefs {
  /** Mirrors the in-vault setting so the alarm can be scheduled while locked. */
  autoLockMinutes: number;
  clipboardClearSeconds: number;
  lockOnHide: boolean;
  theme: 'light' | 'dark' | 'system';
}

const DEFAULT_PREFS: LocalPrefs = {
  autoLockMinutes: 15,
  clipboardClearSeconds: 30,
  lockOnHide: false,
  theme: 'system',
};

export async function loadPrefs(): Promise<LocalPrefs> {
  const stored = await chrome.storage.local.get(SETTINGS_KEY);
  const raw = stored[SETTINGS_KEY] as Partial<LocalPrefs> | undefined;
  const theme = raw?.theme;
  return {
    autoLockMinutes:
      typeof raw?.autoLockMinutes === 'number' && raw.autoLockMinutes > 0
        ? raw.autoLockMinutes
        : DEFAULT_PREFS.autoLockMinutes,
    clipboardClearSeconds:
      typeof raw?.clipboardClearSeconds === 'number' && raw.clipboardClearSeconds >= 0
        ? raw.clipboardClearSeconds
        : DEFAULT_PREFS.clipboardClearSeconds,
    lockOnHide: typeof raw?.lockOnHide === 'boolean' ? raw.lockOnHide : DEFAULT_PREFS.lockOnHide,
    theme: theme === 'light' || theme === 'dark' || theme === 'system' ? theme : DEFAULT_PREFS.theme,
  };
}

export async function savePrefs(prefs: Partial<LocalPrefs>): Promise<void> {
  const current = await loadPrefs();
  await chrome.storage.local.set({ [SETTINGS_KEY]: { ...current, ...prefs } });
}

// ---------------------------------------------------------------------------
// Sync server config (URL + account id only — never the auth secret)
// ---------------------------------------------------------------------------

export interface SyncConfig {
  baseUrl: string;
  accountId: string;
}

const SYNC_KEY = 'keyhole.sync.v1';

export async function loadSyncConfig(): Promise<SyncConfig | null> {
  const stored = await chrome.storage.local.get(SYNC_KEY);
  const raw = stored[SYNC_KEY] as Partial<SyncConfig> | undefined;
  if (!raw || typeof raw.baseUrl !== 'string' || typeof raw.accountId !== 'string') return null;
  if (raw.baseUrl.length === 0 || raw.accountId.length === 0) return null;
  return { baseUrl: raw.baseUrl.replace(/\/+$/, ''), accountId: raw.accountId.trim().toLowerCase() };
}

export async function saveSyncConfig(config: SyncConfig): Promise<void> {
  await chrome.storage.local.set({
    [SYNC_KEY]: {
      baseUrl: config.baseUrl.replace(/\/+$/, ''),
      accountId: config.accountId.trim().toLowerCase(),
    },
  });
}

// ---------------------------------------------------------------------------
// Reset
// ---------------------------------------------------------------------------

/**
 * Remove everything Keyhole has written to this browser profile: the encrypted
 * envelope, the mirrored preferences, and the sync server association.
 *
 * Both halves matter for a "sign out": the vault goes, and so does the account
 * it synced to — otherwise the next person to open the options page reads the
 * previous owner's server URL and account id out of the form.
 *
 * Spelled out key by key rather than `chrome.storage.local.clear()`, so a key
 * added later shows up as a survivor to fix here instead of being wiped along
 * with everything else the extension might one day store.
 */
export async function clearAllStoredData(): Promise<void> {
  await chrome.storage.local.remove([VAULT_KEY, SETTINGS_KEY, SYNC_KEY]);
}
