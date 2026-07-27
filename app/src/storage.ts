/**
 * Persistence for the standalone app.
 *
 * Only ever handles the *encrypted* envelope. The decrypted vault, the master
 * password and derived keys never reach this module — which is why writing the
 * envelope out is acceptable: it is ciphertext plus a public header, and it is
 * exactly what an attacker would get from stealing the file anyway.
 *
 * There are two backends, chosen once at startup:
 *
 *  - **Desktop (Electron).** The vault is a real file at
 *    `%APPDATA%\Keyhole\keyhole-vault.keyhole.json`, written atomically by the
 *    main process. Chosen because a password manager's data should be something
 *    you can back up and carry, not something buried in a browser profile.
 *
 *  - **Browser.** `localStorage` under the page's origin, as before. An
 *    installed PWA and the same origin in a tab share it, so there is exactly
 *    one vault either way.
 *
 * The two are separate stores by construction — different origins, different
 * disks. A desktop build cannot see a browser vault, which is precisely why
 * `initVaultStore` reports whether a legacy browser vault exists, so the UI can
 * offer to import it instead of silently showing an empty "create vault" screen
 * to someone who already has one.
 *
 * File System Access API linking and download/upload remain available on top of
 * either backend, unchanged.
 */

import { parseVaultFile, type VaultFile } from '@keyhole/core';

const STORAGE_KEY = 'keyhole.vault.v1';
const HANDLE_DB = 'keyhole-handles';
const HANDLE_STORE = 'handles';
const HANDLE_KEY = 'vault-file';

export const VAULT_FILE_EXTENSION = '.keyhole.json';

// ---------------------------------------------------------------------------
// Backend selection
// ---------------------------------------------------------------------------

/** The Electron preload bridge, when running inside the desktop build. */
const bridge = (globalThis as { keyhole?: KeyholeDesktopBridge }).keyhole;

export type StorageBackend = 'desktop-file' | 'local-storage';

export const backend: StorageBackend = bridge?.desktop === true ? 'desktop-file' : 'local-storage';

export function isDesktop(): boolean {
  return backend === 'desktop-file';
}

/**
 * Synchronous mirror of whatever the backend holds.
 *
 * `useVault` reads the stored envelope synchronously in several places (initial
 * status, `lock()`, `exportVault()`), and the desktop backend is async. Rather
 * than make lock state async — which would open a window where the UI does not
 * yet know whether a vault exists — the envelope is hydrated once before React
 * mounts and kept here. Writes update the cache first, then the backend.
 */
let cached: VaultFile | null = null;
let hydrated = false;

function parseOrWarn(raw: string): VaultFile | null {
  try {
    return parseVaultFile(JSON.parse(raw));
  } catch {
    // A corrupt entry must not brick the app into an unrecoverable state; the
    // UI falls back to onboarding, and the raw value is left in place so a user
    // can still recover it manually.
    console.warn('Stored vault failed validation; treating as absent.');
    return null;
  }
}

export interface VaultStoreInit {
  backend: StorageBackend;
  /**
   * Desktop only: a vault exists in this machine's browser `localStorage` but
   * not in the desktop file. Set when someone who used the browser build opens
   * the .exe for the first time — the UI offers an import rather than pretending
   * they have no vault.
   *
   * Always false in the browser build, where the two are the same store.
   */
  legacyBrowserVaultAvailable: boolean;
}

/**
 * Hydrate the cache. Must be awaited before React mounts — mounting first would
 * flash "no vault" at someone whose vault is merely still being read.
 */
export async function initVaultStore(): Promise<VaultStoreInit> {
  if (bridge?.desktop === true) {
    let raw: string | null = null;
    try {
      raw = await bridge.vault.read();
    } catch (err) {
      console.warn('Could not read the vault file.', err);
    }
    cached = raw === null ? null : parseOrWarn(raw);
    hydrated = true;
    return {
      backend,
      legacyBrowserVaultAvailable: cached === null && readLocalStorageRaw() !== null,
    };
  }

  const raw = readLocalStorageRaw();
  cached = raw === null ? null : parseOrWarn(raw);
  hydrated = true;
  return { backend, legacyBrowserVaultAvailable: false };
}

function readLocalStorageRaw(): string | null {
  try {
    return localStorage.getItem(STORAGE_KEY);
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Stored envelope
// ---------------------------------------------------------------------------

export function loadStoredVault(): VaultFile | null {
  if (!hydrated) {
    // Reaching here means someone mounted the UI without awaiting
    // initVaultStore() — a bug that would look exactly like a lost vault, so it
    // is worth being loud about rather than returning a plausible null.
    console.error('loadStoredVault() called before initVaultStore() resolved.');
  }
  return cached;
}

export function hasStoredVault(): boolean {
  return cached !== null;
}

/**
 * Persist the envelope. Resolves only once it is durably stored, so callers that
 * await this know an edit survived — on desktop that means the atomic file write
 * completed, and a rejection here is a real "your change did not save".
 */
export async function storeVault(file: VaultFile): Promise<void> {
  const previous = cached;
  cached = file;
  const json = JSON.stringify(file, null, 2);

  if (bridge?.desktop === true) {
    try {
      await bridge.vault.write(json);
    } catch (err) {
      cached = previous; // keep the cache honest about what is actually stored
      throw new Error(`Could not save the vault file: ${err instanceof Error ? err.message : String(err)}`);
    }
    return;
  }

  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(file));
  } catch (err) {
    cached = previous;
    throw new Error(`Could not save the vault: ${err instanceof Error ? err.message : String(err)}`);
  }
}

export async function clearStoredVault(): Promise<void> {
  cached = null;
  if (bridge?.desktop === true) {
    await bridge.vault.clear();
    return;
  }
  localStorage.removeItem(STORAGE_KEY);
}

// ---------------------------------------------------------------------------
// Desktop-only helpers
// ---------------------------------------------------------------------------

/** Absolute path of the vault file, for display in Settings. */
export async function vaultFilePath(): Promise<string | null> {
  if (bridge?.desktop !== true) return null;
  try {
    return await bridge.vault.path();
  } catch {
    return null;
  }
}

export async function revealVaultFile(): Promise<void> {
  if (bridge?.desktop !== true) return;
  await bridge.vault.reveal();
}

/** Native open dialog. Returns null when cancelled. */
export async function importVaultViaDialog(): Promise<VaultFile | null> {
  if (bridge?.desktop !== true) return null;
  const raw = await bridge.vault.importFile();
  if (raw === null) return null;
  return parseVaultFile(JSON.parse(raw));
}

/** Native save dialog. Returns the written path, or null when cancelled. */
export async function exportVaultViaDialog(file: VaultFile): Promise<string | null> {
  if (bridge?.desktop !== true) return null;
  return await bridge.vault.exportFile(JSON.stringify(file, null, 2));
}

/**
 * Desktop first-run migration: read the envelope this machine's browser build
 * left in localStorage. Read-only — the browser copy is never deleted, so a
 * failed migration cannot lose the only copy.
 */
export function readLegacyBrowserVault(): VaultFile | null {
  const raw = readLocalStorageRaw();
  return raw === null ? null : parseOrWarn(raw);
}

// ---------------------------------------------------------------------------
// Download / upload (always available)
// ---------------------------------------------------------------------------

export function downloadVaultFile(file: VaultFile, filename = `keyhole-vault${VAULT_FILE_EXTENSION}`): void {
  const blob = new Blob([JSON.stringify(file, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

export async function readVaultFromBlob(blob: Blob): Promise<VaultFile> {
  const text = await blob.text();
  return parseVaultFile(JSON.parse(text));
}

// ---------------------------------------------------------------------------
// File System Access API (Chromium)
// ---------------------------------------------------------------------------

export function supportsFileSystemAccess(): boolean {
  return typeof globalThis.showSaveFilePicker === 'function';
}

const PICKER_TYPES = [{ description: 'Keyhole vault', accept: { 'application/json': ['.json'] } }];

export async function pickSaveHandle(): Promise<FileSystemFileHandle | null> {
  if (!supportsFileSystemAccess()) return null;
  try {
    const handle = await globalThis.showSaveFilePicker({
      suggestedName: `keyhole-vault${VAULT_FILE_EXTENSION}`,
      types: PICKER_TYPES,
    });
    await storeHandle(handle);
    return handle;
  } catch {
    return null; // user cancelled
  }
}

export async function pickOpenHandle(): Promise<FileSystemFileHandle | null> {
  if (typeof globalThis.showOpenFilePicker !== 'function') return null;
  try {
    const [handle] = await globalThis.showOpenFilePicker({ types: PICKER_TYPES, multiple: false });
    if (!handle) return null;
    await storeHandle(handle);
    return handle;
  } catch {
    return null;
  }
}

export async function writeToHandle(handle: FileSystemFileHandle, file: VaultFile): Promise<void> {
  const writable = await handle.createWritable();
  await writable.write(JSON.stringify(file, null, 2));
  await writable.close();
}

/**
 * Re-check write permission. Chrome drops the grant across reloads, so this
 * returns false rather than throwing when the user must be re-prompted.
 */
export async function hasWritePermission(handle: FileSystemFileHandle): Promise<boolean> {
  const query = await handle.queryPermission?.({ mode: 'readwrite' });
  if (query === 'granted') return true;
  const request = await handle.requestPermission?.({ mode: 'readwrite' });
  return request === 'granted';
}

// ---------------------------------------------------------------------------
// Handle persistence (IndexedDB — FileSystemFileHandle is structured-cloneable
// but not JSON-serialisable, so localStorage cannot hold it)
// ---------------------------------------------------------------------------

function openHandleDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(HANDLE_DB, 1);
    request.onupgradeneeded = () => request.result.createObjectStore(HANDLE_STORE);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function storeHandle(handle: FileSystemFileHandle): Promise<void> {
  const db = await openHandleDb();
  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction(HANDLE_STORE, 'readwrite');
    tx.objectStore(HANDLE_STORE).put(handle, HANDLE_KEY);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
  db.close();
}

export async function loadStoredHandle(): Promise<FileSystemFileHandle | null> {
  if (!supportsFileSystemAccess()) return null;
  try {
    const db = await openHandleDb();
    const handle = await new Promise<FileSystemFileHandle | null>((resolve, reject) => {
      const tx = db.transaction(HANDLE_STORE, 'readonly');
      const req = tx.objectStore(HANDLE_STORE).get(HANDLE_KEY);
      req.onsuccess = () => resolve((req.result as FileSystemFileHandle | undefined) ?? null);
      req.onerror = () => reject(req.error);
    });
    db.close();
    return handle;
  } catch {
    return null;
  }
}

export async function forgetStoredHandle(): Promise<void> {
  try {
    const db = await openHandleDb();
    await new Promise<void>((resolve) => {
      const tx = db.transaction(HANDLE_STORE, 'readwrite');
      tx.objectStore(HANDLE_STORE).delete(HANDLE_KEY);
      tx.oncomplete = () => resolve();
      tx.onerror = () => resolve();
    });
    db.close();
  } catch {
    /* nothing to forget */
  }
}
