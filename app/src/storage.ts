/**
 * Persistence for the local web app.
 *
 * Only ever handles the *encrypted* envelope. The decrypted vault, the master
 * password and derived keys never reach this module — which is why writing the
 * envelope to localStorage is acceptable: it is ciphertext plus a public header,
 * and it is exactly what an attacker would get from stealing the file anyway.
 *
 * Three storage paths, in order of preference:
 *  1. File System Access API — a real .keyhole file you own, re-saved in place.
 *  2. localStorage — always available, survives reload, scoped to the origin.
 *  3. Download/upload — the universal export/import escape hatch.
 */

import { parseVaultFile, type VaultFile } from '@keyhole/core';

const STORAGE_KEY = 'keyhole.vault.v1';
const HANDLE_DB = 'keyhole-handles';
const HANDLE_STORE = 'handles';
const HANDLE_KEY = 'vault-file';

export const VAULT_FILE_EXTENSION = '.keyhole.json';

// ---------------------------------------------------------------------------
// localStorage
// ---------------------------------------------------------------------------

export function loadFromLocalStorage(): VaultFile | null {
  const raw = localStorage.getItem(STORAGE_KEY);
  if (raw === null) return null;
  try {
    return parseVaultFile(JSON.parse(raw));
  } catch {
    // A corrupt entry must not brick the app into an unrecoverable state; the
    // UI falls back to onboarding, and the raw value is left in place so a user
    // can still recover it manually from devtools.
    console.warn('Stored vault failed validation; treating as absent.');
    return null;
  }
}

export function saveToLocalStorage(file: VaultFile): void {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(file));
}

export function clearLocalStorage(): void {
  localStorage.removeItem(STORAGE_KEY);
}

export function hasStoredVault(): boolean {
  return localStorage.getItem(STORAGE_KEY) !== null;
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
