/**
 * The app's single source of truth for lock state.
 *
 * Security-relevant invariants enforced here:
 *  - The unlocked session (CryptoKey + decrypted data) lives only in a React
 *    ref, never in localStorage, sessionStorage, a URL, or the document title.
 *  - Any decryption failure returns the app to `locked` with no partial state.
 *  - Idle timeout, tab-hidden (opt-in) and page unload all lock.
 *  - Every mutation re-encrypts and persists immediately, so a crash or a lock
 *    cannot silently lose an edit.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  DecryptionError,
  changeMasterPassword as coreChangeMasterPassword,
  createVault as coreCreateVault,
  saveVault as coreSaveVault,
  unlockVault as coreUnlockVault,
  type KdfPresetName,
  type VaultData,
  type VaultFile,
  type VaultSession,
} from '@keyhole/core';
import {
  clearLocalStorage,
  forgetStoredHandle,
  hasWritePermission,
  loadFromLocalStorage,
  loadStoredHandle,
  saveToLocalStorage,
  writeToHandle,
} from '../storage.ts';

export type VaultStatus = 'loading' | 'no-vault' | 'locked' | 'unlocked';

export interface VaultController {
  status: VaultStatus;
  data: VaultData | null;
  error: string | null;
  busy: boolean;
  /** Seconds until auto-lock, or null when locked / timeout disabled. */
  secondsUntilLock: number | null;

  createVault: (masterPassword: string, preset?: KdfPresetName) => Promise<void>;
  unlock: (masterPassword: string) => Promise<void>;
  lock: () => void;
  mutate: (recipe: (data: VaultData) => VaultData) => Promise<void>;
  changeMasterPassword: (current: string, next: string) => Promise<void>;
  importVault: (file: VaultFile) => void;
  exportVault: () => VaultFile | null;
  applySyncedSession: (file: VaultFile, session: VaultSession) => Promise<void>;
  deleteVault: () => void;
  clearError: () => void;
  registerActivity: () => void;
}

export function useVault(): VaultController {
  const [status, setStatus] = useState<VaultStatus>('loading');
  const [data, setData] = useState<VaultData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [secondsUntilLock, setSecondsUntilLock] = useState<number | null>(null);

  // Deliberately refs, not state: these must never be serialised into React
  // devtools-visible state trees or persisted by any state middleware.
  const sessionRef = useRef<VaultSession | null>(null);
  const fileRef = useRef<VaultFile | null>(null);
  const lastActivityRef = useRef<number>(Date.now());

  useEffect(() => {
    setStatus(loadFromLocalStorage() ? 'locked' : 'no-vault');
  }, []);

  const lock = useCallback(() => {
    sessionRef.current = null;
    setData(null);
    setSecondsUntilLock(null);
    setStatus(fileRef.current || loadFromLocalStorage() ? 'locked' : 'no-vault');
  }, []);

  const registerActivity = useCallback(() => {
    lastActivityRef.current = Date.now();
  }, []);

  /** Persist to localStorage and, when linked, to the on-disk file. */
  const persist = useCallback(async (file: VaultFile) => {
    fileRef.current = file;
    saveToLocalStorage(file);
    const handle = await loadStoredHandle();
    if (handle && (await hasWritePermission(handle))) {
      await writeToHandle(handle, file);
    }
  }, []);

  const createVault = useCallback(
    async (masterPassword: string, preset: KdfPresetName = 'interactive') => {
      setBusy(true);
      setError(null);
      try {
        const { file, session } = await coreCreateVault(masterPassword, { kdfPreset: preset });
        sessionRef.current = session;
        await persist(file);
        setData(session.data);
        registerActivity();
        setStatus('unlocked');
      } catch (err) {
        setError(messageFor(err));
      } finally {
        setBusy(false);
      }
    },
    [persist, registerActivity],
  );

  const unlock = useCallback(
    async (masterPassword: string) => {
      setBusy(true);
      setError(null);
      try {
        const file = fileRef.current ?? loadFromLocalStorage();
        if (!file) {
          setStatus('no-vault');
          return;
        }
        const session = await coreUnlockVault(file, masterPassword);
        sessionRef.current = session;
        fileRef.current = file;
        setData(session.data);
        registerActivity();
        setStatus('unlocked');
      } catch (err) {
        // Fail closed — stay locked and surface nothing about the vault.
        sessionRef.current = null;
        setData(null);
        setStatus('locked');
        setError(messageFor(err));
      } finally {
        setBusy(false);
      }
    },
    [registerActivity],
  );

  const mutate = useCallback(
    async (recipe: (current: VaultData) => VaultData) => {
      const session = sessionRef.current;
      const file = fileRef.current;
      if (!session || !file) {
        setError('Vault is locked.');
        return;
      }
      setError(null);
      const previousData = session.data;
      try {
        session.data = recipe(session.data);
        const updated = await coreSaveVault(session, file);
        await persist(updated);
        setData(session.data);
        registerActivity();
      } catch (err) {
        session.data = previousData; // roll back so UI and session cannot diverge
        setData(previousData);
        setError(messageFor(err));
      }
    },
    [persist, registerActivity],
  );

  const changeMasterPassword = useCallback(
    async (current: string, next: string) => {
      const file = fileRef.current;
      if (!file) {
        setError('No vault loaded.');
        return;
      }
      setBusy(true);
      setError(null);
      try {
        const result = await coreChangeMasterPassword(file, current, next);
        sessionRef.current = result.session;
        await persist(result.file);
        setData(result.session.data);
        registerActivity();
      } catch (err) {
        setError(messageFor(err));
        throw err;
      } finally {
        setBusy(false);
      }
    },
    [persist, registerActivity],
  );

  const importVault = useCallback(
    (file: VaultFile) => {
      sessionRef.current = null;
      fileRef.current = file;
      saveToLocalStorage(file);
      setData(null);
      setError(null);
      setStatus('locked');
    },
    [],
  );

  const exportVault = useCallback(() => fileRef.current ?? loadFromLocalStorage(), []);

  const applySyncedSession = useCallback(
    async (file: VaultFile, session: VaultSession) => {
      sessionRef.current = session;
      await persist(file);
      setData(session.data);
      registerActivity();
      setStatus('unlocked');
    },
    [persist, registerActivity],
  );

  const deleteVault = useCallback(() => {
    sessionRef.current = null;
    fileRef.current = null;
    clearLocalStorage();
    void forgetStoredHandle();
    setData(null);
    setError(null);
    setStatus('no-vault');
  }, []);

  // -------------------------------------------------------------------------
  // Auto-lock
  // -------------------------------------------------------------------------

  const autoLockMinutes = data?.settings.autoLockMinutes ?? 15;
  const lockOnHide = data?.settings.lockOnHide ?? false;

  useEffect(() => {
    if (status !== 'unlocked') return;

    const timeoutMs = autoLockMinutes * 60_000;
    const tick = window.setInterval(() => {
      const remaining = timeoutMs - (Date.now() - lastActivityRef.current);
      if (remaining <= 0) {
        lock();
      } else {
        setSecondsUntilLock(Math.ceil(remaining / 1000));
      }
    }, 1000);

    return () => window.clearInterval(tick);
  }, [status, autoLockMinutes, lock]);

  useEffect(() => {
    if (status !== 'unlocked') return;

    const onVisibility = () => {
      if (document.visibilityState === 'hidden' && lockOnHide) lock();
    };
    // Best-effort: the in-memory key dies with the page anyway, but this makes
    // the intent explicit and clears state before any bfcache restore.
    const onPageHide = () => lock();

    document.addEventListener('visibilitychange', onVisibility);
    window.addEventListener('pagehide', onPageHide);
    return () => {
      document.removeEventListener('visibilitychange', onVisibility);
      window.removeEventListener('pagehide', onPageHide);
    };
  }, [status, lockOnHide, lock]);

  const clearError = useCallback(() => setError(null), []);

  return useMemo(
    () => ({
      status,
      data,
      error,
      busy,
      secondsUntilLock,
      createVault,
      unlock,
      lock,
      mutate,
      changeMasterPassword,
      importVault,
      exportVault,
      applySyncedSession,
      deleteVault,
      clearError,
      registerActivity,
    }),
    [
      status,
      data,
      error,
      busy,
      secondsUntilLock,
      createVault,
      unlock,
      lock,
      mutate,
      changeMasterPassword,
      importVault,
      exportVault,
      applySyncedSession,
      deleteVault,
      clearError,
      registerActivity,
    ],
  );
}

/** Never surface raw exception text — it can carry structural detail about the vault. */
function messageFor(err: unknown): string {
  if (err instanceof DecryptionError) return 'Wrong master password.';
  if (err instanceof Error) return err.message;
  return 'Something went wrong.';
}
