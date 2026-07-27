/** Settings: lock behaviour, theme, local storage, export/import, master password, delete vault. */

import { useEffect, useRef, useState } from 'react';
import { MIN_MASTER_PASSWORD_LENGTH, type Settings, type VaultFile } from '@keyhole/core';
import { ConfirmDialog, StrengthMeter } from './common.tsx';
import { Icon } from './Icon.tsx';
import {
  downloadVaultFile,
  forgetStoredHandle,
  hasWritePermission,
  loadStoredHandle,
  pickSaveHandle,
  readVaultFromBlob,
  supportsFileSystemAccess,
  writeToHandle,
} from '../storage.ts';
import type { VaultController } from '../hooks/useVault.ts';

interface SettingsPanelProps {
  settings: Settings;
  onSettingsChange: (patch: Partial<Settings>) => void;
  vault: VaultController;
  entryCount: number;
}

export function SettingsPanel({ settings, onSettingsChange, vault, entryCount }: SettingsPanelProps) {
  return (
    <div>
      <h2 style={{ marginTop: 0 }}>Settings</h2>

      <div className="section" style={{ borderTop: 'none', paddingTop: 0, marginTop: 16 }}>
        <h3>Security</h3>

        <div className="field">
          <label htmlFor="autolock">Auto-lock after {settings.autoLockMinutes} minutes idle</label>
          <input
            id="autolock"
            type="range"
            min={1}
            max={60}
            value={settings.autoLockMinutes}
            onChange={(e) => onSettingsChange({ autoLockMinutes: Number(e.target.value) })}
          />
        </div>

        <div className="field">
          <label htmlFor="clipboard">
            Clear clipboard after{' '}
            {settings.clipboardClearSeconds === 0 ? 'never' : `${settings.clipboardClearSeconds} seconds`}
          </label>
          <input
            id="clipboard"
            type="range"
            min={0}
            max={120}
            step={5}
            value={settings.clipboardClearSeconds}
            onChange={(e) => onSettingsChange({ clipboardClearSeconds: Number(e.target.value) })}
          />
        </div>

        <div className="checkbox-row">
          <input
            id="lock-on-hide"
            type="checkbox"
            checked={settings.lockOnHide}
            onChange={(e) => onSettingsChange({ lockOnHide: e.target.checked })}
          />
          <label htmlFor="lock-on-hide">Lock immediately when this tab is hidden</label>
        </div>
      </div>

      <div className="section">
        <h3>Appearance</h3>
        <div className="field">
          <label htmlFor="theme">Theme</label>
          <select
            id="theme"
            value={settings.theme}
            onChange={(e) => onSettingsChange({ theme: e.target.value as Settings['theme'] })}
          >
            <option value="system">Match system</option>
            <option value="light">Light</option>
            <option value="dark">Dark</option>
          </select>
        </div>
      </div>

      <LocalStorageSection vault={vault} />
      <BackupSection vault={vault} entryCount={entryCount} />
      <ChangeMasterPassword vault={vault} />
      <DangerZone vault={vault} entryCount={entryCount} />
    </div>
  );
}

// ---------------------------------------------------------------------------

function LocalStorageSection({ vault }: { vault: VaultController }) {
  const [linkedName, setLinkedName] = useState<string | null>(null);
  const [linkWritable, setLinkWritable] = useState(false);
  const [status, setStatus] = useState<string | null>(null);
  const canLink = supportsFileSystemAccess();

  const refresh = async () => {
    if (!canLink) {
      setLinkedName(null);
      setLinkWritable(false);
      return;
    }
    const handle = await loadStoredHandle();
    if (!handle) {
      setLinkedName(null);
      setLinkWritable(false);
      return;
    }
    setLinkedName(handle.name);
    setLinkWritable(await hasWritePermission(handle));
  };

  useEffect(() => {
    void refresh();
  }, [canLink]);

  const linkFile = async () => {
    const file = vault.exportVault();
    if (!file) return;
    const handle = await pickSaveHandle();
    if (!handle) return;
    await writeToHandle(handle, file);
    setStatus('Linked. Future saves write to this file as well as browser storage.');
    await refresh();
  };

  const unlink = async () => {
    await forgetStoredHandle();
    setStatus('Unlinked. The vault remains in this browser; the file on disk is unchanged.');
    await refresh();
  };

  return (
    <div className="section">
      <h3>Local storage</h3>
      <div className="storage-card">
        <div className="storage-card-icon" aria-hidden="true">
          <Icon name="localServer" size={28} />
        </div>
        <div className="storage-card-body">
          <div className="storage-card-title">Stored on this device</div>
          <p className="hint" style={{ margin: '4px 0 0' }}>
            Keyhole never phones home. The encrypted vault lives in this browser
            {linkedName ? ', and mirrors to a file you chose.' : '.'}
          </p>
          <ul className="storage-facts">
            <li>
              <strong>Browser</strong>
              <span>Encrypted envelope in local storage</span>
            </li>
            <li>
              <strong>Disk file</strong>
              <span>
                {!canLink
                  ? 'Not available in this browser'
                  : linkedName
                    ? `${linkedName}${linkWritable ? '' : ' (re-grant write on next save)'}`
                    : 'Not linked'}
              </span>
            </li>
          </ul>
          {canLink && (
            <div className="button-row" style={{ marginTop: 12 }}>
              <button type="button" onClick={() => void linkFile()}>
                {linkedName ? 'Choose a different file' : 'Link a vault file'}
              </button>
              {linkedName && (
                <button type="button" className="ghost" onClick={() => void unlink()}>
                  Unlink file
                </button>
              )}
            </div>
          )}
          {status && <p className="hint">{status}</p>}
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------

function BackupSection({ vault, entryCount }: { vault: VaultController; entryCount: number }) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [status, setStatus] = useState<string | null>(null);
  const [pendingImport, setPendingImport] = useState<VaultFile | null>(null);

  const exportNow = () => {
    const file = vault.exportVault();
    if (!file) return;
    downloadVaultFile(file);
    setStatus(`Exported ${entryCount} entries (encrypted).`);
  };

  const onFile = async (file: File | undefined) => {
    if (!file) return;
    try {
      setPendingImport(await readVaultFromBlob(file));
      setStatus(null);
    } catch (err) {
      setStatus(err instanceof Error ? err.message : 'Could not read that file.');
    }
  };

  return (
    <div className="section">
      <h3>Backup</h3>
      <p className="hint" style={{ marginBottom: 12 }}>
        The exported file is the same encrypted envelope stored here — safe to keep anywhere, and readable only with
        your master password. It is also the format the Chrome extension imports.
      </p>
      <div className="button-row">
        <button type="button" onClick={exportNow}>
          Export vault file
        </button>
        <button type="button" onClick={() => inputRef.current?.click()}>
          Import vault file
        </button>
      </div>
      <input
        ref={inputRef}
        type="file"
        accept=".json,application/json"
        className="sr-only"
        onChange={(e) => void onFile(e.target.files?.[0])}
      />
      {status && <p className="hint">{status}</p>}

      <ConfirmDialog
        open={pendingImport !== null}
        title="Replace the current vault?"
        confirmLabel="Replace and lock"
        danger
        onCancel={() => setPendingImport(null)}
        onConfirm={() => {
          if (pendingImport) vault.importVault(pendingImport);
          setPendingImport(null);
        }}
      >
        <p>
          This replaces the vault stored in this browser with the imported file. Your current vault will be gone
          unless you exported it first.
        </p>
        <p className="hint">You will need the imported vault's master password to unlock it.</p>
      </ConfirmDialog>
    </div>
  );
}

// ---------------------------------------------------------------------------

function ChangeMasterPassword({ vault }: { vault: VaultController }) {
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [confirm, setConfirm] = useState('');
  const [confirming, setConfirming] = useState(false);
  const [done, setDone] = useState(false);

  const valid = next.length >= MIN_MASTER_PASSWORD_LENGTH && next === confirm && current.length > 0;

  const apply = async () => {
    setConfirming(false);
    try {
      await vault.changeMasterPassword(current, next);
      setCurrent('');
      setNext('');
      setConfirm('');
      setDone(true);
    } catch {
      /* error surfaced through vault.error */
    }
  };

  return (
    <div className="section">
      <h3>Master password</h3>
      {done && (
        <p className="hint" style={{ color: 'var(--ok)' }}>
          Master password changed. Re-export your backup — older exports still use the old password.
        </p>
      )}
      <div className="field">
        <label htmlFor="current-master">Current master password</label>
        <input
          id="current-master"
          type="password"
          autoComplete="current-password"
          value={current}
          onChange={(e) => setCurrent(e.target.value)}
        />
      </div>
      <div className="field">
        <label htmlFor="next-master">New master password</label>
        <input
          id="next-master"
          type="password"
          autoComplete="new-password"
          value={next}
          onChange={(e) => setNext(e.target.value)}
        />
        {next.length > 0 && <StrengthMeter password={next} />}
      </div>
      <div className="field">
        <label htmlFor="confirm-new-master">Confirm new master password</label>
        <input
          id="confirm-new-master"
          type="password"
          autoComplete="new-password"
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
        />
        {confirm.length > 0 && next !== confirm && (
          <p className="hint" style={{ color: 'var(--danger)' }}>
            Passwords do not match.
          </p>
        )}
      </div>
      <button type="button" onClick={() => setConfirming(true)} disabled={!valid || vault.busy}>
        {vault.busy ? 'Re-encrypting…' : 'Change master password'}
      </button>

      <ConfirmDialog
        open={confirming}
        title="Change master password?"
        confirmLabel="Re-encrypt vault"
        onCancel={() => setConfirming(false)}
        onConfirm={() => void apply()}
      >
        <p>This generates a new salt and a new vault key, then re-encrypts every entry.</p>
        <p className="hint">
          Any backup you exported earlier will still need the <em>old</em> password. Export a fresh copy afterwards.
        </p>
      </ConfirmDialog>
    </div>
  );
}

// ---------------------------------------------------------------------------

function DangerZone({ vault, entryCount }: { vault: VaultController; entryCount: number }) {
  const [confirming, setConfirming] = useState(false);
  const [typed, setTyped] = useState('');

  return (
    <div className="section">
      <h3 style={{ color: 'var(--danger)' }}>Danger zone</h3>
      <p className="hint" style={{ marginBottom: 12 }}>
        Deleting removes the encrypted vault from this browser. Exported files are unaffected.
      </p>
      <button type="button" className="danger" onClick={() => setConfirming(true)}>
        Delete vault from this browser
      </button>

      <ConfirmDialog
        open={confirming}
        title="Delete this vault?"
        confirmLabel="Delete vault"
        danger
        confirmDisabled={typed !== 'DELETE'}
        onCancel={() => {
          setConfirming(false);
          setTyped('');
        }}
        onConfirm={() => {
          setConfirming(false);
          setTyped('');
          vault.deleteVault();
        }}
      >
        <p>
          All <strong>{entryCount}</strong> entries will be removed from this browser and cannot be recovered without
          an exported backup.
        </p>
        <div className="field" style={{ marginTop: 12 }}>
          <label htmlFor="delete-confirm">Type DELETE to confirm</label>
          <input id="delete-confirm" value={typed} onChange={(e) => setTyped(e.target.value)} autoComplete="off" />
        </div>
      </ConfirmDialog>
    </div>
  );
}
