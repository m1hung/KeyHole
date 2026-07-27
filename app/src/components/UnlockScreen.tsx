/**
 * Onboarding and unlock.
 *
 * Handles all three cold-start states: no vault yet (create or import), a vault
 * present (unlock), and importing an external vault file.
 */

import { useRef, useState, type FormEvent } from 'react';
import { MIN_MASTER_PASSWORD_LENGTH, estimateStrength } from '@keyhole/core';
import { StrengthMeter } from './common.tsx';
import { readVaultFromBlob } from '../storage.ts';
import type { VaultController } from '../hooks/useVault.ts';
import { Icon } from './Icon.tsx';

/** Below this we warn but still allow — the length floor is the hard gate. */
const RECOMMENDED_BITS = 60;

export function UnlockScreen({ vault }: { vault: VaultController }) {
  const creating = vault.status === 'no-vault';
  return creating ? <CreateVault vault={vault} /> : <Unlock vault={vault} />;
}

// ---------------------------------------------------------------------------

function Unlock({ vault }: { vault: VaultController }) {
  const [password, setPassword] = useState('');
  const [attempt, setAttempt] = useState(0);

  const onSubmit = async (event: FormEvent) => {
    event.preventDefault();
    await vault.unlock(password);
    setAttempt((n) => n + 1);
    setPassword('');
  };

  return (
    <div className="center-screen">
      {/* `key` forces a remount so the shake replays on every failed attempt,
          not just the first. */}
      <form className={`card${vault.error ? ' rejected' : ''}`} key={attempt} onSubmit={onSubmit}>
        <h1>
          <Icon name="vault" size={26} />
          Keyhole
        </h1>
        <p className="subtitle">Your vault is locked.</p>
        <p className="local-badge">
          <Icon name="localServer" size={14} />
          Encrypted vault stays on this device
        </p>

        {vault.error && <div className="error">{vault.error}</div>}

        <div className="field">
          <label htmlFor="master-password">Master password</label>
          <input
            id="master-password"
            type="password"
            autoFocus
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            disabled={vault.busy}
          />
        </div>

        <button
          type="submit"
          className={`primary${vault.busy ? ' deriving' : ''}`}
          style={{ width: '100%' }}
          disabled={vault.busy || password.length === 0}
        >
          {vault.busy ? 'Deriving key…' : 'Unlock'}
        </button>

        <p className="hint" style={{ textAlign: 'center', marginTop: 12 }}>
          Argon2id takes a moment by design.
        </p>

        <ImportControl vault={vault} label="Open a different vault file" />
      </form>
    </div>
  );
}

// ---------------------------------------------------------------------------

function CreateVault({ vault }: { vault: VaultController }) {
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [hardened, setHardened] = useState(false);
  const [acknowledged, setAcknowledged] = useState(false);

  const tooShort = password.length > 0 && password.length < MIN_MASTER_PASSWORD_LENGTH;
  const mismatch = confirm.length > 0 && password !== confirm;
  const weak = password.length > 0 && estimateStrength(password).bits < RECOMMENDED_BITS;
  const canSubmit =
    password.length >= MIN_MASTER_PASSWORD_LENGTH && password === confirm && acknowledged && !vault.busy;

  /**
   * Why the button is disabled, in the order a user works down the form.
   *
   * Without this the form is a dead end: you type a perfectly good password,
   * the button does nothing, and there is no way to tell that the unticked
   * acknowledgement is what is blocking you.
   */
  const blocker = ((): string | null => {
    if (password.length === 0) return 'Enter a master password to continue.';
    if (tooShort) return `Master password must be at least ${MIN_MASTER_PASSWORD_LENGTH} characters — ${MIN_MASTER_PASSWORD_LENGTH - password.length} more to go.`;
    if (confirm.length === 0) return 'Re-enter your master password to confirm it.';
    if (password !== confirm) return 'The two passwords do not match.';
    if (!acknowledged) return 'Tick the box above to confirm you understand there is no password recovery.';
    return null;
  })();

  const onSubmit = async (event: FormEvent) => {
    event.preventDefault();
    if (!canSubmit) return;
    await vault.createVault(password, hardened ? 'hardened' : 'interactive');
    setPassword('');
    setConfirm('');
  };

  return (
    <div className="center-screen">
      <form className="card" onSubmit={onSubmit}>
        <h1>
          <Icon name="vault" size={26} />
          Keyhole
        </h1>
        <p className="subtitle">Create a vault. Everything stays on this device.</p>
        <p className="local-badge">
          <Icon name="localServer" size={14} />
          No accounts · No cloud · No telemetry
        </p>

        {vault.error && <div className="error">{vault.error}</div>}

        <div className="field">
          <label htmlFor="new-master">Master password</label>
          <input
            id="new-master"
            type="password"
            autoFocus
            autoComplete="new-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            aria-describedby="master-help"
          />
          {password.length > 0 && <StrengthMeter password={password} />}
          <p className="hint" id="master-help">
            At least {MIN_MASTER_PASSWORD_LENGTH} characters. A long passphrase of unrelated words beats a short
            complex one.
          </p>
          {tooShort && <p className="hint" style={{ color: 'var(--danger)' }}>Too short.</p>}
          {weak && !tooShort && (
            <p className="hint" style={{ color: 'var(--warn)' }}>
              This is weaker than recommended. It is the only thing protecting your vault.
            </p>
          )}
        </div>

        <div className="field">
          <label htmlFor="confirm-master">Confirm master password</label>
          <input
            id="confirm-master"
            type="password"
            autoComplete="new-password"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
          />
          {mismatch && <p className="hint" style={{ color: 'var(--danger)' }}>Passwords do not match.</p>}
        </div>

        <div className="checkbox-row">
          <input id="hardened" type="checkbox" checked={hardened} onChange={(e) => setHardened(e.target.checked)} />
          <label htmlFor="hardened">Hardened key derivation (256 MiB, slower unlock)</label>
        </div>

        <div className="checkbox-row" style={{ marginTop: 16, alignItems: 'flex-start' }}>
          <input
            id="ack"
            type="checkbox"
            checked={acknowledged}
            onChange={(e) => setAcknowledged(e.target.checked)}
            style={{ marginTop: 3 }}
          />
          <label htmlFor="ack">
            I understand there is <strong>no recovery</strong>. If I forget this password, the vault is
            permanently unreadable — by design.
          </label>
        </div>

        <button
          type="submit"
          className={`primary${vault.busy ? ' deriving' : ''}`}
          style={{ width: '100%', marginTop: 8 }}
          disabled={!canSubmit}
          aria-describedby={blocker ? 'submit-blocker' : undefined}
        >
          {vault.busy ? 'Deriving key…' : 'Create vault'}
        </button>

        {blocker && (
          <p className="hint" id="submit-blocker" role="status" style={{ textAlign: 'center', marginTop: 8 }}>
            {blocker}
          </p>
        )}

        <ImportControl vault={vault} label="Import an existing vault file" />
      </form>
    </div>
  );
}

// ---------------------------------------------------------------------------

function ImportControl({ vault, label }: { vault: VaultController; label: string }) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [importError, setImportError] = useState<string | null>(null);

  const onFile = async (file: File | undefined) => {
    if (!file) return;
    setImportError(null);
    try {
      vault.importVault(await readVaultFromBlob(file));
    } catch (err) {
      setImportError(err instanceof Error ? err.message : 'Could not read that file.');
    }
  };

  return (
    <div className="section" style={{ marginTop: 20, paddingTop: 16 }}>
      <input
        ref={inputRef}
        type="file"
        accept=".json,application/json"
        className="sr-only"
        onChange={(e) => void onFile(e.target.files?.[0])}
      />
      <button type="button" className="ghost" style={{ width: '100%' }} onClick={() => inputRef.current?.click()}>
        {label}
      </button>
      {importError && (
        <p className="hint" style={{ color: 'var(--danger)' }}>
          {importError}
        </p>
      )}
    </div>
  );
}
