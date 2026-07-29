/**
 * Full-tab vault manager.
 *
 * Like the popup, this page holds no key material. It drives the service
 * worker, which owns the session. Secrets are fetched one at a time on an
 * explicit reveal.
 */

import { useCallback, useEffect, useState } from 'react';
import { MIN_MASTER_PASSWORD_LENGTH, estimateStrength, generatePassword, DEFAULT_GENERATOR_OPTIONS } from '@keyhole/core';
import { sendToBackground, type EntrySummary } from '../shared/messages.ts';
import { Icon } from '../../../app/src/components/Icon.tsx';
import { ConfirmDialog } from '../../../app/src/components/common.tsx';
import { SyncPanel } from './SyncPanel.tsx';

type Screen = 'loading' | 'no-vault' | 'locked' | 'unlocked';
type View = 'entries' | 'sync';

interface EntryDraft {
  id?: string;
  title: string;
  username: string;
  password: string;
  urls: string[];
  notes: string;
  tags: string[];
  totpSecret: string | null;
}

const blankDraft = (): EntryDraft => ({
  title: '',
  username: '',
  password: '',
  urls: [],
  notes: '',
  tags: [],
  totpSecret: null,
});

export function Options() {
  const [screen, setScreen] = useState<Screen>('loading');
  const [entries, setEntries] = useState<EntrySummary[]>([]);
  /** Total in the vault, unlike `entries` which is filtered by the search box. */
  const [entryCount, setEntryCount] = useState(0);
  const [query, setQuery] = useState('');
  const [draft, setDraft] = useState<EntryDraft | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [view, setView] = useState<View>('entries');
  const [theme, setTheme] = useState<'light' | 'dark' | 'system'>('system');

  useEffect(() => {
    document.documentElement.dataset['theme'] = theme;
  }, [theme]);

  const refresh = useCallback(async () => {
    const state = await sendToBackground({ type: 'GET_STATE' });
    if (!state.ok || state.type !== 'STATE') {
      setScreen('locked');
      return;
    }
    setTheme(state.theme);
    setEntryCount(state.entryCount);
    const next: Screen = !state.hasVault ? 'no-vault' : state.locked ? 'locked' : 'unlocked';
    setScreen(next);
    if (next === 'unlocked') {
      const listed = await sendToBackground({ type: 'LIST_ENTRIES', query });
      if (listed.ok && listed.type === 'ENTRIES') setEntries(listed.entries);
    }
  }, [query]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const flash = (message: string) => {
    setNotice(message);
    window.setTimeout(() => setNotice(null), 3000);
  };

  const openEntry = async (id: string) => {
    // Fetch the two secret fields explicitly; the list never carried them.
    const [pw, user] = await Promise.all([
      sendToBackground({ type: 'REVEAL_SECRET', entryId: id, field: 'password' }),
      sendToBackground({ type: 'REVEAL_SECRET', entryId: id, field: 'username' }),
    ]);
    const summary = entries.find((e) => e.id === id);
    if (!summary) return;
    setDraft({
      id,
      title: summary.title,
      username: user.ok && user.type === 'SECRET' ? user.value : '',
      password: pw.ok && pw.type === 'SECRET' ? pw.value : '',
      urls: summary.host ? [`https://${summary.host}`] : [],
      notes: '',
      tags: [],
      totpSecret: null,
    });
  };

  const saveDraft = async () => {
    if (!draft) return;
    setBusy(true);
    const response = await sendToBackground({ type: 'SAVE_ENTRY', entry: draft });
    setBusy(false);
    if (!response.ok) {
      setError(response.error);
      return;
    }
    setDraft(null);
    flash('Entry saved.');
    await refresh();
  };

  const removeEntry = async (id: string) => {
    const response = await sendToBackground({ type: 'DELETE_ENTRY', entryId: id });
    if (!response.ok) {
      setError(response.error);
      return;
    }
    setDraft(null);
    flash('Entry deleted.');
    await refresh();
  };

  const exportVault = async () => {
    const response = await sendToBackground({ type: 'EXPORT_VAULT' });
    if (!response.ok || response.type !== 'EXPORT') {
      setError(response.ok ? 'Unexpected response.' : response.error);
      return;
    }
    const blob = new Blob([JSON.stringify(response.file, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = 'keyhole-vault.keyhole.json';
    anchor.click();
    URL.revokeObjectURL(url);
    flash('Encrypted vault exported.');
  };

  /**
   * Sign out of this browser: the stored vault, the mirrored preferences and the
   * sync account all go. Callers gate this behind a typed confirmation.
   */
  const resetVault = async () => {
    setBusy(true);
    const response = await sendToBackground({ type: 'RESET_VAULT' });
    setBusy(false);
    if (!response.ok) {
      setError(response.error);
      return;
    }
    setDraft(null);
    setEntries([]);
    setQuery('');
    setError(null);
    setView('entries');
    flash('Vault removed from this browser.');
    await refresh();
  };

  const importVault = async (file: File) => {
    try {
      const parsed = JSON.parse(await file.text()) as unknown;
      const response = await sendToBackground({ type: 'IMPORT_VAULT', file: parsed });
      if (!response.ok) {
        setError(response.error);
        return;
      }
      flash('Vault imported. Unlock it with its own master password.');
      await refresh();
    } catch {
      setError('That file is not a valid Keyhole vault.');
    }
  };

  if (screen === 'loading') return <div className="center-screen">Loading…</div>;

  if (screen === 'no-vault' || screen === 'locked') {
    return (
      <SetupOrUnlock
        mode={screen}
        error={error}
        notice={notice}
        busy={busy}
        onImport={importVault}
        onReset={resetVault}
        onSubmit={async (password) => {
          setBusy(true);
          setError(null);
          const response = await sendToBackground(
            screen === 'no-vault'
              ? { type: 'CREATE_VAULT', masterPassword: password }
              : { type: 'UNLOCK', masterPassword: password },
          );
          setBusy(false);
          if (!response.ok) {
            setError(response.error);
            return;
          }
          await refresh();
        }}
      />
    );
  }

  return (
    <div className="app">
      <header className="topbar">
        <span className="brand">
          <Icon name="vault" size={20} />
          Keyhole
        </span>
        <input
          className="search"
          type="search"
          placeholder="Search entries…"
          aria-label="Search entries"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
        <div className="spacer" />
        <button
          type="button"
          className={view === 'sync' ? 'primary' : 'ghost'}
          onClick={() => setView((v) => (v === 'sync' ? 'entries' : 'sync'))}
        >
          Sync
        </button>
        <button type="button" className="ghost" onClick={() => void exportVault()}>
          Export
        </button>
        <button
          type="button"
          onClick={() => void sendToBackground({ type: 'LOCK' }).then(refresh)}
        >
          Lock
        </button>
      </header>

      <div className={view === 'sync' ? 'settings-layout' : 'columns detail-open'}>
        {view === 'entries' ? (
          <>
            <div className="list-pane">
              <div style={{ padding: 12, borderBottom: '1px solid var(--border)' }}>
                <button type="button" className="primary" style={{ width: '100%' }} onClick={() => setDraft(blankDraft())}>
                  + New entry
                </button>
              </div>
              {entries.length === 0 ? (
                <div className="empty-state">
                  <p>{query ? 'No matches.' : 'No entries yet.'}</p>
                </div>
              ) : (
                <ul className="entry-list">
                  {entries.map((entry) => (
                    <li key={entry.id}>
                      <button
                        type="button"
                        className="entry-item"
                        aria-current={draft?.id === entry.id}
                        onClick={() => void openEntry(entry.id)}
                      >
                        <div className="title">{entry.title}</div>
                        <div className="meta">
                          {entry.username || <em>no username</em>}
                          {entry.host ? ` · ${entry.host}` : ''}
                        </div>
                      </button>
                    </li>
                  ))}
                </ul>
              )}
            </div>

            <main className="detail-pane">
              {error && <div className="error">{error}</div>}
              {notice && <p className="hint" style={{ color: 'var(--ok)' }}>{notice}</p>}

              {draft ? (
                <EntryForm
                  draft={draft}
                  busy={busy}
                  onChange={setDraft}
                  onSave={() => void saveDraft()}
                  onCancel={() => setDraft(null)}
                  {...(draft.id ? { onDelete: () => void removeEntry(draft.id!) } : {})}
                />
              ) : (
                <div className="empty-state">
                  <p style={{ fontWeight: 600 }}>Select an entry</p>
                  <p className="hint">Or create a new one.</p>
                </div>
              )}
            </main>
          </>
        ) : (
          <main className="settings-pane">
            {error && <div className="error">{error}</div>}
            {notice && <p className="hint" style={{ color: 'var(--ok)' }}>{notice}</p>}
            <SyncPanel
              theme={theme}
              onThemeChange={(next) => {
                setTheme(next);
                void sendToBackground({ type: 'SET_THEME', theme: next });
              }}
            />
            <DangerZone entryCount={entryCount} busy={busy} onReset={() => void resetVault()} />
          </main>
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------

/**
 * Sign out / start over.
 *
 * Mirrors the desktop app's danger zone, including the typed confirmation: the
 * encrypted vault is the only copy unless the user exported one, so a stray
 * click must not be enough to destroy it.
 */
function DangerZone({
  entryCount,
  busy,
  onReset,
}: {
  entryCount: number;
  busy: boolean;
  onReset: () => void;
}) {
  const [confirming, setConfirming] = useState(false);
  const [typed, setTyped] = useState('');

  const close = () => {
    setConfirming(false);
    setTyped('');
  };

  return (
    <div className="section">
      <h3 style={{ color: 'var(--danger)' }}>Danger zone</h3>
      <p className="hint" style={{ marginBottom: 12 }}>
        Signs out of this browser: the encrypted vault, your preferences and the sync server account are
        removed from Chrome's storage, leaving the create-vault screen. Exported files and anything already
        on a sync server are unaffected.
      </p>
      <button type="button" className="danger" disabled={busy} onClick={() => setConfirming(true)}>
        Delete vault and start over
      </button>

      <ConfirmDialog
        open={confirming}
        title="Delete this vault?"
        confirmLabel="Delete and start over"
        danger
        confirmDisabled={typed !== 'DELETE'}
        onCancel={close}
        onConfirm={() => {
          close();
          onReset();
        }}
      >
        <p>
          All <strong>{entryCount}</strong> {entryCount === 1 ? 'entry' : 'entries'} will be removed from this
          browser, along with the saved sync server and account id.
        </p>
        <p className="hint">Without an exported backup, or a copy on a sync server, this vault cannot be recovered.</p>
        <div className="field" style={{ marginTop: 12 }}>
          <label htmlFor="reset-confirm">Type DELETE to confirm</label>
          <input id="reset-confirm" value={typed} onChange={(e) => setTyped(e.target.value)} autoComplete="off" />
        </div>
      </ConfirmDialog>
    </div>
  );
}

// ---------------------------------------------------------------------------

function EntryForm({
  draft,
  busy,
  onChange,
  onSave,
  onCancel,
  onDelete,
}: {
  draft: EntryDraft;
  busy: boolean;
  onChange: (draft: EntryDraft) => void;
  onSave: () => void;
  onCancel: () => void;
  onDelete?: () => void;
}) {
  const [revealed, setRevealed] = useState(false);

  return (
    <div>
      <div className="detail-header">
        <h2>{draft.title || 'New entry'}</h2>
        <div className="button-row">
          <button type="button" className="ghost" onClick={onCancel}>
            Cancel
          </button>
          <button type="button" className="primary" onClick={onSave} disabled={busy || draft.title.trim().length === 0}>
            Save
          </button>
        </div>
      </div>

      <div className="field">
        <label htmlFor="opt-title">Title</label>
        <input id="opt-title" value={draft.title} onChange={(e) => onChange({ ...draft, title: e.target.value })} />
      </div>

      <div className="field">
        <label htmlFor="opt-username">Username</label>
        <input
          id="opt-username"
          value={draft.username}
          autoComplete="off"
          onChange={(e) => onChange({ ...draft, username: e.target.value })}
        />
      </div>

      <div className="field">
        <label htmlFor="opt-password">Password</label>
        <div className="field-row">
          <input
            id="opt-password"
            className="mono"
            type={revealed ? 'text' : 'password'}
            value={draft.password}
            autoComplete="new-password"
            onChange={(e) => onChange({ ...draft, password: e.target.value })}
          />
          <button type="button" className="icon" onClick={() => setRevealed((r) => !r)} aria-pressed={revealed}>
            <Icon name={revealed ? 'eyeOff' : 'eye'} />
          </button>
          <button
            type="button"
            className="icon"
            title="Generate"
            onClick={() => {
              onChange({ ...draft, password: generatePassword(DEFAULT_GENERATOR_OPTIONS) });
              setRevealed(true);
            }}
          >
            <Icon name="refresh" />
          </button>
        </div>
        {draft.password.length > 0 && (
          <p className="hint">
            {estimateStrength(draft.password).bits} bits · {estimateStrength(draft.password).label}
          </p>
        )}
      </div>

      <div className="field">
        <label htmlFor="opt-urls">Websites (one per line)</label>
        <textarea
          id="opt-urls"
          value={draft.urls.join('\n')}
          spellCheck={false}
          onChange={(e) =>
            onChange({ ...draft, urls: e.target.value.split('\n').map((u) => u.trim()).filter(Boolean) })
          }
        />
      </div>

      <div className="field">
        <label htmlFor="opt-notes">Notes</label>
        <textarea id="opt-notes" value={draft.notes} onChange={(e) => onChange({ ...draft, notes: e.target.value })} />
      </div>

      <div className="field">
        <label htmlFor="opt-totp">TOTP secret (optional)</label>
        <input
          id="opt-totp"
          className="mono"
          value={draft.totpSecret ?? ''}
          autoComplete="off"
          onChange={(e) => onChange({ ...draft, totpSecret: e.target.value.trim() || null })}
        />
      </div>

      {onDelete && (
        <div className="section">
          <button type="button" className="danger" onClick={onDelete}>
            Delete entry
          </button>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------

function SetupOrUnlock({
  mode,
  error,
  notice,
  busy,
  onSubmit,
  onImport,
  onReset,
}: {
  mode: 'no-vault' | 'locked';
  error: string | null;
  notice: string | null;
  busy: boolean;
  onSubmit: (password: string) => Promise<void>;
  onImport: (file: File) => Promise<void>;
  onReset: () => Promise<void>;
}) {
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [purging, setPurging] = useState(false);
  const [purgeTyped, setPurgeTyped] = useState('');
  const creating = mode === 'no-vault';
  const valid = creating ? password.length >= MIN_MASTER_PASSWORD_LENGTH && password === confirm : password.length > 0;

  const closePurge = () => {
    setPurging(false);
    setPurgeTyped('');
  };

  return (
    <div className="center-screen">
      <form
        className="card"
        onSubmit={(e) => {
          e.preventDefault();
          if (valid) void onSubmit(password).then(() => setPassword(''));
        }}
      >
        <h1>
          <Icon name="vault" size={26} />
          Keyhole
        </h1>
        <p className="subtitle">{creating ? 'Create a vault for this browser.' : 'Unlock your vault.'}</p>

        {error && <div className="error">{error}</div>}
        {notice && <p className="hint" style={{ color: 'var(--ok)' }}>{notice}</p>}

        <div className="field">
          <label htmlFor="opt-master">Master password</label>
          <input
            id="opt-master"
            type="password"
            autoFocus
            autoComplete={creating ? 'new-password' : 'current-password'}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
          {creating && password.length > 0 && (
            <p className="hint">
              {estimateStrength(password).bits} bits · {estimateStrength(password).label}
            </p>
          )}
        </div>

        {creating && (
          <div className="field">
            <label htmlFor="opt-confirm">Confirm master password</label>
            <input
              id="opt-confirm"
              type="password"
              autoComplete="new-password"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
            />
            {confirm.length > 0 && password !== confirm && (
              <p className="hint" style={{ color: 'var(--danger)' }}>Passwords do not match.</p>
            )}
          </div>
        )}

        <button type="submit" className="primary" style={{ width: '100%' }} disabled={!valid || busy}>
          {busy ? 'Deriving key…' : creating ? 'Create vault' : 'Unlock'}
        </button>

        <div className="section" style={{ marginTop: 20, paddingTop: 16 }}>
          <label htmlFor="opt-import">Import a vault exported from the Keyhole app</label>
          <input
            id="opt-import"
            type="file"
            accept=".json,application/json"
            onChange={(e) => {
              const file = e.target.files?.[0];
              if (file) void onImport(file);
            }}
          />
        </div>

        {/* Only reachable while locked — this is the way out of a forgotten
            master password, which is exactly when the settings page cannot be
            opened to reach the danger zone. */}
        {!creating && (
          <div className="section" style={{ marginTop: 12, paddingTop: 12 }}>
            <button
              type="button"
              className="ghost danger-text"
              style={{ width: '100%' }}
              disabled={busy}
              onClick={() => setPurging(true)}
            >
              Delete vault and start over
            </button>
            <p className="hint" style={{ textAlign: 'center', marginTop: 8 }}>
              Forgot the password, or handing this browser to someone else? This erases the encrypted copy stored
              here, along with the saved sync account.
            </p>
          </div>
        )}
      </form>

      <ConfirmDialog
        open={purging}
        title="Delete this vault?"
        confirmLabel="Delete and start over"
        danger
        confirmDisabled={purgeTyped !== 'DELETE'}
        onCancel={closePurge}
        onConfirm={() => {
          closePurge();
          void onReset();
        }}
      >
        <p>
          The encrypted vault, your preferences and the saved sync server settings are removed from this browser.
          You will return to the create-vault screen.
        </p>
        <p className="hint">Without an exported backup, or a copy on a sync server, this vault cannot be recovered.</p>
        <div className="field" style={{ marginTop: 12 }}>
          <label htmlFor="purge-confirm">Type DELETE to confirm</label>
          <input
            id="purge-confirm"
            value={purgeTyped}
            onChange={(e) => setPurgeTyped(e.target.value)}
            autoComplete="off"
          />
        </div>
      </ConfirmDialog>
    </div>
  );
}
