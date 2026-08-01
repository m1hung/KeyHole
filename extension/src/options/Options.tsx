/**
 * Full-tab vault manager.
 *
 * Like the popup, this page holds no key material. It drives the service
 * worker, which owns the session. Secrets are fetched one at a time on an
 * explicit reveal.
 */

import { useCallback, useEffect, useState } from 'react';
import {
  MIN_MASTER_PASSWORD_LENGTH,
  TRASH_RETENTION_DAYS,
  estimateStrength,
  groupIssuesByEntry,
  generatePassword,
  DEFAULT_GENERATOR_OPTIONS,
  normalizeTotpConfig,
  parseOtpAuthUri,
  type Attachment,
  type CustomField,
  type HealthIssueKind,
  type TotpConfig,
} from '@keyhole/core';
import { sendToBackground, type EntrySummary, type PasskeySummary, type Response as BackgroundResponse } from '../shared/messages.ts';
import { Icon } from '../../../app/src/components/Icon.tsx';
import { ConfirmDialog, FINDINGS_PAGE } from '../../../app/src/components/common.tsx';
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
  totpConfig: TotpConfig | null;
  customFields: CustomField[];
  attachments: Attachment[];
  passkeys: PasskeySummary[];
}

const blankDraft = (): EntryDraft => ({
  title: '',
  username: '',
  password: '',
  urls: [],
  notes: '',
  tags: [],
  totpSecret: null,
  totpConfig: null,
  customFields: [],
  attachments: [],
  passkeys: [],
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
  /**
   * Bumped whenever a panel mutates the vault. Panels below hold their own copies
   * of it — the trash in particular — and a bulk delete in one of them has to
   * reach the others, or the trash keeps claiming to be empty while holding what
   * was just deleted.
   */
  const [vaultVersion, setVaultVersion] = useState(0);

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

  const vaultChanged = useCallback(() => {
    setVaultVersion((version) => version + 1);
    void refresh();
  }, [refresh]);

  const flash = (message: string) => {
    setNotice(message);
    window.setTimeout(() => setNotice(null), 3000);
  };

  const openEntry = async (id: string) => {
    const response = await sendToBackground({ type: 'GET_ENTRY', entryId: id });
    if (!response.ok || response.type !== 'ENTRY') {
      setError(response.ok ? 'Unexpected response.' : response.error);
      return;
    }
    const { entry } = response;
    setDraft({
      id: entry.id,
      title: entry.title,
      username: entry.username,
      password: entry.password,
      urls: entry.urls,
      notes: entry.notes,
      tags: entry.tags,
      totpSecret: entry.totpSecret,
      totpConfig: entry.totpConfig,
      customFields: entry.customFields,
      attachments: entry.attachments,
      passkeys: entry.passkeys,
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

  const removePasskeyFromDraft = async (passkeyId: string) => {
    if (!draft?.id) return;
    setBusy(true);
    const response = await sendToBackground({
      type: 'REMOVE_PASSKEY',
      entryId: draft.id,
      passkeyId,
    });
    setBusy(false);
    if (!response.ok) {
      setError(response.error);
      return;
    }
    setDraft({ ...draft, passkeys: draft.passkeys.filter((pk) => pk.id !== passkeyId) });
    flash('Passkey removed.');
    await refresh();
  };

  const removeEntry = async (id: string) => {
    const response = await sendToBackground({ type: 'DELETE_ENTRY', entryId: id });
    if (!response.ok) {
      setError(response.error);
      return;
    }
    setDraft(null);
    flash('Entry moved to the trash.');
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
                          {entry.hasPasskey ? ' · passkey' : ''}
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
                  onRemovePasskey={(passkeyId) => void removePasskeyFromDraft(passkeyId)}
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
            <VaultHealth onChanged={vaultChanged} />
            <Trash version={vaultVersion} onChanged={vaultChanged} />
            <ChangeMasterPassword />
            <DangerZone entryCount={entryCount} busy={busy} onReset={() => void resetVault()} />
          </main>
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------

/**
 * Deleted entries, still restorable.
 *
 * Deleting is a soft delete now, so without this an extension-only user could put
 * an entry beyond reach with no way to get it back or to destroy it deliberately —
 * the same gap that left them unable to change their master password.
 */
function Trash({ version, onChanged }: { version: number; onChanged: () => void }) {
  const [entries, setEntries] = useState<EntrySummary[]>([]);
  const [confirming, setConfirming] = useState<EntrySummary | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    const response = await sendToBackground({ type: 'LIST_TRASH' });
    if (!response.ok) {
      setError(response.error);
      return;
    }
    if (response.type === 'ENTRIES') setEntries(response.entries);
  }, []);

  // `version` is the dependency that matters: it changes when another panel
  // deletes something, which is what puts entries in here.
  useEffect(() => {
    void load();
  }, [load, version]);

  const act = async (message: { type: 'RESTORE_ENTRY' | 'PURGE_ENTRY'; entryId: string }) => {
    const response = await sendToBackground(message);
    if (!response.ok) {
      setError(response.error);
      return;
    }
    await load();
    onChanged();
  };

  if (entries.length === 0) return null;

  return (
    <div className="section">
      <h3>Trash</h3>
      <p className="hint" style={{ marginBottom: 12 }}>
        Deleted entries are hidden from your list and from autofill, and are removed for good after{' '}
        {TRASH_RETENTION_DAYS} days.
      </p>
      {error && <p className="hint" style={{ color: 'var(--danger)' }}>{error}</p>}

      <ul className="entry-list">
        {entries.map((entry) => (
          <li key={entry.id}>
            <span className="entry-item" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span className="entry-body">
                <div className="title">{entry.title}</div>
                <div className="meta">
                  {entry.username || 'No username'}
                  {entry.deletedAt ? ` · deleted ${new Date(entry.deletedAt).toLocaleDateString()}` : ''}
                </div>
              </span>
              <span className="button-row">
                <button type="button" onClick={() => void act({ type: 'RESTORE_ENTRY', entryId: entry.id })}>
                  Restore
                </button>
                <button type="button" className="ghost danger-text" onClick={() => setConfirming(entry)}>
                  Delete forever
                </button>
              </span>
            </span>
          </li>
        ))}
      </ul>

      <ConfirmDialog
        open={confirming !== null}
        title="Delete this entry for good?"
        confirmLabel="Delete forever"
        danger
        onCancel={() => setConfirming(null)}
        onConfirm={() => {
          const entry = confirming;
          setConfirming(null);
          if (entry) void act({ type: 'PURGE_ENTRY', entryId: entry.id });
        }}
      >
        <p>
          <strong>{confirming?.title ?? 'This entry'}</strong> and its password history will be destroyed here and on
          every synced device. This cannot be undone.
        </p>
      </ConfirmDialog>
    </div>
  );
}

// ---------------------------------------------------------------------------

/**
 * Offline vault audit — reused, weak, stale and empty passwords.
 *
 * The analysis has always existed in core; it was only ever surfaced in the desktop
 * app, so extension-only users had no way to see it. It runs in the service worker
 * (the only process holding decrypted entries) and returns findings, never
 * passwords. Nothing leaves the device and nothing is stored.
 */
function VaultHealth({ onChanged }: { onChanged: () => void }) {
  const [report, setReport] = useState<Extract<BackgroundResponse, { type: 'HEALTH' }> | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selection, setSelection] = useState<ReadonlySet<string>>(() => new Set());
  const [confirmTrash, setConfirmTrash] = useState(false);
  const [showAll, setShowAll] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [breachEnabled, setBreachEnabled] = useState(false);
  const [breachBusy, setBreachBusy] = useState(false);
  const [breachError, setBreachError] = useState<string | null>(null);
  const [breaches, setBreaches] = useState<{ title: string; count: number }[] | null>(null);

  useEffect(() => {
    void sendToBackground({ type: 'GET_STATE' }).then((state) => {
      if (state.ok && state.type === 'STATE') setBreachEnabled(state.breachCheckEnabled);
    });
  }, []);

  /* One row per entry, not per issue: a login that is weak *and* reused *and*
     stale appears three times in the flat list, and a checkbox on each would make
     "3 selected" mean one password. See groupIssuesByEntry. */
  const findings = report ? groupIssuesByEntry(report.issues) : [];
  const selectedIds = findings.filter((f) => selection.has(f.entryId)).map((f) => f.entryId);
  const visible = showAll ? findings : findings.slice(0, FINDINGS_PAGE);

  const kindCounts = new Map<HealthIssueKind, number>();
  for (const finding of findings) {
    for (const kind of finding.kinds) kindCounts.set(kind, (kindCounts.get(kind) ?? 0) + 1);
  }

  /** Whole categories are the usual unit of "deal with this": every reused password. */
  const selectKind = (kind: HealthIssueKind) =>
    setSelection((current) => {
      const next = new Set(current);
      for (const finding of findings) if (finding.kinds.includes(kind)) next.add(finding.entryId);
      return next;
    });

  const scan = async () => {
    setBusy(true);
    setError(null);
    setSelection(new Set());
    setShowAll(false);
    const response = await sendToBackground({ type: 'HEALTH_REPORT' });
    setBusy(false);
    if (!response.ok) {
      setError(response.error);
      return;
    }
    if (response.type === 'HEALTH') setReport(response);
  };

  const run = async () => {
    setNotice(null);
    await scan();
  };

  /**
   * Bulk trash, then re-scan.
   *
   * The re-scan is not cosmetic: unlike the app this report is a snapshot from
   * another process, so leaving it on screen would keep offering to delete
   * entries that are already binned.
   */
  const trashSelected = async () => {
    const entryIds = selectedIds;
    if (entryIds.length === 0) return;
    setBusy(true);
    setError(null);
    setNotice(null);
    const response = await sendToBackground({ type: 'DELETE_ENTRIES', entryIds });
    setBusy(false);
    if (!response.ok) {
      setError(response.error);
      return;
    }
    onChanged();
    await scan();
    setNotice(
      `Moved ${entryIds.length} ${entryIds.length === 1 ? 'entry' : 'entries'} to the trash — restorable below.`,
    );
  };

  const setBreach = async (enabled: boolean) => {
    const response = await sendToBackground({ type: 'SET_BREACH_CHECK', enabled });
    if (!response.ok) {
      setBreachError(response.error);
      return;
    }
    setBreachEnabled(enabled);
    if (!enabled) {
      setBreaches(null);
      setBreachError(null);
    }
  };

  const runBreachCheck = async () => {
    setBreachBusy(true);
    setBreachError(null);
    setBreaches(null);
    try {
      const origin = 'https://api.pwnedpasswords.com/*';
      const have = await chrome.permissions.contains({ origins: [origin] });
      if (!have) {
        const granted = await chrome.permissions.request({ origins: [origin] });
        if (!granted) {
          setBreachError('Permission denied. Breach checks need access to api.pwnedpasswords.com.');
          return;
        }
      }
      const { checkPasswordBreachCount } = await import('../../../app/src/breach/check.ts');
      const listed = await sendToBackground({ type: 'LIST_ENTRIES' });
      if (!listed.ok || listed.type !== 'ENTRIES') {
        setBreachError(listed.ok ? 'Unexpected response.' : listed.error);
        return;
      }
      // Reveal each password one at a time — same trusted path as the editor.
      const findings: { title: string; count: number }[] = [];
      const seen = new Map<string, number>();
      for (const summary of listed.entries) {
        const secret = await sendToBackground({
          type: 'REVEAL_SECRET',
          entryId: summary.id,
          field: 'password',
        });
        if (!secret.ok || secret.type !== 'SECRET' || secret.value.length === 0) continue;
        let count = seen.get(secret.value);
        if (count === undefined) {
          count = await checkPasswordBreachCount(secret.value);
          seen.set(secret.value, count);
        }
        if (count > 0) findings.push({ title: summary.title, count });
      }
      setBreaches(findings);
    } catch (err) {
      setBreachError(err instanceof Error ? err.message : 'Breach check failed.');
    } finally {
      setBreachBusy(false);
    }
  };

  return (
    <div className="section">
      <h3>Vault health</h3>
      <p className="hint" style={{ marginBottom: 12 }}>
        Checks your logins for reused, weak, unchanged and missing passwords. Runs entirely on this device — no
        password, hash or count is sent anywhere, and the result is not stored.
      </p>

      <button type="button" disabled={busy} onClick={() => void run()}>
        {busy ? 'Checking…' : report ? 'Check again' : 'Check vault'}
      </button>

      {error && <p className="hint" style={{ color: 'var(--danger)' }}>{error}</p>}
      {notice && <p className="hint" style={{ color: 'var(--ok)' }}>{notice}</p>}

      {report && (
        <div style={{ marginTop: 12 }}>
          <p className="hint">
            Checked {report.loginCount} logins —{' '}
            {findings.length === 0
              ? 'no issues found.'
              : `${report.issues.length} finding${report.issues.length === 1 ? '' : 's'} across ${findings.length} ${findings.length === 1 ? 'entry' : 'entries'}.`}
          </p>
          {findings.length > 0 && (
            <>
              <div className="findings-toolbar">
                <div className="checkbox-row" style={{ margin: 0 }}>
                  <input
                    id="health-select-all"
                    type="checkbox"
                    checked={selectedIds.length === findings.length}
                    ref={(el) => {
                      if (el) el.indeterminate = selectedIds.length > 0 && selectedIds.length < findings.length;
                    }}
                    onChange={() =>
                      setSelection(
                        selectedIds.length === findings.length ? new Set() : new Set(findings.map((f) => f.entryId)),
                      )
                    }
                  />
                  <label htmlFor="health-select-all">
                    {selectedIds.length > 0
                      ? `${selectedIds.length} of ${findings.length} selected`
                      : `Select all ${findings.length}`}
                  </label>
                </div>
                <button
                  type="button"
                  className="ghost danger-text"
                  disabled={selectedIds.length === 0 || busy}
                  onClick={() => setConfirmTrash(true)}
                >
                  Move {selectedIds.length || ''} to trash
                </button>
              </div>

              <div className="filter-row" style={{ marginBottom: 10 }}>
                <span className="hint" style={{ alignSelf: 'center', marginRight: 2 }}>
                  Select all:
                </span>
                {[...kindCounts.entries()].map(([kind, count]) => (
                  <button key={kind} type="button" className="filter-chip" onClick={() => selectKind(kind)}>
                    {kind}
                    <span className="filter-count">{count}</span>
                  </button>
                ))}
                {selectedIds.length > 0 && (
                  <button type="button" className="filter-chip" onClick={() => setSelection(new Set())}>
                    clear
                  </button>
                )}
              </div>

              <ul className="entry-list">
                {visible.map((finding) => (
                  <li key={finding.entryId} className="finding-row">
                    <input
                      type="checkbox"
                      checked={selection.has(finding.entryId)}
                      aria-label={`Select ${finding.title}`}
                      onChange={() =>
                        setSelection((current) => {
                          const next = new Set(current);
                          if (!next.delete(finding.entryId)) next.add(finding.entryId);
                          return next;
                        })
                      }
                    />
                    <span className="entry-item">
                      <span className="entry-body">
                        <div className="title">
                          {finding.kinds.map((kind) => (
                            <span className="tag" key={kind}>
                              {kind}
                            </span>
                          ))}
                          {finding.title}
                        </div>
                        <div className="meta">{finding.issues.map((issue) => issue.detail).join(' ')}</div>
                      </span>
                    </span>
                  </li>
                ))}
              </ul>

              {/* "Select all" covers findings the list has folded away, so the
                  tail is never silently out of view while a count includes it. */}
              {!showAll && findings.length > visible.length && (
                <button type="button" className="ghost" style={{ marginTop: 8 }} onClick={() => setShowAll(true)}>
                  Show {findings.length - visible.length} more
                </button>
              )}
            </>
          )}
        </div>
      )}

      <ConfirmDialog
        open={confirmTrash}
        title={`Move ${selectedIds.length} ${selectedIds.length === 1 ? 'entry' : 'entries'} to the trash?`}
        confirmLabel="Move to trash"
        danger
        onCancel={() => setConfirmTrash(false)}
        onConfirm={() => {
          setConfirmTrash(false);
          void trashSelected();
        }}
      >
        <p>
          They stop appearing in your list and in autofill straight away. Nothing is destroyed: restore any of them
          from the trash below, or leave them to be removed for good after {TRASH_RETENTION_DAYS} days.
        </p>
      </ConfirmDialog>

      <div style={{ marginTop: 20 }}>
        <h3>Breach check</h3>
        <div className="checkbox-row" style={{ marginBottom: 8 }}>
          <input
            id="ext-breach-check"
            type="checkbox"
            checked={breachEnabled}
            onChange={(e) => void setBreach(e.target.checked)}
          />
          <label htmlFor="ext-breach-check">Allow Have I Been Pwned password checks</label>
        </div>
        <p className="hint" style={{ marginBottom: 12 }}>
          Off by default. When enabled, a click sends only a 5-character SHA-1 prefix to
          api.pwnedpasswords.com. Results stay in memory.
        </p>
        {breachEnabled && (
          <button type="button" disabled={breachBusy} onClick={() => void runBreachCheck()}>
            {breachBusy ? 'Checking…' : breaches ? 'Check again' : 'Check passwords'}
          </button>
        )}
        {breachError && <p className="hint" style={{ color: 'var(--danger)' }}>{breachError}</p>}
        {breaches && (
          <div style={{ marginTop: 12 }}>
            <p className="hint">
              {breaches.length === 0
                ? 'No checked passwords appear in the breach corpus.'
                : `${breaches.length} password(s) found in known breaches.`}
            </p>
            {breaches.length > 0 && (
              <ul className="entry-list" style={{ marginTop: 8 }}>
                {breaches.map((hit) => (
                  <li key={`${hit.title}-${hit.count}`}>
                    <span className="entry-item">
                      <span className="entry-body">
                        <div className="title">{hit.title}</div>
                        <div className="meta">Seen {hit.count.toLocaleString()} times in breaches</div>
                      </span>
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------

/**
 * Re-key the vault.
 *
 * Present in core, the desktop app and iOS, and previously missing here — which
 * meant someone whose only Keyhole was this extension could not rotate their master
 * password at all. The service worker also re-points the sync account, because the
 * new KDF salt invalidates the account's verifier.
 */
function ChangeMasterPassword() {
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [confirm, setConfirm] = useState('');
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState<{ kind: 'ok' | 'error'; message: string } | null>(null);

  const valid = next.length >= MIN_MASTER_PASSWORD_LENGTH && next === confirm && current.length > 0;
  const strength = next.length > 0 ? estimateStrength(next) : null;

  const apply = async () => {
    setBusy(true);
    setStatus(null);
    const response = await sendToBackground({
      type: 'CHANGE_MASTER_PASSWORD',
      currentPassword: current,
      newPassword: next,
    });
    setBusy(false);

    if (!response.ok) {
      setStatus({ kind: 'error', message: response.error });
      return;
    }
    setCurrent('');
    setNext('');
    setConfirm('');
    setStatus({
      kind: 'ok',
      message:
        response.type === 'SYNC_RESULT'
          ? `${response.message} Re-export your backup — older exports still use the old password.`
          : 'Master password changed.',
    });
  };

  return (
    <div className="section">
      <h3>Master password</h3>
      <p className="hint" style={{ marginBottom: 12 }}>
        Re-encrypts this vault under a new password: a fresh key-derivation salt and a new vault key, so the old
        password stops working everywhere. There is no recovery if you forget the new one.
      </p>

      {status && (
        <p className="hint" style={{ color: status.kind === 'ok' ? 'var(--ok)' : 'var(--danger)' }}>
          {status.message}
        </p>
      )}

      <label htmlFor="ext-current-master">Current master password</label>
      <input
        id="ext-current-master"
        type="password"
        autoComplete="current-password"
        value={current}
        disabled={busy}
        onChange={(e) => setCurrent(e.target.value)}
      />

      <label htmlFor="ext-next-master">New master password</label>
      <input
        id="ext-next-master"
        type="password"
        autoComplete="new-password"
        value={next}
        disabled={busy}
        onChange={(e) => setNext(e.target.value)}
      />
      {strength && (
        <p className="hint">
          Strength: {strength.label} (~{strength.bits} bits)
          {next.length < MIN_MASTER_PASSWORD_LENGTH && ` — at least ${MIN_MASTER_PASSWORD_LENGTH} characters`}
        </p>
      )}

      <label htmlFor="ext-confirm-master">Confirm new master password</label>
      <input
        id="ext-confirm-master"
        type="password"
        autoComplete="new-password"
        value={confirm}
        disabled={busy}
        onChange={(e) => setConfirm(e.target.value)}
      />
      {confirm.length > 0 && next !== confirm && (
        <p className="hint" style={{ color: 'var(--danger)' }}>
          Passwords do not match.
        </p>
      )}

      <button type="button" disabled={!valid || busy} onClick={() => void apply()}>
        {busy ? 'Re-encrypting…' : 'Change master password'}
      </button>
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
  onRemovePasskey,
}: {
  draft: EntryDraft;
  busy: boolean;
  onChange: (draft: EntryDraft) => void;
  onSave: () => void;
  onCancel: () => void;
  onDelete?: () => void;
  onRemovePasskey: (passkeyId: string) => void;
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
          onChange={(e) => {
            const trimmed = e.target.value.trim();
            if (trimmed.length === 0) {
              onChange({ ...draft, totpSecret: null, totpConfig: null });
              return;
            }
            const parsed = parseOtpAuthUri(trimmed);
            onChange({
              ...draft,
              totpSecret: parsed?.secret ?? trimmed,
              totpConfig: parsed ? normalizeTotpConfig(parsed.options) : draft.totpConfig,
            });
          }}
        />
        {draft.totpConfig && (
          <p className="hint">
            Non-default parameters: {draft.totpConfig.digits} digits · {draft.totpConfig.periodSeconds}s ·{' '}
            {draft.totpConfig.algorithm}
          </p>
        )}
      </div>

      {draft.passkeys.length > 0 && (
        <div className="field">
          <label>Passkeys</label>
          <p className="hint">
            Created on iPhone. Sign in with Safari or iOS AutoFill — Chrome cannot assert these passkeys.
          </p>
          <ul className="entry-list" style={{ border: '1px solid var(--border)', borderRadius: 8, marginTop: 8 }}>
            {draft.passkeys.map((pk) => (
              <li key={pk.id} style={{ padding: '10px 12px', borderBottom: '1px solid var(--border)' }}>
                <div className="title">{pk.userName || pk.userDisplayName || pk.relyingPartyId}</div>
                <div className="meta">{pk.relyingPartyId}</div>
                {pk.lastUsedAt && (
                  <p className="hint" style={{ marginTop: 4 }}>
                    Last used {new Date(pk.lastUsedAt).toLocaleString()}
                  </p>
                )}
                <button
                  type="button"
                  className="danger"
                  style={{ marginTop: 8 }}
                  disabled={busy || !draft.id}
                  onClick={() => onRemovePasskey(pk.id)}
                >
                  Remove passkey
                </button>
              </li>
            ))}
          </ul>
        </div>
      )}

      {draft.customFields.length > 0 && (
        <div className="field">
          <label>Custom fields</label>
          <p className="hint">
            {draft.customFields.map((f) => f.label || '(unnamed)').join(', ')} — edit these in the desktop app for now.
          </p>
        </div>
      )}

      {draft.attachments.length > 0 && (
        <div className="field">
          <label>Attachments</label>
          <p className="hint">
            {draft.attachments.map((a) => a.name).join(', ')} — download or replace from the desktop app.
          </p>
        </div>
      )}

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
