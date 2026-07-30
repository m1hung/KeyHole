/** Settings: lock behaviour, theme, local storage, export/import, master password, delete vault. */

import { useEffect, useMemo, useRef, useState } from 'react';
import {
  MIN_MASTER_PASSWORD_LENGTH,
  TRASH_RETENTION_DAYS,
  applyMigration,
  analyzeVaultHealth,
  createEntry,
  createFolder,
  deleteEntries,
  deriveSyncAuthSecret,
  groupIssuesByEntry,
  parseMigrationPayload,
  type HealthIssueKind,
  type Settings,
  type VaultFile,
} from '@keyhole/core';
import { ConfirmDialog, FINDINGS_PAGE, StrengthMeter } from './common.tsx';
import { Icon } from './Icon.tsx';
import {
  downloadVaultFile,
  forgetStoredHandle,
  hasWritePermission,
  isDesktop,
  loadStoredHandle,
  pickSaveHandle,
  readVaultFromBlob,
  revealVaultFile,
  supportsFileSystemAccess,
  vaultFilePath,
  writeToHandle,
} from '../storage.ts';
import type { VaultController } from '../hooks/useVault.ts';
import { healthCheck, registerAccount, SyncClientError } from '../sync/client.ts';
import { loadSyncConfig, saveSyncConfig } from '../sync/storage.ts';

interface SettingsPanelProps {
  settings: Settings;
  onSettingsChange: (patch: Partial<Settings>) => void;
  vault: VaultController;
  entryCount: number;
  onOpenEntry?: (id: string) => void;
}

export function SettingsPanel({ settings, onSettingsChange, vault, entryCount, onOpenEntry }: SettingsPanelProps) {
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
          <label htmlFor="lock-on-hide">
            Lock immediately when this {isDesktop() ? 'window is hidden' : 'tab is hidden'}
          </label>
        </div>

        <div className="checkbox-row">
          <input
            id="breach-check"
            type="checkbox"
            checked={settings.breachCheckEnabled}
            onChange={(e) => onSettingsChange({ breachCheckEnabled: e.target.checked })}
          />
          <label htmlFor="breach-check">Allow optional Have I Been Pwned password checks</label>
        </div>
        <p className="hint">
          Off by default. When enabled, the health panel can send the first five characters of a password&apos;s
          SHA-1 hash to api.pwnedpasswords.com — only on an explicit click, never automatically. The operator can
          infer that someone using that prefix range checked a password at that moment. Nothing else leaves the
          device.
        </p>
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

      <AppSection />
      <LocalStorageSection vault={vault} />
      <SyncSection vault={vault} />
      <MigrateSection vault={vault} />
      <VaultHealthSection
        vault={vault}
        breachCheckEnabled={settings.breachCheckEnabled}
        onOpenEntry={onOpenEntry}
      />
      <BackupSection vault={vault} entryCount={entryCount} />
      <ChangeMasterPassword vault={vault} />
      <DangerZone vault={vault} entryCount={entryCount} />
    </div>
  );
}

// ---------------------------------------------------------------------------

/**
 * Where the vault file lives — desktop only.
 *
 * Keyhole is not distributed as an installable web app, so there is no install
 * prompt, no offline shell and no in-app update channel to report on. Running
 * this renderer in a browser is a development mode, and a settings section
 * about the app's installation would have nothing true to say there.
 */
function AppSection() {
  if (!isDesktop()) return null;
  return <DesktopAppSection />;
}

/**
 * The desktop build's equivalent: where the vault file actually is.
 *
 * Showing the real path is the point. The whole reason the desktop app writes a
 * file instead of using the browser's storage is that a password vault should be
 * something you can find, copy and back up — a path you cannot see is barely
 * better than an opaque profile directory.
 */
function DesktopAppSection() {
  const [path, setPath] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    void vaultFilePath().then((value) => {
      if (active) setPath(value);
    });
    return () => {
      active = false;
    };
  }, []);

  return (
    <div className="section">
      <h3>App</h3>
      <div className="storage-card">
        <div className="storage-card-icon" aria-hidden="true">
          <Icon name="vault" size={28} />
        </div>
        <div className="storage-card-body">
          <div className="storage-card-title">Running as the desktop app</div>
          <p className="hint" style={{ margin: '4px 0 0' }}>
            Your vault is a real file on this machine. Back it up like any other file — it is encrypted, so a copy on a
            USB stick or in cloud storage reveals nothing without your master password.
          </p>
          <ul className="storage-facts">
            <li>
              <strong>Vault file</strong>
              <span style={{ wordBreak: 'break-all' }}>{path ?? 'Locating…'}</span>
            </li>
            <li>
              <strong>Updates</strong>
              <span>Replace the .exe — there is no auto-updater and nothing phones home</span>
            </li>
          </ul>
          <div className="button-row" style={{ marginTop: 12 }}>
            <button type="button" onClick={() => void revealVaultFile()}>
              Show in Explorer
            </button>
          </div>
        </div>
      </div>
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
    setStatus('Unlinked. The vault remains on this device; the file on disk is unchanged.');
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
            Keyhole never phones home. The encrypted vault lives{' '}
            {isDesktop() ? 'in a file on this machine' : 'in this browser'}
            {linkedName ? ', and mirrors to a file you chose.' : '.'}
          </p>
          <ul className="storage-facts">
            <li>
              <strong>{isDesktop() ? 'Primary copy' : 'Browser'}</strong>
              <span>
                {isDesktop() ? 'Encrypted envelope in %APPDATA%\\Keyhole' : 'Encrypted envelope in local storage'}
              </span>
            </li>
            <li>
              <strong>{isDesktop() ? 'Mirror file' : 'Disk file'}</strong>
              <span>
                {!canLink
                  ? 'Not available in this runtime'
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

function SyncSection({ vault }: { vault: VaultController }) {
  const saved = loadSyncConfig();
  const [baseUrl, setBaseUrl] = useState(saved?.baseUrl ?? 'http://127.0.0.1:8787');
  const [accountId, setAccountId] = useState(saved?.accountId ?? '');
  const [masterPassword, setMasterPassword] = useState('');
  const [status, setStatus] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const formatSyncError = (err: unknown, fallback: string): string => {
    if (err instanceof SyncClientError) return err.message;
    if (err instanceof TypeError && /fetch|network|load failed/i.test(err.message)) {
      return 'Could not reach the sync server (browser blocked the request). Confirm the server is running and try again.';
    }
    if (err instanceof Error) return err.message;
    return fallback;
  };

  const persistConfig = () => {
    const trimmedId = accountId.trim().toLowerCase();
    if (baseUrl.trim().length === 0 || trimmedId.length === 0) return;
    saveSyncConfig({ baseUrl: baseUrl.trim(), accountId: trimmedId });
  };

  const register = async () => {
    const file = vault.exportVault();
    if (!file) {
      setStatus('No vault loaded.');
      return;
    }
    if (masterPassword.length === 0) {
      setStatus('Enter your master password to derive sync credentials.');
      return;
    }
    const trimmedId = accountId.trim().toLowerCase();
    if (trimmedId.length === 0) {
      setStatus('Account id is required.');
      return;
    }

    setBusy(true);
    setStatus(null);
    try {
      const ok = await healthCheck(baseUrl.trim());
      if (!ok) {
        setStatus(
          'Sync server is not reachable. Confirm it is running (npm run dev:server) and the URL matches — usually http://127.0.0.1:8787.',
        );
        return;
      }

      const syncAuthSecretB64 = await deriveSyncAuthSecret(masterPassword, file.kdf);
      const result = await registerAccount(baseUrl.trim(), trimmedId, syncAuthSecretB64, file);
      saveSyncConfig({ baseUrl: baseUrl.trim(), accountId: trimmedId });
      vault.setSyncAuthSecret(syncAuthSecretB64);
      setStatus(`Registered as ${result.accountId} (server version ${result.version}).`);
      setMasterPassword('');
    } catch (err) {
      setStatus(formatSyncError(err, 'Registration failed.'));
    } finally {
      setBusy(false);
    }
  };

  const syncNow = async () => {
    const trimmedId = accountId.trim().toLowerCase();
    if (trimmedId.length === 0) {
      setStatus('Account id is required.');
      return;
    }
    if (masterPassword.length === 0 && !vault.getSyncAuthSecret()) {
      setStatus('Enter your master password once this session to enable sync.');
      return;
    }

    setBusy(true);
    setStatus(null);
    try {
      const ok = await healthCheck(baseUrl.trim());
      if (!ok) {
        setStatus(
          'Sync server is not reachable. Confirm it is running (npm run dev:server) and the URL matches — usually http://127.0.0.1:8787.',
        );
        return;
      }

      saveSyncConfig({ baseUrl: baseUrl.trim(), accountId: trimmedId });
      const message = await vault.syncNow({
        baseUrl: baseUrl.trim(),
        accountId: trimmedId,
        ...(masterPassword.length > 0 ? { masterPassword } : {}),
      });
      setStatus(message);
      setMasterPassword('');
    } catch (err) {
      setStatus(formatSyncError(err, 'Sync failed.'));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="section">
      <h3>Sync server</h3>
      <p className="hint" style={{ marginBottom: 12 }}>
        Optional self-hosted sync via the server in <code>server/</code>. The server stores only your encrypted
        envelope — never plaintext. See <code>server/README.md</code> for setup.
      </p>

      <div className="field">
        <label htmlFor="sync-url">Server URL</label>
        <input
          id="sync-url"
          type="url"
          value={baseUrl}
          onChange={(e) => setBaseUrl(e.target.value)}
          onBlur={persistConfig}
          placeholder="http://127.0.0.1:8787"
        />
      </div>

      <div className="field">
        <label htmlFor="sync-account">Account id</label>
        <input
          id="sync-account"
          type="text"
          autoComplete="off"
          value={accountId}
          onChange={(e) => setAccountId(e.target.value)}
          onBlur={persistConfig}
          placeholder="you@home"
        />
      </div>

      <div className="field">
        <label htmlFor="sync-master">
          Master password {vault.getSyncAuthSecret() ? '(optional — cached for this unlock)' : '(required once per unlock)'}
        </label>
        <input
          id="sync-master"
          type="password"
          autoComplete="current-password"
          value={masterPassword}
          onChange={(e) => setMasterPassword(e.target.value)}
        />
      </div>

      <div className="button-row">
        <button type="button" onClick={() => void register()} disabled={busy || vault.busy}>
          {busy ? 'Working…' : 'Register & upload'}
        </button>
        <button type="button" onClick={() => void syncNow()} disabled={busy || vault.busy}>
          {busy ? 'Syncing…' : 'Sync now'}
        </button>
      </div>

      {status && <p className="hint">{status}</p>}
    </div>
  );
}

// ---------------------------------------------------------------------------

function MigrateSection({ vault }: { vault: VaultController }) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [status, setStatus] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const onFile = async (file: File | undefined) => {
    if (!file || vault.status !== 'unlocked') return;
    setBusy(true);
    setStatus(null);
    try {
      const text = await file.text();
      const migration = parseMigrationPayload(text, file.name);
      let summary = '';
      await vault.mutate((current) => {
        const applied = applyMigration(current, migration, { createFolder, createEntry });
        // `migration.format` names the schema the parser targets, which is a
        // maintainer detail — report the file type the user actually chose.
        const fileType = migration.format === 'csv' ? '.csv' : '.json';
        const entryText = applied.entryCount === 1 ? '1 entry' : `${applied.entryCount} entries`;
        const folderText = applied.folderCount === 1 ? '1 folder' : `${applied.folderCount} folders`;
        summary = `Imported ${entryText}` +
          (applied.folderCount > 0 ? ` and ${folderText}` : '') +
          ` from the ${fileType} file.`;
        if (migration.warnings.length > 0) {
          summary += ` (${migration.warnings.length} skipped)`;
        }
        return applied.data;
      });
      setStatus(summary);
    } catch (err) {
      setStatus(err instanceof Error ? err.message : 'Import failed.');
    } finally {
      setBusy(false);
      if (inputRef.current) inputRef.current.value = '';
    }
  };

  return (
    <div className="section">
      <h3>Import entries</h3>
      <p className="hint" style={{ marginBottom: 12 }}>
        Merge a <strong>.csv</strong> or <strong>.json</strong> export into this unlocked vault. The file must be
        unencrypted — export it without a password.
      </p>
      <button type="button" disabled={busy || vault.busy} onClick={() => inputRef.current?.click()}>
        {busy ? 'Importing…' : 'Choose a .csv or .json file'}
      </button>
      <input
        ref={inputRef}
        type="file"
        accept=".json,.csv,text/csv,application/json"
        className="sr-only"
        onChange={(e) => void onFile(e.target.files?.[0])}
      />
      {status && <p className="hint">{status}</p>}
    </div>
  );
}

function VaultHealthSection({
  vault,
  breachCheckEnabled,
  onOpenEntry,
}: {
  vault: VaultController;
  breachCheckEnabled: boolean;
  onOpenEntry?: ((id: string) => void) | undefined;
}) {
  /** 0 = never scanned. Bumped by the button; the report itself is derived. */
  const [scanToken, setScanToken] = useState(0);
  const [selection, setSelection] = useState<ReadonlySet<string>>(() => new Set());
  const [confirmTrash, setConfirmTrash] = useState(false);
  const [showAll, setShowAll] = useState(false);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [breachBusy, setBreachBusy] = useState(false);
  const [breachError, setBreachError] = useState<string | null>(null);
  const [breaches, setBreaches] = useState<
    { entryId: string; title: string; count: number }[] | null
  >(null);

  const data = vault.data;

  /* Derived from `data` rather than frozen at the click, so acting on the report
     cannot leave it describing a vault that no longer exists. A list still
     offering to delete something already binned is how a bulk action deletes the
     wrong thing. */
  const report = useMemo(() => (scanToken === 0 || !data ? null : analyzeVaultHealth(data)), [scanToken, data]);
  const findings = useMemo(() => (report ? groupIssuesByEntry(report.issues) : []), [report]);

  /* The selection is intersected with what is currently on screen, so an id that
     has since been deleted or fixed can never be swept up by an action. */
  const selectedIds = useMemo(
    () => findings.filter((f) => selection.has(f.entryId)).map((f) => f.entryId),
    [findings, selection],
  );

  const kindCounts = useMemo(() => {
    const counts = new Map<HealthIssueKind, number>();
    for (const finding of findings) {
      for (const kind of finding.kinds) counts.set(kind, (counts.get(kind) ?? 0) + 1);
    }
    return [...counts.entries()];
  }, [findings]);

  const visible = showAll ? findings : findings.slice(0, FINDINGS_PAGE);

  /* Breach results are a snapshot of one deliberate network call, so they are kept
     across a bulk delete rather than thrown away — but an entry that has since
     been binned drops out, for the same reason the scan is derived from `data`. */
  const liveBreaches = useMemo(
    () =>
      breaches === null || !data
        ? breaches
        : breaches.filter((hit) => data.entries.some((e) => e.id === hit.entryId && e.deletedAt === null)),
    [breaches, data],
  );

  const toggle = (entryId: string) =>
    setSelection((current) => {
      const next = new Set(current);
      if (!next.delete(entryId)) next.add(entryId);
      return next;
    });

  const selectKind = (kind: HealthIssueKind) =>
    setSelection((current) => {
      const next = new Set(current);
      for (const finding of findings) if (finding.kinds.includes(kind)) next.add(finding.entryId);
      return next;
    });

  const run = () => {
    setSelection(new Set());
    setNotice(null);
    setShowAll(false);
    setScanToken((token) => token + 1);
  };

  /**
   * Bulk trash. One edit, not a loop: see `deleteEntries`.
   *
   * Deliberately the reversible delete — these entries go to the trash, stop
   * appearing in autofill immediately, and can be restored for
   * `TRASH_RETENTION_DAYS`. Acting on many entries at once from a list of
   * automated findings is exactly the place not to offer the irreversible one.
   */
  const trashSelected = async () => {
    const ids = selectedIds;
    if (ids.length === 0) return;
    setBusy(true);
    setNotice(null);
    vault.clearError();
    await vault.mutate((current) => deleteEntries(current, ids));
    setSelection(new Set());
    setBusy(false);
    setNotice(
      `Moved ${ids.length} ${ids.length === 1 ? 'entry' : 'entries'} to the trash. Restore from the Trash filter in the vault list.`,
    );
  };

  const runBreachCheck = async () => {
    if (!vault.data || !breachCheckEnabled) return;
    setBreachBusy(true);
    setBreachError(null);
    setBreaches(null);
    try {
      const { checkPasswordBreachCount } = await import('../breach/check.ts');
      const { liveEntries } = await import('@keyhole/core');
      const findings: { entryId: string; title: string; count: number }[] = [];
      // One range request per unique password — not per entry — so a reused
      // password is not counted out to the network by how often it appears.
      const seen = new Map<string, number>();
      for (const entry of liveEntries(vault.data)) {
        if (entry.kind !== 'login' || entry.password.length === 0) continue;
        let count = seen.get(entry.password);
        if (count === undefined) {
          count = await checkPasswordBreachCount(entry.password);
          seen.set(entry.password, count);
        }
        if (count > 0) findings.push({ entryId: entry.id, title: entry.title, count });
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
        Offline check for reused, weak, empty, or stale passwords. Nothing leaves this device.
      </p>
      <button type="button" onClick={run}>
        {report ? 'Scan again' : 'Scan vault'}
      </button>
      {/* Suppressed when the save failed — `vault.mutate` reports through
          `vault.error`, which the shell shows above this panel, and a success
          line beside it would contradict it. */}
      {notice && !vault.error && <p className="hint">{notice}</p>}
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
                    id="findings-select-all"
                    type="checkbox"
                    checked={selectedIds.length === findings.length}
                    // Inline so it re-applies on every render: `indeterminate` is a
                    // DOM property with no React attribute.
                    ref={(el) => {
                      if (el) el.indeterminate = selectedIds.length > 0 && selectedIds.length < findings.length;
                    }}
                    onChange={() =>
                      setSelection(
                        selectedIds.length === findings.length ? new Set() : new Set(findings.map((f) => f.entryId)),
                      )
                    }
                  />
                  <label htmlFor="findings-select-all">
                    {selectedIds.length > 0
                      ? `${selectedIds.length} of ${findings.length} selected`
                      : `Select all ${findings.length}`}
                  </label>
                </div>
                <button
                  type="button"
                  className="ghost danger-text"
                  disabled={selectedIds.length === 0 || busy || vault.busy}
                  onClick={() => setConfirmTrash(true)}
                >
                  <Icon name="trash" size={14} />
                  {busy ? 'Moving…' : `Move ${selectedIds.length || ''} to trash`}
                </button>
              </div>

              {/* Whole categories are the usual unit of "deal with this": every
                  empty-password entry, every reused one. */}
              <div className="filter-row" style={{ marginBottom: 10 }}>
                <span className="hint" style={{ alignSelf: 'center', marginRight: 2 }}>
                  Select all:
                </span>
                {kindCounts.map(([kind, count]) => (
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
                      onChange={() => toggle(finding.entryId)}
                      aria-label={`Select ${finding.title}`}
                    />
                    <button type="button" className="entry-item" onClick={() => onOpenEntry?.(finding.entryId)}>
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
                    </button>
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
          from the Trash filter, or leave them to be removed for good after {TRASH_RETENTION_DAYS} days.
        </p>
        <ul className="hint" style={{ margin: '8px 0 0', paddingLeft: 18 }}>
          {findings
            .filter((f) => selection.has(f.entryId))
            .slice(0, 8)
            .map((f) => (
              <li key={f.entryId}>{f.title}</li>
            ))}
          {selectedIds.length > 8 && <li>and {selectedIds.length - 8} more</li>}
        </ul>
      </ConfirmDialog>

      {breachCheckEnabled && (
        <div style={{ marginTop: 20 }}>
          <h3>Breach check</h3>
          <p className="hint" style={{ marginBottom: 12 }}>
            Sends only a 5-character SHA-1 prefix to Have I Been Pwned, once per unique password, when you click.
            Results stay in memory and are never written to the vault.
          </p>
          <button type="button" disabled={breachBusy} onClick={() => void runBreachCheck()}>
            {breachBusy ? 'Checking…' : breaches ? 'Check again' : 'Check passwords'}
          </button>
          {breachError && <p className="hint" style={{ color: 'var(--danger)' }}>{breachError}</p>}
          {liveBreaches && (
            <div style={{ marginTop: 12 }}>
              <p className="hint">
                {liveBreaches.length === 0
                  ? 'No checked passwords appear in the breach corpus.'
                  : `${liveBreaches.length} password(s) found in known breaches.`}
              </p>
              {liveBreaches.length > 0 && (
                <ul className="entry-list" style={{ marginTop: 8 }}>
                  {liveBreaches.map((hit) => (
                    <li key={hit.entryId}>
                      <button type="button" className="entry-item" onClick={() => onOpenEntry?.(hit.entryId)}>
                        <span className="entry-body">
                          <div className="title">{hit.title}</div>
                          <div className="meta">Seen {hit.count.toLocaleString()} times in breaches</div>
                        </span>
                      </button>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          )}
        </div>
      )}
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
          if (pendingImport) void vault.importVault(pendingImport);
          setPendingImport(null);
        }}
      >
        <p>
          This replaces the vault stored on this device with the imported file. Your current vault will be gone
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
  /* Re-keying re-points the sync account too, which is worth saying out loud —
     every other device will need the new password before it can sync again. */
  const syncConfigured = loadSyncConfig() !== null;

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
          {syncConfigured && ' Your sync account was re-pointed at the new password; other devices will need it too.'}
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
        Deleting removes the encrypted vault from this device so you can create a new one with a new master password.
        Exported files are unaffected.
      </p>
      <button type="button" className="danger" onClick={() => setConfirming(true)}>
        Delete vault and start over
      </button>

      <ConfirmDialog
        open={confirming}
        title="Delete this vault?"
        confirmLabel="Delete and start over"
        danger
        confirmDisabled={typed !== 'DELETE'}
        onCancel={() => {
          setConfirming(false);
          setTyped('');
        }}
        onConfirm={() => {
          setConfirming(false);
          setTyped('');
          void vault.deleteVault();
        }}
      >
        <p>
          All <strong>{entryCount}</strong> entries will be removed from this device. You will return to the create-vault
          screen to pick a new master password.
        </p>
        <p className="hint">Without an exported backup, the old vault cannot be recovered.</p>
        <div className="field" style={{ marginTop: 12 }}>
          <label htmlFor="delete-confirm">Type DELETE to confirm</label>
          <input id="delete-confirm" value={typed} onChange={(e) => setTyped(e.target.value)} autoComplete="off" />
        </div>
      </ConfirmDialog>
    </div>
  );
}
