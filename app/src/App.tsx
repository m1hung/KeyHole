/**
 * Application shell: routing between list / entry / generator / settings,
 * search, theme application and the lock countdown.
 */

import { useEffect, useRef, useState } from 'react';
import {
  DEFAULT_GENERATOR_OPTIONS,
  createEntry,
  createFolder,
  deleteEntry,
  deleteFolder,
  displayHost,
  searchEntries,
  updateEntry,
  updateSettings,
  type Entry,
  type EntryKind,
  type GeneratorOptions,
  type Settings,
} from '@keyhole/core';
import { useVault } from './hooks/useVault.ts';
import { useClipboard } from './hooks/useClipboard.ts';
import { UnlockScreen } from './components/UnlockScreen.tsx';
import { EntryEditor } from './components/EntryEditor.tsx';
import { GeneratorPanel } from './components/GeneratorPanel.tsx';
import { SettingsPanel } from './components/SettingsPanel.tsx';
import { EmptyState, Toast } from './components/common.tsx';
import { Icon } from './components/Icon.tsx';
import { readLegacyBrowserVault } from './storage.ts';

type View = { kind: 'entry'; id: string } | { kind: 'generator' } | { kind: 'settings' } | { kind: 'none' };
type ListFilter = 'all' | EntryKind | { folderId: string };

/**
 * Manifest shortcuts — right-click the installed app icon — launch the app at
 * `?view=generator` or `?view=settings`.
 *
 * Read once at module load and stripped from the URL immediately: this is a
 * launch intent, not application state. Leaving it in place would re-open that
 * pane on every subsequent reload, and the app has no routing to reconcile it
 * with. Held until the vault unlocks, since no pane can be shown before that.
 */
const LAUNCH_VIEW = readLaunchView();

function readLaunchView(): View | null {
  const requested = new URLSearchParams(window.location.search).get('view');
  if (requested !== 'generator' && requested !== 'settings') return null;
  window.history.replaceState(null, '', window.location.pathname);
  return { kind: requested };
}

interface AppProps {
  /**
   * Desktop first run with a vault present in this machine's browser build.
   * See `MigrationOffer` — the two are separate stores, and saying so beats
   * showing an empty create-vault screen to someone who has a vault.
   */
  legacyBrowserVaultAvailable?: boolean;
}

export function App({ legacyBrowserVaultAvailable = false }: AppProps) {
  const vault = useVault();
  const pendingLaunchView = useRef<View | null>(LAUNCH_VIEW);
  const [migrationDismissed, setMigrationDismissed] = useState(false);
  const [query, setQuery] = useState('');
  const [filter, setFilter] = useState<ListFilter>('all');
  const [view, setView] = useState<View>({ kind: 'none' });
  const [newFolderName, setNewFolderName] = useState('');

  const settings = vault.data?.settings;
  const clipboard = useClipboard(settings?.clipboardClearSeconds ?? 30);

  useTheme(settings?.theme ?? 'system');
  useActivityTracking(vault.registerActivity, vault.status === 'unlocked');

  // Reset transient UI when the vault locks so nothing survives a re-unlock.
  useEffect(() => {
    if (vault.status !== 'unlocked') {
      setView({ kind: 'none' });
      setQuery('');
      setFilter('all');
      setNewFolderName('');
      return;
    }
    // First unlock after a shortcut launch: honour it, then forget it, so a
    // later manual lock/unlock returns to the normal entry list.
    const pending = pendingLaunchView.current;
    if (pending) {
      pendingLaunchView.current = null;
      setView(pending);
    }
  }, [vault.status]);

  if (vault.status === 'loading') {
    return <div className="center-screen">Loading…</div>;
  }
  if (vault.status !== 'unlocked' || !vault.data || !settings) {
    return (
      <>
        {legacyBrowserVaultAvailable && !migrationDismissed && vault.status === 'no-vault' && (
          <MigrationOffer vault={vault} onDismiss={() => setMigrationDismissed(true)} />
        )}
        <UnlockScreen vault={vault} />
      </>
    );
  }

  const data = vault.data;
  const results = searchEntries(data, query).filter((e) => {
    if (filter === 'all') return true;
    if (typeof filter === 'string') return e.kind === filter;
    return e.folderId === filter.folderId;
  });
  const selected = view.kind === 'entry' ? data.entries.find((e) => e.id === view.id) : undefined;
  const loginCount = data.entries.filter((e) => e.kind === 'login').length;
  const noteCount = data.entries.filter((e) => e.kind === 'note').length;

  const addEntry = async (kind: EntryKind) => {
    let created: Entry | undefined;
    const folderId = typeof filter === 'object' ? filter.folderId : null;
    await vault.mutate((current) => {
      const result = createEntry(current, {
        title: kind === 'note' ? 'New secure note' : 'New entry',
        kind,
        username: '',
        password: '',
        folderId,
      });
      created = result.entry;
      return result.data;
    });
    if (created) {
      if (typeof filter === 'string' && filter !== 'all' && filter !== kind) setFilter(kind);
      setView({ kind: 'entry', id: created.id });
    }
  };

  const addFolder = async () => {
    const name = newFolderName.trim();
    if (!name) return;
    await vault.mutate((current) => createFolder(current, name).data);
    setNewFolderName('');
  };

  const patchSettings = (patch: Partial<Settings>) => vault.mutate((current) => updateSettings(current, patch));

  const saveGeneratorDefaults = (generator: GeneratorOptions) =>
    vault.mutate((current) => updateSettings(current, { generator }));

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
          placeholder="Search by name, username, URL or tag…"
          aria-label="Search entries"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />

        <div className="spacer" />

        {vault.secondsUntilLock !== null && vault.secondsUntilLock < 60 && (
          <span className={`lock-status${vault.secondsUntilLock <= 15 ? ' urgent' : ''}`} role="status">
            Locking in {vault.secondsUntilLock}s
          </span>
        )}
        {/* Duplicated by the mobile tab bar below; CSS shows exactly one. */}
        <span className="nav-desktop">
          <button type="button" className="ghost" onClick={() => setView({ kind: 'generator' })}>
            Generator
          </button>
          <button type="button" className="ghost" onClick={() => setView({ kind: 'settings' })}>
            Settings
          </button>
        </span>
        <button type="button" onClick={vault.lock}>
          Lock
        </button>
      </header>

      {/* On mobile the search field gets its own full-width row — inline in the
          topbar it collapses to an unusable sliver. */}
      <div className="search-row">
        <input
          type="search"
          placeholder="Search entries…"
          aria-label="Search entries"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
      </div>

      <div className={`columns${view.kind === 'none' ? '' : ' detail-open'}`}>
        <div className="list-pane">
          <div className="list-toolbar">
            <div className="filter-row" role="tablist" aria-label="Entry type">
              <FilterChip active={filter === 'all'} onClick={() => setFilter('all')} count={data.entries.length}>
                All
              </FilterChip>
              <FilterChip active={filter === 'login'} onClick={() => setFilter('login')} count={loginCount} icon="key">
                Logins
              </FilterChip>
              <FilterChip
                active={filter === 'note'}
                onClick={() => setFilter('note')}
                count={noteCount}
                icon="secureNote"
              >
                Notes
              </FilterChip>
            </div>
            {data.folders.length > 0 && (
              <div className="filter-row" role="tablist" aria-label="Folders" style={{ marginTop: 8 }}>
                {data.folders.map((folder) => (
                  <FilterChip
                    key={folder.id}
                    active={typeof filter === 'object' && filter.folderId === folder.id}
                    onClick={() => setFilter({ folderId: folder.id })}
                    count={data.entries.filter((e) => e.folderId === folder.id).length}
                  >
                    {folder.name}
                  </FilterChip>
                ))}
              </div>
            )}
            <div className="field-row" style={{ marginTop: 8, padding: '0 12px' }}>
              <input
                type="text"
                placeholder="New folder name"
                aria-label="New folder name"
                value={newFolderName}
                onChange={(e) => setNewFolderName(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') void addFolder();
                }}
              />
              <button type="button" className="ghost" disabled={newFolderName.trim().length === 0} onClick={() => void addFolder()}>
                Add folder
              </button>
            </div>
            {typeof filter === 'object' && (
              <div className="button-row" style={{ padding: '8px 12px' }}>
                <button
                  type="button"
                  className="ghost danger-text"
                  onClick={() => {
                    const id = filter.folderId;
                    setFilter('all');
                    void vault.mutate((current) => deleteFolder(current, id));
                  }}
                >
                  Delete folder
                </button>
              </div>
            )}
            <div className="new-entry-row">
              <button type="button" className="primary" onClick={() => void addEntry('login')}>
                <Icon name="key" size={16} />
                New login
              </button>
              <button type="button" className="ghost" onClick={() => void addEntry('note')}>
                <Icon name="secureNote" size={16} />
                New note
              </button>
            </div>
          </div>

          {results.length === 0 ? (
            <EmptyState title={query || filter !== 'all' ? 'No matches' : 'Your vault is empty'}>
              <p className="hint">
                {query
                  ? 'Try a different search.'
                  : typeof filter === 'object'
                    ? 'This folder is empty.'
                  : filter === 'note'
                    ? 'Create a secure note for secrets that are not a login.'
                    : 'Add your first login or secure note to get started.'}
              </p>
            </EmptyState>
          ) : (
            <ul className="entry-list">
              {results.map((entry) => (
                <li key={entry.id}>
                  <button
                    type="button"
                    className="entry-item"
                    aria-current={selected?.id === entry.id}
                    onClick={() => setView({ kind: 'entry', id: entry.id })}
                  >
                    <span className="entry-icon" aria-hidden="true">
                      <Icon name={entry.kind === 'note' ? 'secureNote' : 'key'} size={18} />
                    </span>
                    <span className="entry-body">
                      <div className="title">{entry.title}</div>
                      <div className="meta">
                        {entry.kind === 'note' ? (
                          entry.notes.trim() ? (
                            entry.notes.trim().split('\n')[0]
                          ) : (
                            <em>empty note</em>
                          )
                        ) : (
                          <>
                            {entry.username || <em>no username</em>}
                            {entry.urls[0] ? ` · ${displayHost(entry.urls[0])}` : ''}
                          </>
                        )}
                      </div>
                      {entry.tags.length > 0 && (
                        <div style={{ marginTop: 4 }}>
                          {entry.tags.map((tag) => (
                            <span className="tag" key={tag}>
                              {tag}
                            </span>
                          ))}
                        </div>
                      )}
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>

        {/* Keyed on the active view so React remounts the subtree and the
            fade-up animation replays when you switch entries. */}
        <main className="detail-pane" key={view.kind === 'entry' ? view.id : view.kind}>
          <button type="button" className="back-button" onClick={() => setView({ kind: 'none' })}>
            <Icon name="chevronLeft" size={18} /> All entries
          </button>

          {vault.error && <div className="error">{vault.error}</div>}
          {clipboard.error && <div className="error">{clipboard.error}</div>}

          {view.kind === 'settings' && (
            <SettingsPanel
              settings={settings}
              onSettingsChange={patchSettings}
              vault={vault}
              entryCount={data.entries.length}
              onOpenEntry={(id) => setView({ kind: 'entry', id })}
            />
          )}

          {view.kind === 'generator' && (
            <GeneratorPanel
              options={settings.generator ?? DEFAULT_GENERATOR_OPTIONS}
              onOptionsChange={saveGeneratorDefaults}
              onCopy={(value, label) => void clipboard.copy(value, label)}
            />
          )}

          {view.kind === 'entry' && selected && (
            <EntryEditor
              entry={selected}
              folders={data.folders}
              generatorDefaults={settings.generator ?? DEFAULT_GENERATOR_OPTIONS}
              onCopy={(value, label) => void clipboard.copy(value, label)}
              onClose={() => setView({ kind: 'none' })}
              onSave={(patch) => void vault.mutate((current) => updateEntry(current, selected.id, patch))}
              onDelete={() => {
                setView({ kind: 'none' });
                void vault.mutate((current) => deleteEntry(current, selected.id));
              }}
            />
          )}

          {view.kind === 'entry' && !selected && <EmptyState title="That entry no longer exists." />}

          {view.kind === 'none' && (
            <EmptyState title="Select an entry">
              <p className="hint">Or create a new login or secure note to get started.</p>
            </EmptyState>
          )}
        </main>
      </div>

      {/* Mobile primary navigation. Hidden on desktop, where the topbar carries
          the same actions. */}
      <nav className="tabbar" aria-label="Main">
        <button type="button" aria-current={view.kind === 'none' || view.kind === 'entry'} onClick={() => setView({ kind: 'none' })}>
          <Icon name="vault" size={22} className="tab-icon" />
          Vault
        </button>
        <button type="button" aria-current={view.kind === 'generator'} onClick={() => setView({ kind: 'generator' })}>
          <Icon name="generator" size={22} className="tab-icon" />
          Generator
        </button>
        <button type="button" aria-current={view.kind === 'settings'} onClick={() => setView({ kind: 'settings' })}>
          <Icon name="settings" size={22} className="tab-icon" />
          Settings
        </button>
      </nav>

      {clipboard.lastCopied && (
        <Toast
          message={`${clipboard.lastCopied} copied`}
          countdown={clipboard.secondsRemaining}
          totalSeconds={settings.clipboardClearSeconds}
        />
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------

function FilterChip({
  active,
  onClick,
  count,
  icon,
  children,
}: {
  active: boolean;
  onClick: () => void;
  count: number;
  icon?: 'key' | 'secureNote';
  children: string;
}) {
  return (
    <button type="button" role="tab" aria-selected={active} className={`filter-chip${active ? ' active' : ''}`} onClick={onClick}>
      {icon && <Icon name={icon} size={14} />}
      {children}
      <span className="filter-count">{count}</span>
    </button>
  );
}

/**
 * Shown once, on a desktop first run, when this machine's browser build has a
 * vault the desktop app cannot see.
 *
 * The two builds are different origins with different stores, so "your vault is
 * gone" is the natural but wrong conclusion for a user to reach here. Copying is
 * strictly additive: the browser copy is read, never deleted, so declining this
 * or having it fail leaves the original exactly where it was.
 */
function MigrationOffer({ vault, onDismiss }: { vault: ReturnType<typeof useVault>; onDismiss: () => void }) {
  const [busy, setBusy] = useState(false);
  const [failed, setFailed] = useState<string | null>(null);

  const copyOver = async () => {
    setBusy(true);
    setFailed(null);
    try {
      const legacy = readLegacyBrowserVault();
      if (!legacy) throw new Error('The browser vault could not be read.');
      await vault.importVault(legacy);
      onDismiss();
    } catch (err) {
      setFailed(err instanceof Error ? err.message : 'Could not copy the vault.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="banner" role="status">
      <Icon name="vault" size={18} />
      <div>
        <strong>A vault from Keyhole in your browser was found on this machine.</strong>
        <p className="hint" style={{ margin: '4px 0 0' }}>
          The desktop app keeps its vault as a file instead, so it starts empty. Copy the existing one across to carry
          on where you left off — the browser copy is left untouched either way.
        </p>
        {failed && <p className="hint">{failed}</p>}
      </div>
      <div className="button-row">
        <button type="button" className="primary" disabled={busy} onClick={() => void copyOver()}>
          {busy ? 'Copying…' : 'Copy it across'}
        </button>
        <button type="button" disabled={busy} onClick={onDismiss}>
          Start fresh
        </button>
      </div>
    </div>
  );
}

function useTheme(theme: Settings['theme']): void {
  useEffect(() => {
    document.documentElement.dataset['theme'] = theme;
  }, [theme]);
}

/** Any real interaction pushes back the idle auto-lock deadline. */
function useActivityTracking(onActivity: () => void, active: boolean): void {
  useEffect(() => {
    if (!active) return;
    const events = ['pointerdown', 'keydown', 'wheel', 'touchstart'] as const;
    for (const event of events) window.addEventListener(event, onActivity, { passive: true });
    return () => {
      for (const event of events) window.removeEventListener(event, onActivity);
    };
  }, [onActivity, active]);
}
