/**
 * Application shell: routing between list / entry / generator / settings,
 * search, theme application and the lock countdown.
 */

import { useEffect, useState } from 'react';
import {
  DEFAULT_GENERATOR_OPTIONS,
  createEntry,
  deleteEntry,
  displayHost,
  searchEntries,
  updateEntry,
  updateSettings,
  type Entry,
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

type View = { kind: 'entry'; id: string } | { kind: 'generator' } | { kind: 'settings' } | { kind: 'none' };

export function App() {
  const vault = useVault();
  const [query, setQuery] = useState('');
  const [view, setView] = useState<View>({ kind: 'none' });

  const settings = vault.data?.settings;
  const clipboard = useClipboard(settings?.clipboardClearSeconds ?? 30);

  useTheme(settings?.theme ?? 'system');
  useActivityTracking(vault.registerActivity, vault.status === 'unlocked');

  // Reset transient UI when the vault locks so nothing survives a re-unlock.
  useEffect(() => {
    if (vault.status !== 'unlocked') {
      setView({ kind: 'none' });
      setQuery('');
    }
  }, [vault.status]);

  if (vault.status === 'loading') {
    return <div className="center-screen">Loading…</div>;
  }
  if (vault.status !== 'unlocked' || !vault.data || !settings) {
    return <UnlockScreen vault={vault} />;
  }

  const data = vault.data;
  const results = searchEntries(data, query);
  const selected = view.kind === 'entry' ? data.entries.find((e) => e.id === view.id) : undefined;

  const addEntry = async () => {
    let created: Entry | undefined;
    await vault.mutate((current) => {
      const result = createEntry(current, { title: 'New entry', username: '', password: '' });
      created = result.entry;
      return result.data;
    });
    if (created) setView({ kind: 'entry', id: created.id });
  };

  const patchSettings = (patch: Partial<Settings>) => vault.mutate((current) => updateSettings(current, patch));

  const saveGeneratorDefaults = (generator: GeneratorOptions) =>
    vault.mutate((current) => updateSettings(current, { generator }));

  return (
    <div className="app">
      <header className="topbar">
        <span className="brand">🔑 Keyhole</span>

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
          <span className="lock-status" role="status">
            Locking in {vault.secondsUntilLock}s
          </span>
        )}
        <button type="button" className="ghost" onClick={() => setView({ kind: 'generator' })}>
          Generator
        </button>
        <button type="button" className="ghost" onClick={() => setView({ kind: 'settings' })}>
          Settings
        </button>
        <button type="button" onClick={vault.lock}>
          Lock
        </button>
      </header>

      <div className={`columns${view.kind === 'none' ? '' : ' detail-open'}`}>
        <div className="list-pane">
          <div style={{ padding: 12, borderBottom: '1px solid var(--border)' }}>
            <button type="button" className="primary" style={{ width: '100%' }} onClick={() => void addEntry()}>
              + New entry
            </button>
          </div>

          {results.length === 0 ? (
            <EmptyState title={query ? 'No matches' : 'Your vault is empty'}>
              <p className="hint">{query ? 'Try a different search.' : 'Add your first entry to get started.'}</p>
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
                    <div className="title">{entry.title}</div>
                    <div className="meta">
                      {entry.username || <em>no username</em>}
                      {entry.urls[0] ? ` · ${displayHost(entry.urls[0])}` : ''}
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
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>

        <main className="detail-pane">
          {vault.error && <div className="error">{vault.error}</div>}

          {view.kind === 'settings' && (
            <SettingsPanel
              settings={settings}
              onSettingsChange={patchSettings}
              vault={vault}
              entryCount={data.entries.length}
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
              <p className="hint">Or create a new one to get started.</p>
            </EmptyState>
          )}
        </main>
      </div>

      {clipboard.lastCopied && (
        <Toast message={`${clipboard.lastCopied} copied`} countdown={clipboard.secondsRemaining} />
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------

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
