/**
 * Popup UI.
 *
 * Holds no vault data of its own: every secret is fetched from the service
 * worker one value at a time, in response to a specific user click, and is
 * dropped as soon as the popup closes.
 */

import { useCallback, useEffect, useState } from 'react';
import { sendToBackground, type EntrySummary } from '../shared/messages.ts';
import { openVaultWindow } from '../shared/openVaultWindow.ts';
import { Icon } from '../../../app/src/components/Icon.tsx';

type Screen = 'loading' | 'no-vault' | 'locked' | 'unlocked';

export function Popup() {
  const [screen, setScreen] = useState<Screen>('loading');
  const [matches, setMatches] = useState<EntrySummary[]>([]);
  const [all, setAll] = useState<EntrySummary[]>([]);
  const [query, setQuery] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [tabId, setTabId] = useState<number | null>(null);
  /** `${entryId}:${field}` of the button that was just used, for the pulse. */
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [tabHost, setTabHost] = useState<string | null>(null);
  /** Set when a fill failed only because Keyhole lacks access to this site. */
  const [accessRequest, setAccessRequest] = useState<{ pattern: string; entryId: string } | null>(null);
  /** Why a fill failed, in host-level terms. Same line the service worker logs. */
  const [errorDetail, setErrorDetail] = useState<string | null>(null);
  /** Set when this vault was last written by a newer Keyhole than this build. */
  const [foreignSchemaVersion, setForeignSchemaVersion] = useState<number | null>(null);

  const refreshState = useCallback(async () => {
    const response = await sendToBackground({ type: 'GET_STATE' });
    if (!response.ok) {
      setError(response.error);
      setScreen('locked');
      return;
    }
    if (response.type !== 'STATE') return;
    document.documentElement.dataset['theme'] = response.theme;
    setForeignSchemaVersion(response.foreignSchemaVersion);
    setScreen(!response.hasVault ? 'no-vault' : response.locked ? 'locked' : 'unlocked');
  }, []);

  useEffect(() => {
    void (async () => {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tab?.id !== undefined) setTabId(tab.id);
      if (tab?.url) {
        try {
          setTabHost(new URL(tab.url).hostname);
        } catch {
          setTabHost(null);
        }
      }
      await refreshState();
    })();
  }, [refreshState]);

  // Load entries whenever we become unlocked or the search changes.
  useEffect(() => {
    if (screen !== 'unlocked') return;
    void (async () => {
      if (tabId !== null) {
        const matched = await sendToBackground({ type: 'MATCH_TAB', tabId });
        if (matched.ok && matched.type === 'ENTRIES') setMatches(matched.entries);
      }
      const listed = await sendToBackground({ type: 'LIST_ENTRIES', query });
      if (listed.ok && listed.type === 'ENTRIES') setAll(listed.entries);
    })();
  }, [screen, query, tabId]);

  const flash = (message: string) => {
    setNotice(message);
    window.setTimeout(() => setNotice(null), 2500);
  };

  const copy = async (entryId: string, field: 'password' | 'username' | 'totp') => {
    const response = await sendToBackground({ type: 'REVEAL_SECRET', entryId, field });
    if (!response.ok) {
      setError(response.error);
      return;
    }
    if (response.type !== 'SECRET') return;
    // Rejects with NotAllowedError if the popup lost focus or clipboard
    // permission is denied. Silently skipping the feedback below would leave the
    // user pasting a stale clipboard value, thinking it was their password.
    try {
      await navigator.clipboard.writeText(response.value);
    } catch {
      setError('Could not copy — the browser denied clipboard access.');
      return;
    }
    setCopiedKey(`${entryId}:${field}`);
    window.setTimeout(() => setCopiedKey(null), 900);
    flash(`${field === 'totp' ? 'Code' : field === 'password' ? 'Password' : 'Username'} copied`);

    if (response.clipboardClearSeconds > 0) {
      // Best effort: the popup usually closes first, so the service worker
      // cannot rely on this. Documented in the README.
      window.setTimeout(() => {
        void navigator.clipboard.writeText('').catch(() => undefined);
      }, response.clipboardClearSeconds * 1000);
    }
  };

  const fill = async (entryId: string) => {
    if (tabId === null) return;
    setError(null);
    setErrorDetail(null);
    setAccessRequest(null);
    const response = await sendToBackground({ type: 'FILL', entryId, tabId });
    if (!response.ok) {
      setError(response.error);
      setErrorDetail(response.detail ?? null);
      // A fill that failed only for want of site access is recoverable right here,
      // because this click is the user gesture chrome.permissions.request needs.
      if (response.needsHostAccess !== undefined) {
        setAccessRequest({ pattern: response.needsHostAccess, entryId });
      }
      return;
    }
    window.close(); // credential delivered; nothing left to show
  };

  /** Ask for the site, then retry the fill that prompted the request. */
  const grantAccessAndRetry = async () => {
    if (!accessRequest) return;
    setBusy(true);
    let granted = false;
    try {
      granted = await chrome.permissions.request({ origins: [accessRequest.pattern] });
    } catch {
      granted = false;
    }
    setBusy(false);
    if (!granted) {
      setError('Keyhole was not allowed on this site, so nothing was filled.');
      return;
    }
    const { entryId } = accessRequest;
    setAccessRequest(null);
    await fill(entryId);
  };

  if (screen === 'loading') return <div className="popup-center">Loading…</div>;

  if (screen === 'no-vault') {
    return (
      <div className="popup">
        <Header host={tabHost} />
        <div className="popup-center">
          <p>No vault in this browser yet.</p>
          <button
            type="button"
            className="primary"
            onClick={() => void openVaultWindow().then(() => window.close())}
          >
            Set up Keyhole
          </button>
          <p className="hint">Create a new vault, or import one exported from the Keyhole app.</p>
        </div>
      </div>
    );
  }

  if (screen === 'locked') {
    return (
      <UnlockForm
        error={error}
        busy={busy}
        host={tabHost}
        onUnlock={async (password) => {
          setBusy(true);
          setError(null);
          const response = await sendToBackground({ type: 'UNLOCK', masterPassword: password });
          setBusy(false);
          if (!response.ok) {
            setError(response.error);
            return;
          }
          await refreshState();
        }}
      />
    );
  }

  const shown = query.trim().length > 0 ? all : matches.length > 0 ? matches : all;
  const showingMatches = query.trim().length === 0 && matches.length > 0;

  return (
    <div className="popup">
      <Header host={tabHost}>
        <button
          type="button"
          className="icon"
          title="Lock vault"
          onClick={() => void sendToBackground({ type: 'LOCK' }).then(refreshState)}
        >
          <Icon name="lock" size={18} />
        </button>
        <button
          type="button"
          className="icon"
          title="Open full vault"
          onClick={() => void openVaultWindow().then(() => window.close())}
        >
          <Icon name="settings" size={18} />
        </button>
      </Header>

      <input
        className="popup-search"
        type="search"
        placeholder="Search all entries…"
        aria-label="Search entries"
        value={query}
        onChange={(e) => setQuery(e.target.value)}
        autoFocus
      />

      {error && (
        <div className="popup-error">
          {error}
          {errorDetail && <div className="popup-error-detail">{errorDetail}</div>}
          {accessRequest && (
            <button
              type="button"
              className="primary popup-error-action"
              disabled={busy}
              onClick={() => void grantAccessAndRetry()}
            >
              {busy ? 'Requesting…' : `Allow Keyhole on ${tabHost ?? 'this site'} and retry`}
            </button>
          )}
        </div>
      )}

      {/* Not an error: the vault works and nothing is lost. But this build cannot
          show newer fields, so it must not imply the list is complete. */}
      {foreignSchemaVersion !== null && (
        <div className="popup-notice" role="status">
          Written by a newer Keyhole (format {foreignSchemaVersion}). Everything still works, but newer fields are not
          shown here.
        </div>
      )}

      {showingMatches && <p className="popup-section-label">Matches for {tabHost}</p>}
      {!showingMatches && shown.length > 0 && <p className="popup-section-label">All entries</p>}

      {shown.length === 0 ? (
        <div className="popup-center">
          <p className="hint">{query ? 'No matches.' : 'No entries yet.'}</p>
        </div>
      ) : (
        <ul className="popup-list">
          {shown.map((entry) => (
            <li key={entry.id} className="popup-item">
              <div className="popup-item-main">
                <div className="popup-item-title">
                  {entry.title}
                  {entry.matchStrength === 'exact' && <span className="badge">exact</span>}
                  {/* Saved on a different host of the same site — say so, so the
                      user can tell a related suggestion from their own login. */}
                  {entry.matchStrength === 'domain' && (
                    <span className="badge soft" title="Saved for another host on this site">
                      similar
                    </span>
                  )}
                </div>
                <div className="popup-item-meta">
                  {entry.username || <em>no username</em>}
                  {entry.host ? ` · ${entry.host}` : ''}
                </div>
              </div>
              <div className="popup-item-actions">
                <button
                  type="button"
                  className={`icon${copiedKey === `${entry.id}:username` ? ' just-copied' : ''}`}
                  title="Copy username"
                  onClick={() => void copy(entry.id, 'username')}
                >
                  <Icon name="user" size={17} />
                </button>
                <button
                  type="button"
                  className={`icon${copiedKey === `${entry.id}:password` ? ' just-copied' : ''}`}
                  title="Copy password"
                  onClick={() => void copy(entry.id, 'password')}
                >
                  <Icon name="copy" size={17} />
                </button>
                {entry.hasTotp && (
                  <button
                    type="button"
                    className={`icon${copiedKey === `${entry.id}:totp` ? ' just-copied' : ''}`}
                    title="Copy one-time code"
                    onClick={() => void copy(entry.id, 'totp')}
                  >
                    <Icon name="clock" size={17} />
                  </button>
                )}
                <button type="button" className="fill-button" onClick={() => void fill(entry.id)}>
                  Fill
                </button>
              </div>
            </li>
          ))}
        </ul>
      )}

      {notice && <div className="popup-toast">{notice}</div>}
    </div>
  );
}

// ---------------------------------------------------------------------------

function Header({ host, children }: { host: string | null; children?: React.ReactNode }) {
  return (
    <header className="popup-header">
      <span className="popup-brand">
        <Icon name="vault" size={17} />
        Keyhole
      </span>
      {host && <span className="popup-host">{host}</span>}
      <span style={{ flex: 1 }} />
      {children}
    </header>
  );
}

function UnlockForm({
  error,
  busy,
  host,
  onUnlock,
}: {
  error: string | null;
  busy: boolean;
  host: string | null;
  onUnlock: (password: string) => Promise<void>;
}) {
  const [password, setPassword] = useState('');
  return (
    <div className="popup">
      <Header host={host} />
      <form
        className="popup-unlock"
        onSubmit={(e) => {
          e.preventDefault();
          void onUnlock(password).then(() => setPassword(''));
        }}
      >
        <label htmlFor="popup-master">Master password</label>
        <input
          id="popup-master"
          type="password"
          autoComplete="current-password"
          autoFocus
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          disabled={busy}
        />
        {error && <div className="popup-error">{error}</div>}
        <button type="submit" className="primary" disabled={busy || password.length === 0}>
          {busy ? 'Deriving key…' : 'Unlock'}
        </button>
        {/* The reset itself lives in the vault window: it is destructive and
            needs a typed confirmation, which does not belong in a 320px popup
            that closes the moment focus moves. */}
        <button
          type="button"
          className="popup-link"
          onClick={() => void openVaultWindow().then(() => window.close())}
        >
          Forgot your master password?
        </button>
      </form>
    </div>
  );
}
