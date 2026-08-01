/**
 * Sync server settings — drives privileged sync via the service worker.
 *
 * Master password is sent to the background for sync only; it is never stored.
 * After the first successful sync this unlock, the auth secret stays in SW memory.
 */

import { useEffect, useState } from 'react';
import { sendToBackground } from '../shared/messages.ts';
import { Icon } from '../../../app/src/components/Icon.tsx';
import { copy } from '../../../app/src/copy.ts';

const DEFAULT_BASE_URL = 'http://127.0.0.1:8787';

type Theme = 'light' | 'dark' | 'system';

function isLocalHost(hostname: string): boolean {
  return hostname === '127.0.0.1' || hostname === 'localhost';
}

async function ensureHostPermission(baseUrl: string): Promise<string | null> {
  let origin: string;
  try {
    origin = new URL(baseUrl).origin;
  } catch {
    return 'Invalid server URL.';
  }

  const hostname = new URL(baseUrl).hostname;
  if (isLocalHost(hostname)) return null;

  const pattern = `${origin}/*`;
  const has = await chrome.permissions.contains({ origins: [pattern] });
  if (has) return null;

  const granted = await chrome.permissions.request({ origins: [pattern] });
  if (!granted) {
    return 'Host permission denied. Keyhole needs access to reach your sync server.';
  }
  return null;
}

interface SyncPanelProps {
  theme: Theme;
  onThemeChange: (theme: Theme) => void;
}

const SUGGEST_ORIGINS = ['http://*/*', 'https://*/*'] as const;

async function hasSuggestPermission(): Promise<boolean> {
  return chrome.permissions.contains({ origins: [...SUGGEST_ORIGINS] });
}

export function SyncPanel({ theme, onThemeChange }: SyncPanelProps) {
  const [baseUrl, setBaseUrl] = useState(DEFAULT_BASE_URL);
  const [accountId, setAccountId] = useState('');
  const [masterPassword, setMasterPassword] = useState('');
  const [hasSyncAuth, setHasSyncAuth] = useState(false);
  const [status, setStatus] = useState<string | null>(null);
  const [statusKind, setStatusKind] = useState<'ok' | 'error'>('ok');
  const [busy, setBusy] = useState(false);
  const [vaultMismatch, setVaultMismatch] = useState(false);
  const [suggestEnabled, setSuggestEnabled] = useState(false);

  useEffect(() => {
    void (async () => {
      const response = await sendToBackground({ type: 'GET_SYNC_CONFIG' });
      if (response.ok && response.type === 'SYNC_CONFIG') {
        if (response.baseUrl) setBaseUrl(response.baseUrl);
        if (response.accountId) setAccountId(response.accountId);
        setHasSyncAuth(response.hasSyncAuthSecret);
      }
      setSuggestEnabled(await hasSuggestPermission());
    })();
  }, []);

  const enableSuggestions = async () => {
    setBusy(true);
    const granted = await chrome.permissions.request({ origins: [...SUGGEST_ORIGINS] });
    setBusy(false);
    if (!granted) {
      showStatus('Permission denied. Login suggestions stay off until you allow website access.', 'error');
      return;
    }
    setSuggestEnabled(true);
    showStatus('Login suggestions enabled. Reload open tabs to start seeing them.', 'ok');
  };

  const disableSuggestions = async () => {
    setBusy(true);
    await chrome.permissions.remove({ origins: [...SUGGEST_ORIGINS] });
    setBusy(false);
    setSuggestEnabled(false);
    showStatus('Login suggestions disabled.', 'ok');
  };

  const showStatus = (message: string, kind: 'ok' | 'error') => {
    setStatus(message);
    setStatusKind(kind);
  };

  const persistConfig = async () => {
    const trimmedId = accountId.trim().toLowerCase();
    if (baseUrl.trim().length === 0 || trimmedId.length === 0) return;
    await sendToBackground({
      type: 'SAVE_SYNC_CONFIG',
      baseUrl: baseUrl.trim(),
      accountId: trimmedId,
    });
  };

  const register = async () => {
    if (masterPassword.length === 0) {
      showStatus('Enter your master password.', 'error');
      return;
    }
    if (accountId.trim().length === 0) {
      showStatus('Account id is required.', 'error');
      return;
    }
    const trimmedId = accountId.trim().toLowerCase();

    setBusy(true);
    setStatus(null);
    setVaultMismatch(false);
    try {
      const permErr = await ensureHostPermission(baseUrl.trim());
      if (permErr) {
        showStatus(permErr, 'error');
        return;
      }

      const response = await sendToBackground({
        type: 'SYNC_REGISTER',
        masterPassword,
        baseUrl: baseUrl.trim(),
        accountId: trimmedId,
      });
      if (!response.ok) {
        showStatus(response.error, 'error');
        return;
      }
      if (response.type === 'SYNC_RESULT') {
        showStatus(response.message, 'ok');
        setMasterPassword('');
        setHasSyncAuth(true);
      }
    } finally {
      setBusy(false);
    }
  };

  const syncNow = async () => {
    if (masterPassword.length === 0 && !hasSyncAuth) {
      showStatus('Enter your master password once this unlock to enable sync.', 'error');
      return;
    }
    if (accountId.trim().length === 0) {
      showStatus('Account id is required.', 'error');
      return;
    }
    const trimmedId = accountId.trim().toLowerCase();

    setBusy(true);
    setStatus(null);
    setVaultMismatch(false);
    try {
      const state = await sendToBackground({ type: 'GET_STATE' });
      if (!state.ok) {
        showStatus(state.error, 'error');
        return;
      }
      if (state.type === 'STATE' && state.locked) {
        showStatus('Unlock the vault before syncing.', 'error');
        return;
      }

      const permErr = await ensureHostPermission(baseUrl.trim());
      if (permErr) {
        showStatus(permErr, 'error');
        return;
      }

      const response = await sendToBackground({
        type: 'SYNC_NOW',
        ...(masterPassword.length > 0 ? { masterPassword } : {}),
        baseUrl: baseUrl.trim(),
        accountId: trimmedId,
      });
      if (!response.ok) {
        showStatus(response.error, 'error');
        return;
      }
      if (response.type === 'SYNC_VAULT_MISMATCH') {
        setVaultMismatch(true);
        showStatus(
          'This device and the server hold different vaults. Choose which one to keep — merging unrelated vaults is refused on purpose.',
          'error',
        );
        return;
      }
      if (response.type === 'SYNC_RESULT') {
        showStatus(response.message, 'ok');
        setMasterPassword('');
        setHasSyncAuth(true);
      }
    } finally {
      setBusy(false);
    }
  };

  const resolveMismatch = async (action: 'SYNC_ADOPT_REMOTE' | 'SYNC_OVERWRITE_REMOTE') => {
    if (masterPassword.length === 0) {
      showStatus('Enter your master password.', 'error');
      return;
    }
    if (accountId.trim().length === 0) {
      showStatus('Account id is required.', 'error');
      return;
    }
    const trimmedId = accountId.trim().toLowerCase();

    setBusy(true);
    setStatus(null);
    try {
      const response = await sendToBackground({
        type: action,
        masterPassword,
        baseUrl: baseUrl.trim(),
        accountId: trimmedId,
      });
      if (!response.ok) {
        showStatus(response.error, 'error');
        return;
      }
      if (response.type === 'SYNC_RESULT') {
        setVaultMismatch(false);
        showStatus(response.message, 'ok');
        setMasterPassword('');
        setHasSyncAuth(true);
      }
    } finally {
      setBusy(false);
    }
  };

  return (
    <div>
      <div className="detail-header">
        <h2>
          <Icon name="localServer" size={22} />
          Sync server
        </h2>
      </div>

      <p className="hint" style={{ marginBottom: 16 }}>
        Optional self-hosted sync via the server in <code>server/</code>. Use the same vault that was registered
        for this account (export/import from the Keyhole app if needed). The server stores only your encrypted envelope
        — never plaintext.
      </p>

      <div className="field">
        <label htmlFor="ext-sync-url">Server URL</label>
        <input
          id="ext-sync-url"
          type="url"
          value={baseUrl}
          onChange={(e) => setBaseUrl(e.target.value)}
          onBlur={() => void persistConfig()}
          placeholder={DEFAULT_BASE_URL}
        />
      </div>

      <div className="field">
        <label htmlFor="ext-sync-account">Account id</label>
        <input
          id="ext-sync-account"
          type="text"
          autoComplete="off"
          value={accountId}
          onChange={(e) => setAccountId(e.target.value)}
          onBlur={() => void persistConfig()}
          placeholder="you@home"
        />
      </div>

      <div className="field">
        <label htmlFor="ext-sync-master">
          Master password {hasSyncAuth ? '(optional — cached for this unlock)' : '(required once per unlock)'}
        </label>
        <input
          id="ext-sync-master"
          type="password"
          autoComplete="current-password"
          value={masterPassword}
          onChange={(e) => setMasterPassword(e.target.value)}
        />
      </div>

      <div className="button-row">
        <button type="button" onClick={() => void register()} disabled={busy}>
          {busy ? copy.syncWorking : copy.syncRegister}
        </button>
        <button type="button" className="primary" onClick={() => void syncNow()} disabled={busy}>
          {busy ? copy.syncSyncing : copy.syncNow}
        </button>
      </div>

      {status && (
        <p className="hint" style={{ marginTop: 12, color: statusKind === 'error' ? 'var(--danger)' : 'var(--ok)' }}>
          {status}
        </p>
      )}

      {vaultMismatch && (
        <div className="section" style={{ marginTop: 8 }}>
          <p className="hint" style={{ marginBottom: 10 }}>
            Account <code>{accountId.trim().toLowerCase() || '…'}</code> already has a different vault on the server
            (usually from the Keyhole app). Pick one:
          </p>
          <div className="button-row">
            <button
              type="button"
              className="primary"
              disabled={busy}
              onClick={() => void resolveMismatch('SYNC_ADOPT_REMOTE')}
            >
              Use server vault here
            </button>
            <button type="button" className="danger" disabled={busy} onClick={() => void resolveMismatch('SYNC_OVERWRITE_REMOTE')}>
              Overwrite server with this device
            </button>
          </div>
        </div>
      )}

      <div className="section">
        <h3>Inline autofill</h3>
        <p className="hint">
          When enabled, Keyhole shows matching logins when you click a username or password field.
          Chrome will ask for permission to run on websites. After you submit a login, Keyhole can also
          offer to save or update the password (with your confirmation).
        </p>
        <div className="button-row">
          <button type="button" className="primary" disabled={busy || suggestEnabled} onClick={() => void enableSuggestions()}>
            {suggestEnabled ? 'Suggestions enabled' : 'Enable login suggestions'}
          </button>
          {suggestEnabled && (
            <button type="button" className="ghost" disabled={busy} onClick={() => void disableSuggestions()}>
              Disable
            </button>
          )}
        </div>
      </div>

      <div className="section">
        <h3>Appearance</h3>
        <div className="field">
          <label htmlFor="ext-theme">Theme</label>
          <select
            id="ext-theme"
            value={theme}
            onChange={(e) => onThemeChange(e.target.value as Theme)}
          >
            <option value="system">Match system</option>
            <option value="light">Light</option>
            <option value="dark">Dark</option>
          </select>
        </div>
      </div>
    </div>
  );
}
