/** Detail / edit view for a single entry, including TOTP and deletion. */

import { useEffect, useState } from 'react';
import {
  DEFAULT_GENERATOR_OPTIONS,
  displayHost,
  generatePassword,
  generateTotp,
  parseOtpAuthUri,
  type Entry,
  type GeneratorOptions,
} from '@keyhole/core';
import { ConfirmDialog, SecretField, StrengthMeter } from './common.tsx';

interface EntryEditorProps {
  entry: Entry;
  generatorDefaults: GeneratorOptions;
  onSave: (patch: Partial<Entry>) => void;
  onDelete: () => void;
  onCopy: (value: string, label: string) => void;
  onClose: () => void;
}

export function EntryEditor({ entry, generatorDefaults, onSave, onDelete, onCopy, onClose }: EntryEditorProps) {
  const [draft, setDraft] = useState(entry);
  const [revealed, setRevealed] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);

  // Switching entries must reset the draft and re-hide the password — otherwise
  // a revealed secret would carry over to the next entry the user clicks.
  useEffect(() => {
    setDraft(entry);
    setRevealed(false);
  }, [entry.id, entry]);

  const dirty =
    draft.title !== entry.title ||
    draft.username !== entry.username ||
    draft.password !== entry.password ||
    draft.notes !== entry.notes ||
    draft.urls.join('\n') !== entry.urls.join('\n') ||
    draft.tags.join(',') !== entry.tags.join(',') ||
    draft.totpSecret !== entry.totpSecret;

  const save = () => {
    onSave({
      title: draft.title,
      username: draft.username,
      password: draft.password,
      notes: draft.notes,
      urls: draft.urls,
      tags: draft.tags,
      totpSecret: draft.totpSecret,
    });
  };

  const regenerate = () => {
    setDraft({ ...draft, password: generatePassword(generatorDefaults ?? DEFAULT_GENERATOR_OPTIONS) });
    setRevealed(true);
  };

  const setTotp = (raw: string) => {
    const trimmed = raw.trim();
    // Accept a pasted otpauth:// URI as well as a bare base32 seed.
    const parsed = parseOtpAuthUri(trimmed);
    setDraft({ ...draft, totpSecret: trimmed.length === 0 ? null : (parsed?.secret ?? trimmed) });
  };

  return (
    <div>
      <div className="detail-header">
        <h2>{draft.title || 'Untitled'}</h2>
        <div className="button-row">
          <button type="button" className="ghost" onClick={onClose}>
            Close
          </button>
          <button type="button" className="primary" onClick={save} disabled={!dirty || draft.title.trim().length === 0}>
            {dirty ? 'Save changes' : 'Saved'}
          </button>
        </div>
      </div>

      <div className="field">
        <label htmlFor="entry-title">Title</label>
        <input id="entry-title" value={draft.title} onChange={(e) => setDraft({ ...draft, title: e.target.value })} />
      </div>

      <div className="field">
        <label htmlFor="entry-username">Username</label>
        <div className="field-row">
          <input
            id="entry-username"
            value={draft.username}
            autoComplete="off"
            onChange={(e) => setDraft({ ...draft, username: e.target.value })}
          />
          <button
            type="button"
            className="icon"
            onClick={() => onCopy(draft.username, 'Username')}
            title="Copy username"
            disabled={draft.username.length === 0}
          >
            📋
          </button>
        </div>
      </div>

      <SecretField
        id="entry-password"
        label="Password"
        value={draft.password}
        revealed={revealed}
        onToggleReveal={() => setRevealed((r) => !r)}
        onCopy={() => onCopy(draft.password, 'Password')}
      />
      <div className="field" style={{ marginTop: -8 }}>
        {revealed && draft.password.length > 0 && <StrengthMeter password={draft.password} />}
        <div className="button-row" style={{ marginTop: 8 }}>
          <button type="button" className="ghost" onClick={regenerate}>
            Generate new password
          </button>
        </div>
        {draft.password !== entry.password && (
          <p className="hint" style={{ color: 'var(--warn)' }}>
            Unsaved password change — remember to update the site too.
          </p>
        )}
      </div>

      <div className="field">
        <label htmlFor="entry-urls">Websites (one per line)</label>
        <textarea
          id="entry-urls"
          value={draft.urls.join('\n')}
          onChange={(e) =>
            setDraft({ ...draft, urls: e.target.value.split('\n').map((u) => u.trim()).filter(Boolean) })
          }
          style={{ minHeight: 60 }}
          spellCheck={false}
        />
        <p className="hint">Used to match this entry when autofilling. {draft.urls.map(displayHost).join(', ')}</p>
      </div>

      <div className="field">
        <label htmlFor="entry-tags">Tags (comma separated)</label>
        <input
          id="entry-tags"
          value={draft.tags.join(', ')}
          onChange={(e) =>
            setDraft({ ...draft, tags: e.target.value.split(',').map((t) => t.trim()).filter(Boolean) })
          }
        />
      </div>

      <div className="field">
        <label htmlFor="entry-notes">Notes</label>
        <textarea
          id="entry-notes"
          value={draft.notes}
          onChange={(e) => setDraft({ ...draft, notes: e.target.value })}
        />
        <p className="hint">Encrypted with the rest of the vault.</p>
      </div>

      <TotpSection secret={draft.totpSecret} onChange={setTotp} onCopy={onCopy} />

      <div className="section">
        <h3>Details</h3>
        <p className="hint">
          Created {new Date(entry.createdAt).toLocaleString()} · Updated {new Date(entry.updatedAt).toLocaleString()}
          <br />
          Password last changed {new Date(entry.passwordUpdatedAt).toLocaleDateString()}
        </p>
        <button type="button" className="danger" style={{ marginTop: 12 }} onClick={() => setConfirmDelete(true)}>
          Delete entry
        </button>
      </div>

      <ConfirmDialog
        open={confirmDelete}
        title="Delete this entry?"
        confirmLabel="Delete permanently"
        danger
        onCancel={() => setConfirmDelete(false)}
        onConfirm={() => {
          setConfirmDelete(false);
          onDelete();
        }}
      >
        <p>
          <strong>{entry.title}</strong> will be removed from the vault. This cannot be undone.
        </p>
      </ConfirmDialog>
    </div>
  );
}

// ---------------------------------------------------------------------------

function TotpSection({
  secret,
  onChange,
  onCopy,
}: {
  secret: string | null;
  onChange: (value: string) => void;
  onCopy: (value: string, label: string) => void;
}) {
  const [code, setCode] = useState<{ code: string; secondsRemaining: number } | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!secret) {
      setCode(null);
      setError(null);
      return;
    }
    let cancelled = false;
    const refresh = async () => {
      try {
        const result = await generateTotp(secret);
        if (!cancelled) {
          setCode({ code: result.code, secondsRemaining: result.secondsRemaining });
          setError(null);
        }
      } catch {
        if (!cancelled) {
          setCode(null);
          setError('Not a valid TOTP secret.');
        }
      }
    };
    void refresh();
    const timer = window.setInterval(() => void refresh(), 1000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [secret]);

  return (
    <div className="section">
      <h3>Two-factor code</h3>
      <div className="field">
        <label htmlFor="entry-totp">TOTP secret or otpauth:// URI</label>
        <input
          id="entry-totp"
          className="mono"
          value={secret ?? ''}
          placeholder="JBSWY3DPEHPK3PXP"
          autoComplete="off"
          spellCheck={false}
          onChange={(e) => onChange(e.target.value)}
        />
        {error && <p className="hint" style={{ color: 'var(--danger)' }}>{error}</p>}
      </div>
      {code && (
        <div className="row-between">
          <span className="totp-code">{code.code.replace(/(\d{3})(?=\d)/, '$1 ')}</span>
          <div className="button-row">
            <span className="lock-status">{code.secondsRemaining}s</span>
            <button type="button" className="ghost" onClick={() => onCopy(code.code, 'One-time code')}>
              Copy code
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
