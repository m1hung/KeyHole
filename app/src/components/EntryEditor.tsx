/** Detail / edit view for a single entry, including TOTP and deletion. */

import { useEffect, useState } from 'react';
import {
  DEFAULT_GENERATOR_OPTIONS,
  displayHost,
  generatePassword,
  generatePassphrase,
  generatorEntropyBits,
  generateTotp,
  parseOtpAuthUri,
  PASSPHRASE_WORDLIST,
  type Entry,
  type Folder,
  type GeneratorOptions,
} from '@keyhole/core';
import { ConfirmDialog, SecretField, StrengthMeter } from './common.tsx';
import { GeneratorOptionsForm } from './GeneratorOptionsForm.tsx';
import { Icon } from './Icon.tsx';

interface EntryEditorProps {
  entry: Entry;
  folders: Folder[];
  generatorDefaults: GeneratorOptions;
  onSave: (patch: Partial<Entry>) => void;
  onDelete: () => void;
  onCopy: (value: string, label: string) => void;
  onClose: () => void;
}

export function EntryEditor({
  entry,
  folders,
  generatorDefaults,
  onSave,
  onDelete,
  onCopy,
  onClose,
}: EntryEditorProps) {
  const [draft, setDraft] = useState(entry);
  const [revealed, setRevealed] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [genOptions, setGenOptions] = useState<GeneratorOptions>(
    () => generatorDefaults ?? DEFAULT_GENERATOR_OPTIONS,
  );
  /** Open by default for brand-new empty passwords so create flow has the controls handy. */
  const [showGenerator, setShowGenerator] = useState(() => entry.password.length === 0 && entry.kind !== 'note');
  const [genError, setGenError] = useState<string | null>(null);
  /**
   * Exact entropy, set only while showing a password this editor just generated.
   * Null for a stored password, whose pool we cannot know after the fact.
   */
  const [generatedBits, setGeneratedBits] = useState<number | null>(null);

  // Switching entries must reset the draft and re-hide the password — otherwise
  // a revealed secret would carry over to the next entry the user clicks.
  useEffect(() => {
    const defaults = generatorDefaults ?? DEFAULT_GENERATOR_OPTIONS;
    setGenOptions(defaults);
    setGenError(null);

    if (entry.kind !== 'note' && entry.password.length === 0) {
      // New login: open options and seed a password so create isn't empty.
      try {
        const password = generatePassword(defaults);
        setDraft({ ...entry, password });
        setGeneratedBits(generatorEntropyBits(defaults));
        setRevealed(true);
        setShowGenerator(true);
      } catch (err) {
        setDraft(entry);
        setGeneratedBits(null);
        setRevealed(false);
        setShowGenerator(true);
        setGenError(err instanceof Error ? err.message : 'Cannot generate with these options.');
      }
      return;
    }

    setDraft(entry);
    setRevealed(false);
    setGeneratedBits(null);
    setShowGenerator(false);
  }, [entry.id, entry, generatorDefaults]);

  const isNote = draft.kind === 'note';

  const dirty =
    draft.title !== entry.title ||
    draft.username !== entry.username ||
    draft.password !== entry.password ||
    draft.notes !== entry.notes ||
    draft.urls.join('\n') !== entry.urls.join('\n') ||
    draft.tags.join(',') !== entry.tags.join(',') ||
    draft.totpSecret !== entry.totpSecret ||
    draft.folderId !== entry.folderId;

  const save = () => {
    onSave({
      title: draft.title,
      username: draft.username,
      password: draft.password,
      notes: draft.notes,
      urls: draft.urls,
      tags: draft.tags,
      totpSecret: draft.totpSecret,
      folderId: draft.folderId,
    });
  };

  const applyGenerated = (options: GeneratorOptions) => {
    try {
      setDraft((current) => ({ ...current, password: generatePassword(options) }));
      setGeneratedBits(generatorEntropyBits(options));
      setRevealed(true);
      setGenError(null);
      setShowGenerator(true);
    } catch (err) {
      setGenError(err instanceof Error ? err.message : 'Cannot generate with these options.');
    }
  };

  const applyPassphrase = () => {
    try {
      setDraft((current) => ({
        ...current,
        password: generatePassphrase(PASSPHRASE_WORDLIST, 5, '-'),
      }));
      setGeneratedBits(Math.round(5 * Math.log2(PASSPHRASE_WORDLIST.length) * 10) / 10);
      setRevealed(true);
      setGenError(null);
    } catch (err) {
      setGenError(err instanceof Error ? err.message : 'Cannot generate passphrase.');
    }
  };

  const onGenOptionsChange = (options: GeneratorOptions) => {
    setGenOptions(options);
    // Live-refresh only when the current password still came from the generator,
    // so typing a manual password is never overwritten by a slider nudge.
    if (generatedBits !== null) applyGenerated(options);
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
        <h2>
          <span className="detail-kind" title={isNote ? 'Secure note' : 'Login'}>
            <Icon name={isNote ? 'secureNote' : 'key'} size={22} />
          </span>
          {draft.title || 'Untitled'}
        </h2>
        <div className="button-row">
          <button type="button" className="ghost close-desktop" onClick={onClose}>
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
        <label htmlFor="entry-folder">Folder</label>
        <select
          id="entry-folder"
          value={draft.folderId ?? ''}
          onChange={(e) => setDraft({ ...draft, folderId: e.target.value.length > 0 ? e.target.value : null })}
        >
          <option value="">No folder</option>
          {folders.map((folder) => (
            <option key={folder.id} value={folder.id}>
              {folder.name}
            </option>
          ))}
        </select>
      </div>

      {isNote ? (
        <div className="field">
          <label htmlFor="entry-notes">Secure note</label>
          <textarea
            id="entry-notes"
            className="note-body"
            value={draft.notes}
            onChange={(e) => setDraft({ ...draft, notes: e.target.value })}
            placeholder="Encrypted with the rest of the vault…"
          />
        </div>
      ) : (
        <>
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
                <Icon name="copy" />
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
            {revealed && draft.password.length > 0 && (
              <StrengthMeter password={draft.password} exactBits={generatedBits ?? undefined} />
            )}
            <div className="button-row" style={{ marginTop: 8 }}>
              <button type="button" className="ghost" onClick={() => applyGenerated(genOptions)}>
                <Icon name="refresh" size={16} />
                Generate password
              </button>
              <button type="button" className="ghost" onClick={applyPassphrase}>
                <Icon name="refresh" size={16} />
                Generate passphrase
              </button>
              <button
                type="button"
                className="ghost"
                aria-expanded={showGenerator}
                onClick={() => setShowGenerator((open) => !open)}
              >
                <Icon name="generator" size={16} />
                {showGenerator ? 'Hide options' : 'Generator options'}
              </button>
            </div>
            {showGenerator && (
              <div className="entry-generator">
                <GeneratorOptionsForm
                  options={genOptions}
                  onChange={onGenOptionsChange}
                  idPrefix={`entry-gen-${entry.id}`}
                  compact
                />
                {genError && (
                  <p className="hint" style={{ color: 'var(--danger)' }}>
                    {genError}
                  </p>
                )}
                <p className="hint" style={{ marginTop: 8 }}>
                  Starts from your vault defaults. Changes here apply to this password only.
                </p>
              </div>
            )}
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
        </>
      )}

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

      {!isNote && (
        <div className="field">
          <label htmlFor="entry-notes">Notes</label>
          <textarea
            id="entry-notes"
            value={draft.notes}
            onChange={(e) => setDraft({ ...draft, notes: e.target.value })}
          />
          <p className="hint">Encrypted with the rest of the vault.</p>
        </div>
      )}

      {!isNote && (
        <TotpSection
          secret={draft.totpSecret}
          entryTitle={draft.title}
          onChange={setTotp}
          onCopy={onCopy}
        />
      )}

      <div className="section">
        <h3>Details</h3>
        <p className="hint">
          {isNote ? 'Secure note' : 'Login'} · Created {new Date(entry.createdAt).toLocaleString()} · Updated{' '}
          {new Date(entry.updatedAt).toLocaleString()}
          {!isNote && (
            <>
              <br />
              Password last changed {new Date(entry.passwordUpdatedAt).toLocaleDateString()}
            </>
          )}
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
  entryTitle,
  onChange,
  onCopy,
}: {
  secret: string | null;
  entryTitle: string;
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

  const otpauthUri =
    secret && !error
      ? `otpauth://totp/${encodeURIComponent(entryTitle || 'Keyhole')}?secret=${secret.replace(/\s+/g, '')}&issuer=Keyhole`
      : null;

  return (
    <div className="section">
      <h3>Two-factor code</h3>
      <div className="field">
        <label htmlFor="entry-totp">TOTP secret or otpauth:// URI</label>
        <input
          id="entry-totp"
          className="mono"
          value={secret ?? ''}
          placeholder="Paste secret or otpauth://…"
          autoComplete="off"
          spellCheck={false}
          onChange={(e) => onChange(e.target.value)}
        />
        <p className="hint">Paste a base32 secret or a full otpauth:// URI from your authenticator export.</p>
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
      {otpauthUri && (
        <div className="field" style={{ marginTop: 12 }}>
          <label htmlFor="entry-otpauth">Enroll URI (for authenticator apps)</label>
          <div className="field-row">
            <input id="entry-otpauth" className="mono" readOnly value={otpauthUri} />
            <button type="button" className="icon" title="Copy otpauth URI" onClick={() => onCopy(otpauthUri, 'otpauth URI')}>
              <Icon name="copy" />
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
