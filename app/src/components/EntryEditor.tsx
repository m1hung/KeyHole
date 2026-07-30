/** Detail / edit view for a single entry, including TOTP and deletion. */

import { useEffect, useState } from 'react';
import {
  DEFAULT_GENERATOR_OPTIONS,
  displayHost,
  TRASH_RETENTION_DAYS,
  generatePassword,
  generatePassphrase,
  generatorEntropyBits,
  generateTotp,
  normalizeTotpConfig,
  parseOtpAuthUri,
  PASSPHRASE_WORDLIST,
  MAX_ATTACHMENT_BYTES,
  MAX_ATTACHMENTS_VAULT_BYTES,
  bytesToB64,
  b64ToBytes,
  randomUuid,
  type Attachment,
  type CustomField,
  type Entry,
  type Folder,
  type GeneratorOptions,
  type TotpConfig,
} from '@keyhole/core';
import { ConfirmDialog, SecretField, StrengthMeter } from './common.tsx';
import { GeneratorOptionsForm } from './GeneratorOptionsForm.tsx';
import { Icon } from './Icon.tsx';

interface EntryEditorProps {
  entry: Entry;
  folders: Folder[];
  generatorDefaults: GeneratorOptions;
  /** Total attachment bytes across the vault (for the budget meter). */
  vaultAttachmentTotalBytes: number;
  onSave: (patch: Partial<Entry>) => void;
  onDelete: () => void;
  onCopy: (value: string, label: string) => void;
  onClose: () => void;
}

export function EntryEditor({
  entry,
  folders,
  generatorDefaults,
  vaultAttachmentTotalBytes,
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
    JSON.stringify(draft.totpConfig) !== JSON.stringify(entry.totpConfig) ||
    JSON.stringify(draft.customFields) !== JSON.stringify(entry.customFields) ||
    JSON.stringify(draft.attachments) !== JSON.stringify(entry.attachments) ||
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
      totpConfig: draft.totpConfig,
      customFields: draft.customFields,
      attachments: draft.attachments,
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
    if (trimmed.length === 0) {
      setDraft({ ...draft, totpSecret: null, totpConfig: null });
      return;
    }
    setDraft({
      ...draft,
      totpSecret: parsed?.secret ?? trimmed,
      totpConfig: parsed ? normalizeTotpConfig(parsed.options) : draft.totpConfig,
    });
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
                {entry.password.length === 0
                  ? /* Nothing is stored on this entry yet — the field above holds a
                       password this editor generated for you, not one the vault has.
                       The rotation wording below would say the opposite ("update the
                       site too" implies it is saved and the site is what is behind),
                       which is how an entry ends up looking complete while the health
                       scan correctly reports it as empty. */
                    'Suggested password — nothing is saved on this entry until you press Save.'
                  : 'Unsaved password change — remember to update the site too.'}
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
          config={draft.totpConfig}
          entryTitle={draft.title}
          onChange={setTotp}
          onCopy={onCopy}
        />
      )}

      <CustomFieldsSection
        fields={draft.customFields}
        onChange={(customFields) => setDraft({ ...draft, customFields })}
        onCopy={onCopy}
      />

      <AttachmentsSection
        attachments={draft.attachments}
        vaultAttachmentBytes={
          vaultAttachmentTotalBytes -
          entry.attachments.reduce((s, a) => s + a.sizeBytes, 0) +
          draft.attachments.reduce((s, a) => s + a.sizeBytes, 0)
        }
        onChange={(attachments) => setDraft({ ...draft, attachments })}
        onError={(message) => {
          window.alert(message);
        }}
      />

      {/* Previous passwords. The reason this exists: you rotate a password here,
          the site rejects the change, and without this the one that still works is
          gone for good — "no recovery, no backdoor" cuts both ways. */}
      {!isNote && entry.history.length > 0 && (
        <div className="section">
          <h3>Previous passwords</h3>
          <p className="hint" style={{ marginBottom: 8 }}>
            Kept in case a password change does not take on the site. Restoring puts one back as the current password;
            the one it replaces is remembered in turn.
          </p>
          <ul className="entry-list">
            {entry.history.map((old) => (
              <li key={`${old.changedAt}:${old.password}`}>
                <div className="history-row">
                  <span className="meta">Replaced {new Date(old.changedAt).toLocaleString()}</span>
                  <div className="button-row">
                    <button type="button" onClick={() => onCopy(old.password, 'Previous password')}>
                      Copy
                    </button>
                    <button type="button" onClick={() => setDraft((current) => ({ ...current, password: old.password }))}>
                      Restore
                    </button>
                  </div>
                </div>
              </li>
            ))}
          </ul>
        </div>
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
          Move to trash
        </button>
      </div>

      <ConfirmDialog
        open={confirmDelete}
        title="Move this entry to the trash?"
        confirmLabel="Move to trash"
        onCancel={() => setConfirmDelete(false)}
        onConfirm={() => {
          setConfirmDelete(false);
          onDelete();
        }}
      >
        <p>
          <strong>{entry.title}</strong> will be hidden from your list and from autofill, and can be restored from the
          trash for {TRASH_RETENTION_DAYS} days before it is deleted for good.
        </p>
      </ConfirmDialog>
    </div>
  );
}

// ---------------------------------------------------------------------------

function TotpSection({
  secret,
  config,
  entryTitle,
  onChange,
  onCopy,
}: {
  secret: string | null;
  config: TotpConfig | null;
  entryTitle: string;
  onChange: (value: string) => void;
  onCopy: (value: string, label: string) => void;
}) {
  const [code, setCode] = useState<{ code: string; secondsRemaining: number; periodSeconds: number } | null>(null);
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
        const result = await generateTotp(secret, config ?? undefined);
        if (!cancelled) {
          setCode({
            code: result.code,
            secondsRemaining: result.secondsRemaining,
            periodSeconds: result.periodSeconds,
          });
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
  }, [secret, config]);

  const otpauthUri =
    secret && !error
      ? `otpauth://totp/${encodeURIComponent(entryTitle || 'Keyhole')}?secret=${secret.replace(/\s+/g, '')}&issuer=Keyhole${
          config
            ? `&digits=${config.digits}&period=${config.periodSeconds}&algorithm=${config.algorithm.replace('-', '')}`
            : ''
        }`
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
        {config && (
          <p className="hint">
            Non-default parameters: {config.digits} digits · {config.periodSeconds}s · {config.algorithm}
          </p>
        )}
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

function CustomFieldsSection({
  fields,
  onChange,
  onCopy,
}: {
  fields: CustomField[];
  onChange: (fields: CustomField[]) => void;
  onCopy: (value: string, label: string) => void;
}) {
  const update = (id: string, patch: Partial<CustomField>) => {
    onChange(fields.map((f) => (f.id === id ? { ...f, ...patch } : f)));
  };

  return (
    <div className="section">
      <h3>Custom fields</h3>
      <p className="hint" style={{ marginBottom: 8 }}>
        Labels are searchable; values are not. Mark a field secret to mask it and clear the clipboard after copy.
      </p>
      {fields.map((field) => (
        <div key={field.id} className="field" style={{ marginBottom: 12 }}>
          <div className="field-row">
            <input
              aria-label="Field label"
              placeholder="Label"
              value={field.label}
              onChange={(e) => update(field.id, { label: e.target.value })}
            />
            <button
              type="button"
              className="icon"
              title="Remove field"
              onClick={() => onChange(fields.filter((f) => f.id !== field.id))}
            >
              <Icon name="trash" />
            </button>
          </div>
          <div className="field-row" style={{ marginTop: 6 }}>
            <input
              className={field.secret ? 'mono' : undefined}
              type={field.secret ? 'password' : 'text'}
              aria-label={field.label || 'Field value'}
              placeholder="Value"
              value={field.value}
              autoComplete="off"
              onChange={(e) => update(field.id, { value: e.target.value })}
            />
            {field.value.length > 0 && (
              <button type="button" className="icon" title="Copy" onClick={() => onCopy(field.value, field.label || 'Field')}>
                <Icon name="copy" />
              </button>
            )}
          </div>
          <div className="checkbox-row" style={{ marginTop: 6 }}>
            <input
              id={`secret-${field.id}`}
              type="checkbox"
              checked={field.secret}
              onChange={(e) => update(field.id, { secret: e.target.checked })}
            />
            <label htmlFor={`secret-${field.id}`}>Secret (mask and clear clipboard after copy)</label>
          </div>
        </div>
      ))}
      <button
        type="button"
        className="ghost"
        onClick={() =>
          onChange([
            ...fields,
            { id: randomUuid(), label: '', value: '', secret: false },
          ])
        }
      >
        Add field
      </button>
    </div>
  );
}

function AttachmentsSection({
  attachments,
  vaultAttachmentBytes,
  onChange,
  onError,
}: {
  attachments: Attachment[];
  /** Bytes already used by this entry's attachments (siblings checked on save). */
  vaultAttachmentBytes: number;
  onChange: (attachments: Attachment[]) => void;
  onError: (message: string) => void;
}) {
  const used = vaultAttachmentBytes;
  const remaining = Math.max(0, MAX_ATTACHMENTS_VAULT_BYTES - used);

  const addFiles = async (list: FileList | null) => {
    if (!list || list.length === 0) return;
    const next = [...attachments];
    let running = used;
    for (const file of Array.from(list)) {
      if (file.size > MAX_ATTACHMENT_BYTES) {
        onError(`"${file.name}" is over the ${Math.round(MAX_ATTACHMENT_BYTES / 1024 / 1024)} MB per-file limit.`);
        continue;
      }
      if (running + file.size > MAX_ATTACHMENTS_VAULT_BYTES) {
        onError(`"${file.name}" does not fit in the remaining vault attachment budget.`);
        continue;
      }
      const buffer = new Uint8Array(await file.arrayBuffer());
      next.push({
        id: randomUuid(),
        name: file.name,
        mimeType: file.type || 'application/octet-stream',
        sizeBytes: file.size,
        dataB64: bytesToB64(buffer),
      });
      running += file.size;
    }
    onChange(next);
  };

  const download = (att: Attachment) => {
    const bytes = b64ToBytes(att.dataB64);
    const blob = new Blob([bytes.slice().buffer as ArrayBuffer], { type: att.mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = att.name;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="section">
      <h3>Attachments</h3>
      <p className="hint" style={{ marginBottom: 8 }}>
        Stored inside the encrypted vault. Max {Math.round(MAX_ATTACHMENT_BYTES / 1024 / 1024)} MB per file,{' '}
        {Math.round(MAX_ATTACHMENTS_VAULT_BYTES / 1024 / 1024)} MB per vault —{' '}
        {(used / 1024 / 1024).toFixed(2)} MB used in this vault,{' '}
        {(remaining / 1024 / 1024).toFixed(2)} MB remaining of the{' '}
        {Math.round(MAX_ATTACHMENTS_VAULT_BYTES / 1024 / 1024)} MB budget.
      </p>
      {attachments.length > 0 && (
        <ul className="entry-list" style={{ marginBottom: 8 }}>
          {attachments.map((att) => (
            <li key={att.id}>
              <div className="history-row">
                <span className="meta">
                  {att.name} · {(att.sizeBytes / 1024).toFixed(1)} KB
                </span>
                <div className="button-row">
                  <button type="button" onClick={() => download(att)}>
                    Download
                  </button>
                  <button type="button" className="danger" onClick={() => onChange(attachments.filter((a) => a.id !== att.id))}>
                    Remove
                  </button>
                </div>
              </div>
            </li>
          ))}
        </ul>
      )}
      <label className="ghost" style={{ display: 'inline-block', cursor: 'pointer' }}>
        Add file
        <input
          type="file"
          className="sr-only"
          multiple
          onChange={(e) => {
            void addFiles(e.target.files);
            e.target.value = '';
          }}
        />
      </label>
    </div>
  );
}
