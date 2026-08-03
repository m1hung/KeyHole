/** Standalone password / passphrase generator with live strength feedback. */

import { useCallback, useEffect, useState } from 'react';
import {
  generatePassword,
  generatePassphrase,
  generatorEntropyBits,
  PASSPHRASE_WORDLIST,
  type GeneratorOptions,
} from '@keyhole/core';
import { StrengthMeter } from './common.tsx';
import { GeneratorOptionsForm } from './GeneratorOptionsForm.tsx';
import { Icon } from './Icon.tsx';

interface GeneratorPanelProps {
  options: GeneratorOptions;
  onOptionsChange: (options: GeneratorOptions) => void;
  onCopy: (value: string, label: string) => void;
}

type Mode = 'password' | 'passphrase';

export function GeneratorPanel({ options, onOptionsChange, onCopy }: GeneratorPanelProps) {
  const [mode, setMode] = useState<Mode>('password');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [wordCount, setWordCount] = useState(5);
  const [separator, setSeparator] = useState('-');

  const regeneratePassword = useCallback((opts: GeneratorOptions) => {
    try {
      setPassword(generatePassword(opts));
      setError(null);
    } catch (err) {
      setPassword('');
      setError(err instanceof Error ? err.message : 'Cannot generate with these options.');
    }
  }, []);

  const regeneratePassphrase = useCallback(() => {
    try {
      setPassword(generatePassphrase(PASSPHRASE_WORDLIST, wordCount, separator));
      setError(null);
    } catch (err) {
      setPassword('');
      setError(err instanceof Error ? err.message : 'Cannot generate passphrase.');
    }
  }, [wordCount, separator]);

  useEffect(() => {
    if (mode === 'password') regeneratePassword(options);
    else regeneratePassphrase();
  }, [mode, options, regeneratePassword, regeneratePassphrase]);

  const bits =
    mode === 'password'
      ? generatorEntropyBits(options)
      : Math.round(wordCount * Math.log2(PASSPHRASE_WORDLIST.length) * 10) / 10;

  return (
    <div>
      <h2 style={{ marginTop: 0 }}>Generator</h2>

      <div className="filter-row" role="tablist" aria-label="Generator mode" style={{ marginBottom: 16 }}>
        <button type="button" className={mode === 'password' ? 'primary' : 'ghost'} onClick={() => setMode('password')}>
          Password
        </button>
        <button
          type="button"
          className={mode === 'passphrase' ? 'primary' : 'ghost'}
          onClick={() => setMode('passphrase')}
        >
          Passphrase
        </button>
      </div>

      <div className="field">
        <label htmlFor="generated">{mode === 'password' ? 'Generated password' : 'Generated passphrase'}</label>
        <div className="field-row">
          <input id="generated" className="mono" readOnly value={password} aria-live="polite" />
          <button
            type="button"
            className="icon"
            onClick={() => (mode === 'password' ? regeneratePassword(options) : regeneratePassphrase())}
            title="Regenerate"
          >
            <Icon name="refresh" />
          </button>
          <button
            type="button"
            className="icon"
            onClick={() => onCopy(password, mode === 'password' ? 'Password' : 'Passphrase')}
            title="Copy"
            disabled={password.length === 0}
          >
            <Icon name="copy" />
          </button>
        </div>
        {error ? (
          <p className="hint" style={{ color: 'var(--danger)' }}>
            {error}
          </p>
        ) : (
          <StrengthMeter password={password} exactBits={bits} />
        )}
      </div>

      {mode === 'password' ? (
        <GeneratorOptionsForm options={options} onChange={onOptionsChange} idPrefix="gen" />
      ) : (
        <div className="section">
          <div className="field">
            <label htmlFor="gen-words">Words: {wordCount}</label>
            <input
              id="gen-words"
              type="range"
              min={3}
              max={12}
              value={wordCount}
              onChange={(e) => setWordCount(Number(e.target.value))}
            />
          </div>
          <div className="field">
            <label htmlFor="gen-sep">Separator</label>
            <select id="gen-sep" value={separator} onChange={(e) => setSeparator(e.target.value)}>
              <option value="-">Hyphen (-)</option>
              <option value=".">Dot (.)</option>
              <option value=" ">Space</option>
              <option value="_">Underscore (_)</option>
            </select>
          </div>
          <p className="hint">Uses the BIP-39 English wordlist ({PASSPHRASE_WORDLIST.length} words).</p>
        </div>
      )}

      <p className="hint" style={{ marginTop: 16 }}>
        Generated with <code>crypto.getRandomValues</code>. Password settings are saved as your defaults.
      </p>
    </div>
  );
}
