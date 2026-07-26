/** Standalone password generator with live strength feedback. */

import { useCallback, useEffect, useState } from 'react';
import { MAX_LENGTH, MIN_LENGTH, generatePassword, type GeneratorOptions } from '@keyhole/core';
import { StrengthMeter } from './common.tsx';

interface GeneratorPanelProps {
  options: GeneratorOptions;
  onOptionsChange: (options: GeneratorOptions) => void;
  onCopy: (value: string, label: string) => void;
}

export function GeneratorPanel({ options, onOptionsChange, onCopy }: GeneratorPanelProps) {
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);

  const regenerate = useCallback((opts: GeneratorOptions) => {
    try {
      setPassword(generatePassword(opts));
      setError(null);
    } catch (err) {
      setPassword('');
      setError(err instanceof Error ? err.message : 'Cannot generate with these options.');
    }
  }, []);

  useEffect(() => {
    regenerate(options);
  }, [options, regenerate]);

  const update = (patch: Partial<GeneratorOptions>) => onOptionsChange({ ...options, ...patch });

  const classToggles: Array<[keyof GeneratorOptions, string]> = [
    ['lowercase', 'Lowercase (a–z)'],
    ['uppercase', 'Uppercase (A–Z)'],
    ['digits', 'Digits (0–9)'],
    ['symbols', 'Symbols (!@#$%^&*)'],
  ];

  return (
    <div>
      <h2 style={{ marginTop: 0 }}>Password generator</h2>

      <div className="field">
        <label htmlFor="generated">Generated password</label>
        <div className="field-row">
          <input id="generated" className="mono" readOnly value={password} aria-live="polite" />
          <button type="button" className="icon" onClick={() => regenerate(options)} title="Regenerate">
            🔄
          </button>
          <button
            type="button"
            className="icon"
            onClick={() => onCopy(password, 'Password')}
            title="Copy"
            disabled={password.length === 0}
          >
            📋
          </button>
        </div>
        {error ? <p className="hint" style={{ color: 'var(--danger)' }}>{error}</p> : <StrengthMeter password={password} />}
      </div>

      <div className="field">
        <label htmlFor="length">Length: {options.length}</label>
        <input
          id="length"
          type="range"
          min={MIN_LENGTH}
          max={MAX_LENGTH}
          value={options.length}
          onChange={(e) => update({ length: Number(e.target.value) })}
        />
      </div>

      <div className="section">
        <h3>Character classes</h3>
        {classToggles.map(([key, label]) => (
          <div className="checkbox-row" key={key}>
            <input
              id={`gen-${key}`}
              type="checkbox"
              checked={options[key] as boolean}
              onChange={(e) => update({ [key]: e.target.checked } as Partial<GeneratorOptions>)}
            />
            <label htmlFor={`gen-${key}`}>{label}</label>
          </div>
        ))}
        <div className="checkbox-row">
          <input
            id="gen-ambiguous"
            type="checkbox"
            checked={options.excludeAmbiguous}
            onChange={(e) => update({ excludeAmbiguous: e.target.checked })}
          />
          <label htmlFor="gen-ambiguous">Exclude look-alike characters (0/O, 1/l/I)</label>
        </div>
      </div>

      <p className="hint" style={{ marginTop: 16 }}>
        Generated with <code>crypto.getRandomValues</code> and rejection sampling, so every character is equally
        likely. These settings are saved as your defaults.
      </p>
    </div>
  );
}
