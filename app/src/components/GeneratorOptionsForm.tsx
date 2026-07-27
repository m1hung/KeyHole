/** Shared length / character-class controls for the password generator. */

import { MAX_LENGTH, MIN_LENGTH, type GeneratorOptions } from '@keyhole/core';

const CLASS_TOGGLES: Array<[keyof GeneratorOptions, string]> = [
  ['lowercase', 'Lowercase (a–z)'],
  ['uppercase', 'Uppercase (A–Z)'],
  ['digits', 'Digits (0–9)'],
  ['symbols', 'Symbols (!@#$%^&*)'],
];

interface GeneratorOptionsFormProps {
  options: GeneratorOptions;
  onChange: (options: GeneratorOptions) => void;
  /** Prefix for input ids so multiple forms can coexist on one page. */
  idPrefix: string;
  /** Compact layout for the entry editor. */
  compact?: boolean;
}

export function GeneratorOptionsForm({ options, onChange, idPrefix, compact = false }: GeneratorOptionsFormProps) {
  const update = (patch: Partial<GeneratorOptions>) => onChange({ ...options, ...patch });

  return (
    <div className={compact ? 'generator-options compact' : 'generator-options'}>
      <div className="field">
        <label htmlFor={`${idPrefix}-length`}>Length: {options.length}</label>
        <input
          id={`${idPrefix}-length`}
          type="range"
          min={MIN_LENGTH}
          max={MAX_LENGTH}
          value={options.length}
          onChange={(e) => update({ length: Number(e.target.value) })}
        />
      </div>

      <div className={compact ? undefined : 'section'} style={compact ? { marginTop: 4 } : undefined}>
        {!compact && <h3>Character classes</h3>}
        <div className={compact ? 'generator-class-grid' : undefined}>
          {CLASS_TOGGLES.map(([key, label]) => (
            <div className="checkbox-row" key={key}>
              <input
                id={`${idPrefix}-${key}`}
                type="checkbox"
                checked={options[key] as boolean}
                onChange={(e) => update({ [key]: e.target.checked } as Partial<GeneratorOptions>)}
              />
              <label htmlFor={`${idPrefix}-${key}`}>{compact ? shortLabel(key) : label}</label>
            </div>
          ))}
          <div className="checkbox-row">
            <input
              id={`${idPrefix}-ambiguous`}
              type="checkbox"
              checked={options.excludeAmbiguous}
              onChange={(e) => update({ excludeAmbiguous: e.target.checked })}
            />
            <label htmlFor={`${idPrefix}-ambiguous`}>
              {compact ? 'Exclude look-alikes' : 'Exclude look-alike characters (0/O, 1/l/I)'}
            </label>
          </div>
        </div>
      </div>
    </div>
  );
}

function shortLabel(key: keyof GeneratorOptions): string {
  switch (key) {
    case 'lowercase':
      return 'a–z';
    case 'uppercase':
      return 'A–Z';
    case 'digits':
      return '0–9';
    case 'symbols':
      return '!@#$%^&*';
    default:
      return String(key);
  }
}
