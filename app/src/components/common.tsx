/** Small shared UI primitives used by both the app and the extension popup. */

import { useEffect, useRef, type ReactNode } from 'react';
import { estimateStrength } from '@keyhole/core';

// ------------------------------------------------------------------ secrets

interface SecretFieldProps {
  label: string;
  value: string;
  revealed: boolean;
  onToggleReveal: () => void;
  onCopy: () => void;
  id: string;
}

/**
 * Displays a secret. When hidden the DOM holds a bullet placeholder rather than
 * the real value, so a screenshot, a screen-share or a stray DOM inspection
 * cannot expose it while it is "hidden".
 */
export function SecretField({ label, value, revealed, onToggleReveal, onCopy, id }: SecretFieldProps) {
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      <div className="field-row">
        <input
          id={id}
          className="mono"
          readOnly
          type="text"
          value={revealed ? value : '•'.repeat(Math.min(value.length, 24))}
          aria-label={revealed ? label : `${label} (hidden)`}
        />
        <button type="button" className="icon" onClick={onToggleReveal} aria-pressed={revealed} title={revealed ? 'Hide' : 'Show'}>
          {revealed ? '🙈' : '👁'}
        </button>
        <button type="button" className="icon" onClick={onCopy} title={`Copy ${label.toLowerCase()}`}>
          📋
        </button>
      </div>
    </div>
  );
}

// ------------------------------------------------------------------ strength

export function StrengthMeter({ password }: { password: string }) {
  const result = estimateStrength(password);
  const colors = ['var(--danger)', 'var(--danger)', 'var(--warn)', 'var(--ok)', 'var(--ok)'];
  return (
    <div className="strength">
      <div className="strength-track">
        <div
          className="strength-fill"
          style={{ width: `${Math.min(100, (result.bits / 128) * 100)}%`, background: colors[result.score] }}
        />
      </div>
      <div className="strength-label">
        <span>
          {result.label} · {result.bits} bits
        </span>
        <span>{result.crackTimeDisplay}</span>
      </div>
      {/* Announced to screen readers only when it settles, not on every keystroke. */}
      <span className="sr-only" role="status">
        Password strength: {result.label}
      </span>
    </div>
  );
}

// ------------------------------------------------------------------- dialog

interface ConfirmDialogProps {
  open: boolean;
  title: string;
  children: ReactNode;
  confirmLabel: string;
  danger?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
  confirmDisabled?: boolean;
}

export function ConfirmDialog({
  open,
  title,
  children,
  confirmLabel,
  danger = false,
  onConfirm,
  onCancel,
  confirmDisabled = false,
}: ConfirmDialogProps) {
  const ref = useRef<HTMLDialogElement>(null);

  useEffect(() => {
    const dialog = ref.current;
    if (!dialog) return;
    // showModal() gives us focus trapping and Escape handling for free.
    if (open && !dialog.open) dialog.showModal();
    if (!open && dialog.open) dialog.close();
  }, [open]);

  return (
    <dialog ref={ref} onCancel={onCancel} aria-labelledby="confirm-title">
      <h2 id="confirm-title">{title}</h2>
      {children}
      <div className="dialog-actions">
        <button type="button" onClick={onCancel}>
          Cancel
        </button>
        <button
          type="button"
          className={danger ? 'danger' : 'primary'}
          onClick={onConfirm}
          disabled={confirmDisabled}
        >
          {confirmLabel}
        </button>
      </div>
    </dialog>
  );
}

// -------------------------------------------------------------------- toast

export function Toast({ message, countdown }: { message: string; countdown: number | null }) {
  return (
    <div className="toast" role="status" aria-live="polite">
      <span>{message}</span>
      {countdown !== null && <span className="countdown">clears in {countdown}s</span>}
    </div>
  );
}

// --------------------------------------------------------------- empty state

export function EmptyState({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="empty-state">
      <p style={{ fontWeight: 600, color: 'var(--text)' }}>{title}</p>
      {children}
    </div>
  );
}
