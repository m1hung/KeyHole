/** Small shared UI primitives used by both the app and the extension popup. */

import { useEffect, useRef, useState, type ReactNode } from 'react';
import { estimateStrength, strengthFromBits } from '@keyhole/core';
import { Icon } from './Icon.tsx';

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
  const [justCopied, setJustCopied] = useState(false);

  const copy = () => {
    onCopy();
    setJustCopied(true);
  };

  // Clear the confirmation pulse without leaving a timer running after unmount.
  useEffect(() => {
    if (!justCopied) return;
    const timer = window.setTimeout(() => setJustCopied(false), 900);
    return () => window.clearTimeout(timer);
  }, [justCopied]);

  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      <div className="field-row">
        <input
          id={id}
          className={`mono secret-input${revealed ? ' revealed' : ''}`}
          readOnly
          type="text"
          value={revealed ? value : '•'.repeat(Math.min(value.length, 24))}
          aria-label={revealed ? label : `${label} (hidden)`}
        />
        <button
          type="button"
          className="icon"
          onClick={onToggleReveal}
          aria-pressed={revealed}
          title={revealed ? 'Hide' : 'Show'}
        >
          <Icon name={revealed ? 'eyeOff' : 'eye'} />
        </button>
        <button
          type="button"
          className={`icon${justCopied ? ' just-copied' : ''}`}
          onClick={copy}
          title={`Copy ${label.toLowerCase()}`}
        >
          <Icon name={justCopied ? 'check' : 'copy'} />
        </button>
      </div>
    </div>
  );
}

// ------------------------------------------------------------------ strength

interface StrengthMeterProps {
  password: string;
  /**
   * Exact entropy, when the caller generated this password and knows the pool.
   * Omit for user-typed passwords, where `estimateStrength` must infer it.
   */
  exactBits?: number | undefined;
}

export function StrengthMeter({ password, exactBits }: StrengthMeterProps) {
  const result = exactBits === undefined ? estimateStrength(password) : strengthFromBits(exactBits);
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

interface ToastProps {
  message: string;
  /** Seconds left before the clipboard is cleared, or null when not counting. */
  countdown: number | null;
  /** The full clipboard-clear window, used to pace the ring. */
  totalSeconds?: number;
}

export function Toast({ message, countdown, totalSeconds }: ToastProps) {
  const showRing = countdown !== null && totalSeconds !== undefined && totalSeconds > 0;
  return (
    <div className="toast" role="status" aria-live="polite">
      {showRing && (
        // Drains in step with the countdown so a secret sitting in the
        // clipboard stays visible peripherally, not just as a number to read.
        // The CSS keyframe inherits this duration.
        <svg className="ring" viewBox="0 0 16 16" aria-hidden="true" style={{ animationDuration: `${totalSeconds}s` }}>
          <circle className="track" cx="8" cy="8" r="6.5" />
          <circle className="value" cx="8" cy="8" r="6.5" style={{ animationDuration: `${totalSeconds}s` }} />
        </svg>
      )}
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
