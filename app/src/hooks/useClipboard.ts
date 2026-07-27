/**
 * Clipboard copy with an automatic clear timer.
 *
 * HONEST LIMITATION: clearing only works while this page is alive and the
 * clipboard still holds what we put there. It cannot reach OS clipboard
 * managers or sync features (Handoff, Windows clipboard history) that may have
 * already captured the value. It closes the common window — a password sitting
 * in the clipboard for hours — not every window.
 */

import { useCallback, useEffect, useRef, useState } from 'react';

export interface ClipboardController {
  copy: (value: string, label: string) => Promise<void>;
  /** Seconds remaining before the clipboard is cleared, or null when idle. */
  secondsRemaining: number | null;
  lastCopied: string | null;
  /** Set when a copy failed, so the UI never implies success that did not happen. */
  error: string | null;
}

export function useClipboard(clearAfterSeconds: number): ClipboardController {
  const [secondsRemaining, setSecondsRemaining] = useState<number | null>(null);
  const [lastCopied, setLastCopied] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const copiedValueRef = useRef<string | null>(null);
  const intervalRef = useRef<number | null>(null);

  const stopTimer = useCallback(() => {
    if (intervalRef.current !== null) {
      window.clearInterval(intervalRef.current);
      intervalRef.current = null;
    }
    setSecondsRemaining(null);
  }, []);

  const clearClipboard = useCallback(async () => {
    try {
      // Only clear if the clipboard still holds our value — otherwise we would
      // destroy whatever the user copied since.
      const current = await navigator.clipboard.readText().catch(() => null);
      if (current === null || current === copiedValueRef.current) {
        await navigator.clipboard.writeText('');
      }
    } catch {
      /* clipboard permission denied — nothing we can do */
    } finally {
      copiedValueRef.current = null;
      setLastCopied(null);
      stopTimer();
    }
  }, [stopTimer]);

  const copy = useCallback(
    async (value: string, label: string) => {
      setError(null);

      /**
       * `writeText` rejects on a NotAllowedError when the document is not
       * focused, or when clipboard permission is denied by policy.
       *
       * Before, the rejection propagated into a `void copy(...)` call site and
       * vanished: no toast, no error, nothing. The user would then paste
       * whatever was already on the clipboard, believing it was their password.
       * Failing loudly is the only safe option here.
       */
      try {
        await navigator.clipboard.writeText(value);
      } catch {
        setLastCopied(null);
        stopTimer();
        setError(`Could not copy ${label.toLowerCase()} — the browser denied clipboard access.`);
        return;
      }

      copiedValueRef.current = value;
      setLastCopied(label);
      stopTimer();

      if (clearAfterSeconds <= 0) return;

      let remaining = clearAfterSeconds;
      setSecondsRemaining(remaining);
      intervalRef.current = window.setInterval(() => {
        remaining -= 1;
        if (remaining <= 0) {
          void clearClipboard();
        } else {
          setSecondsRemaining(remaining);
        }
      }, 1000);
    },
    [clearAfterSeconds, clearClipboard, stopTimer],
  );

  // Clear on unmount so a copied secret does not outlive the page.
  useEffect(() => {
    return () => {
      if (intervalRef.current !== null) window.clearInterval(intervalRef.current);
      if (copiedValueRef.current !== null) void navigator.clipboard.writeText('').catch(() => undefined);
    };
  }, []);

  return { copy, secondsRemaining, lastCopied, error };
}
