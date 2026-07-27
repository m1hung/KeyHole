/**
 * Installed-app plumbing: offline shell registration, the install prompt, and
 * update state.
 *
 * All of it is strictly additive. Every function here degrades to a no-op when
 * the browser lacks the API, and none of it touches the vault, the session or
 * any storage the vault uses — Keyhole in a plain tab behaves exactly as it did
 * before this module existed.
 *
 * Exposed as a tiny external store rather than React state because the events it
 * listens for (`beforeinstallprompt`, `appinstalled`, worker lifecycle) fire
 * outside React and, in the first case, fire *before* React has mounted.
 */

export interface AppShellState {
  /** Running as the packaged Electron desktop build. */
  desktop: boolean;
  /** Running in its own window rather than a browser tab. */
  standalone: boolean;
  /** The browser has an install prompt we are allowed to trigger. */
  installable: boolean;
  /** The offline shell is registered and controlling this page. */
  offlineReady: boolean;
  /** A newer build is installed and waiting for a restart. */
  updateWaiting: boolean;
}

type Listener = () => void;

let state: AppShellState = {
  desktop: false,
  standalone: false,
  installable: false,
  offlineReady: false,
  updateWaiting: false,
};

const listeners = new Set<Listener>();
let deferredPrompt: BeforeInstallPromptEvent | null = null;
/** Set only when the user asked for the update, so we never reload unbidden. */
let reloadOnControllerChange = false;

export function subscribeAppShell(listener: Listener): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

/** Stable snapshot — `useSyncExternalStore` requires reference equality. */
export function getAppShellState(): AppShellState {
  return state;
}

function update(patch: Partial<AppShellState>): void {
  const next = { ...state, ...patch };
  const changed = (Object.keys(next) as (keyof AppShellState)[]).some((key) => next[key] !== state[key]);
  if (!changed) return;
  state = next;
  for (const listener of listeners) listener();
}

// ---------------------------------------------------------------------------

const STANDALONE_QUERY = '(display-mode: standalone), (display-mode: minimal-ui), (display-mode: window-controls-overlay)';

function detectStandalone(): boolean {
  if (window.matchMedia(STANDALONE_QUERY).matches) return true;
  // iOS Safari predates display-mode and reports it here instead.
  return (navigator as Navigator & { standalone?: boolean }).standalone === true;
}

/**
 * Call once, before React mounts. `beforeinstallprompt` can fire during initial
 * page load, and it is only offered once — miss it and there is no way to ask
 * the browser for it again this session.
 */
export function initAppShell(): void {
  /**
   * The desktop build owns its own window, ships its own assets and updates by
   * replacing the .exe. Every mechanism below — the install prompt, the offline
   * shell, the update-and-restart flow — exists to make a *browser* behave like
   * an app, so running any of it here would be redundant at best. The `app://`
   * scheme is not registered for service workers in any case.
   */
  if ((globalThis as { keyhole?: { desktop?: boolean } }).keyhole?.desktop === true) {
    update({ desktop: true, standalone: true });
    return;
  }

  update({ standalone: detectStandalone() });

  const media = window.matchMedia(STANDALONE_QUERY);
  media.addEventListener('change', () => update({ standalone: detectStandalone() }));

  window.addEventListener('beforeinstallprompt', (event) => {
    // Suppress the browser's own banner so the offer lives in Settings, next to
    // the explanation of what installing actually changes.
    event.preventDefault();
    deferredPrompt = event as BeforeInstallPromptEvent;
    update({ installable: true });
  });

  window.addEventListener('appinstalled', () => {
    deferredPrompt = null;
    update({ installable: false });
  });

  if (import.meta.env.PROD) {
    void registerOfflineShell();
  } else {
    // A worker left behind by a production build served on this same port would
    // otherwise shadow the dev server with stale assets and break HMR.
    void unregisterAll();
  }
}

export async function promptInstall(): Promise<'accepted' | 'dismissed' | 'unavailable'> {
  if (!deferredPrompt) return 'unavailable';
  const prompt = deferredPrompt;
  deferredPrompt = null;
  update({ installable: false });
  await prompt.prompt();
  const { outcome } = await prompt.userChoice;
  return outcome;
}

/**
 * Hand control to the waiting build and reload. The reload locks the vault, by
 * the same rule that any reload does — so this is only ever reached through a
 * button that says so.
 */
export async function activateUpdate(): Promise<void> {
  if (!('serviceWorker' in navigator)) return;
  const registration = await navigator.serviceWorker.getRegistration();
  const waiting = registration?.waiting;
  if (!waiting) return;
  reloadOnControllerChange = true;
  waiting.postMessage({ type: 'KEYHOLE_ACTIVATE_UPDATE' });
}

// ---------------------------------------------------------------------------

async function registerOfflineShell(): Promise<void> {
  if (!('serviceWorker' in navigator)) return;

  navigator.serviceWorker.addEventListener('controllerchange', () => {
    if (!reloadOnControllerChange) {
      update({ offlineReady: true });
      return;
    }
    reloadOnControllerChange = false;
    window.location.reload();
  });

  try {
    const registration = await navigator.serviceWorker.register(
      // Resolved against the document so a subpath deploy registers the right
      // script with the right scope.
      new URL('sw.js', document.baseURI).href,
      // 'none' keeps the HTTP cache from serving a stale worker script and
      // pinning users to an old build indefinitely.
      { updateViaCache: 'none' },
    );

    const sync = () =>
      update({
        offlineReady: navigator.serviceWorker.controller !== null,
        updateWaiting: registration.waiting !== null,
      });

    sync();
    registration.addEventListener('updatefound', () => {
      registration.installing?.addEventListener('statechange', sync);
    });
  } catch {
    // Offline support is a convenience. If registration fails — private window,
    // an unusual origin, a locked-down profile — the app still works online, so
    // there is nothing here worth interrupting the user about.
  }
}

async function unregisterAll(): Promise<void> {
  if (!('serviceWorker' in navigator)) return;
  try {
    const registrations = await navigator.serviceWorker.getRegistrations();
    await Promise.all(registrations.map((registration) => registration.unregister()));
  } catch {
    /* nothing registered, or the API is unavailable */
  }
}
