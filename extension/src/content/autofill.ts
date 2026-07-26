/**
 * Content script — runs in the page, and is therefore the LEAST trusted part of
 * Keyhole.
 *
 * What it deliberately does NOT do:
 *  - hold the master key, the vault key, or any vault data
 *  - read existing page passwords, or scrape form values
 *  - request anything from the service worker (messaging is one-way, in)
 *  - run at document_start on every page — it is injected on demand, under
 *    `activeTab`, only after the user opens the popup and clicks Fill
 *
 * It receives one credential, writes it into two fields, and forgets it.
 */

/**
 * DEPENDENCY-FREE BY DESIGN. This file imports nothing — not zod, not the core.
 *
 * Everything injected here runs inside the page's process, so every kilobyte is
 * both attack surface and a cost paid on each fill. Importing the shared zod
 * schemas pulled ~130 KB of parser into every page; the hand-rolled check below
 * validates the same three fields in a dozen lines and keeps the bundle ~4 KB.
 */

interface FillCommand {
  type: 'KEYHOLE_FILL';
  username: string;
  password: string;
  expectedOrigin: string;
}

function parseFillCommand(raw: unknown): FillCommand | null {
  if (typeof raw !== 'object' || raw === null) return null;
  const candidate = raw as Record<string, unknown>;
  if (candidate['type'] !== 'KEYHOLE_FILL') return null;
  const { username, password, expectedOrigin } = candidate;
  if (typeof username !== 'string' || username.length > 512) return null;
  if (typeof password !== 'string' || password.length > 4096) return null;
  if (typeof expectedOrigin !== 'string' || expectedOrigin.length > 2048) return null;
  return { type: 'KEYHOLE_FILL', username, password, expectedOrigin };
}

/**
 * Guard against double injection — `executeScript` runs this file on every fill,
 * and registering the listener twice would answer each message twice.
 *
 * A local cast rather than `declare global`, so this file stays a plain script
 * with no imports or exports, which is what a classic content script must be.
 */
const injectionFlag = window as Window & { __keyholeContentLoaded?: boolean };

if (!injectionFlag.__keyholeContentLoaded) {
  injectionFlag.__keyholeContentLoaded = true;
  install();
}

function install(): void {
  chrome.runtime.onMessage.addListener((raw, sender, sendResponse) => {
    // Only our own extension may drive this script. A page cannot forge
    // `sender.id`; chrome.runtime.onMessage is not reachable from page JS at all.
    if (sender.id !== chrome.runtime.id) {
      sendResponse(undefined);
      return false;
    }

    const command = parseFillCommand(raw);
    if (!command) {
      sendResponse(undefined);
      return false;
    }

    // Second origin check, in the page's own context. The service worker already
    // verified the tab URL; this catches an in-flight same-tab navigation and
    // costs nothing.
    if (window.location.origin !== command.expectedOrigin) {
      sendResponse({ filledUsername: false, filledPassword: false });
      return false;
    }

    sendResponse(performFill(command.username, command.password));
    return false;
  });
}

// ---------------------------------------------------------------------------
// Field detection
// ---------------------------------------------------------------------------

function isVisible(element: HTMLElement): boolean {
  if (element.hidden) return false;
  const style = window.getComputedStyle(element);
  if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
  const rect = element.getBoundingClientRect();
  return rect.width > 0 && rect.height > 0;
}

function isUsable(input: HTMLInputElement): boolean {
  return !input.disabled && !input.readOnly && isVisible(input);
}

/**
 * Password field: the first visible, usable `type=password`.
 *
 * Deliberately does not look at any other password input on the page, and never
 * reads `.value` from one.
 */
function findPasswordField(root: Document): HTMLInputElement | null {
  const candidates = [...root.querySelectorAll<HTMLInputElement>('input[type="password"]')].filter(isUsable);
  return candidates[0] ?? null;
}

/**
 * Username field: prefer the usable text-like input immediately preceding the
 * password field in DOM order, which is the near-universal login layout. Fall
 * back to autocomplete/name/type hints.
 */
function findUsernameField(root: Document, passwordField: HTMLInputElement | null): HTMLInputElement | null {
  const textInputs = [...root.querySelectorAll<HTMLInputElement>('input')].filter(
    (input) => ['text', 'email', 'tel', ''].includes(input.type.toLowerCase()) && isUsable(input),
  );

  if (passwordField) {
    const all = [...root.querySelectorAll<HTMLInputElement>('input')];
    const passwordIndex = all.indexOf(passwordField);
    const preceding = textInputs.filter((input) => all.indexOf(input) < passwordIndex);
    const nearest = preceding[preceding.length - 1];
    if (nearest) return nearest;
  }

  const hinted = textInputs.find((input) => {
    const hint = `${input.autocomplete} ${input.name} ${input.id} ${input.getAttribute('aria-label') ?? ''}`.toLowerCase();
    return /user|email|login|account|identifi/.test(hint);
  });
  return hinted ?? textInputs[0] ?? null;
}

// ---------------------------------------------------------------------------
// Filling
// ---------------------------------------------------------------------------

/**
 * Set a value the way a user would, so React/Vue/Angular controlled inputs
 * actually register it.
 *
 * Assigning `.value` directly is swallowed by React's synthetic event system —
 * it tracks the last value it set and treats a direct assignment as a no-op.
 * Going through the native setter and then dispatching bubbling input/change
 * events is what makes framework-driven login forms accept the fill.
 */
function setFieldValue(field: HTMLInputElement, value: string): void {
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
  if (setter) setter.call(field, value);
  else field.value = value;

  field.dispatchEvent(new Event('input', { bubbles: true }));
  field.dispatchEvent(new Event('change', { bubbles: true }));
}

function performFill(username: string, password: string): { filledUsername: boolean; filledPassword: boolean } {
  const passwordField = findPasswordField(document);
  const usernameField = findUsernameField(document, passwordField);

  let filledUsername = false;
  let filledPassword = false;

  if (usernameField && username.length > 0) {
    setFieldValue(usernameField, username);
    filledUsername = true;
  }
  if (passwordField && password.length > 0) {
    setFieldValue(passwordField, password);
    filledPassword = true;
  }

  // Focus the password field so the user can submit directly, and so it is
  // obvious which fields were touched.
  if (passwordField) passwordField.focus();

  flash(usernameField, filledUsername);
  flash(passwordField, filledPassword);

  return { filledUsername, filledPassword };
}

/**
 * Brief outline on filled fields.
 *
 * This is the only DOM mutation Keyhole makes beyond the field values, and it
 * is reverted after the animation so no trace is left in the page's styles.
 */
function flash(field: HTMLInputElement | null, didFill: boolean): void {
  if (!field || !didFill) return;
  const previousOutline = field.style.outline;
  const previousTransition = field.style.transition;
  field.style.transition = 'outline 120ms ease';
  field.style.outline = '2px solid #4f46e5';
  window.setTimeout(() => {
    field.style.outline = previousOutline;
    field.style.transition = previousTransition;
  }, 900);
}
