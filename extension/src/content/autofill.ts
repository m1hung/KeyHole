/**
 * Content script — runs in the page, and is therefore the LEAST trusted part of
 * Keyhole.
 *
 * What it deliberately does NOT do:
 *  - hold the master key, the vault key, or any vault data
 *  - read existing page passwords, or scrape form values
 *  - receive passwords until the user picks a specific suggestion (or Fill)
 *
 * Injection:
 *  - On demand via `activeTab` when the user clicks Fill in the popup
 *  - Persistently (after the user grants optional host access) so login fields
 *    can show suggestions on focus/click
 *
 * It may ask the service worker for *metadata* matches for this tab, and for a
 * fill of one chosen entry. Matching always uses the tab URL from Chrome —
 * never a URL supplied by this script.
 */

/**
 * DEPENDENCY-FREE BY DESIGN. This file imports nothing — not zod, not the core.
 *
 * Everything injected here runs inside the page's process, so every kilobyte is
 * both attack surface and a cost paid on each fill. Importing the shared zod
 * schemas pulled ~130 KB of parser into every page; the hand-rolled checks
 * below keep the bundle tiny.
 */

interface FillCommand {
  type: 'KEYHOLE_FILL';
  username: string;
  password: string;
  totp?: string;
  expectedOrigin: string;
}

interface SuggestEntry {
  id: string;
  title: string;
  username: string;
  host: string | null;
  matchStrength?: string;
}

interface SuggestResponse {
  ok: boolean;
  type?: string;
  locked?: boolean;
  theme?: 'light' | 'dark' | 'system';
  entries?: SuggestEntry[];
  error?: string;
}

interface PendingSave {
  username: string;
  password: string;
  host: string;
}

function parseFillCommand(raw: unknown): FillCommand | null {
  if (typeof raw !== 'object' || raw === null) return null;
  const candidate = raw as Record<string, unknown>;
  if (candidate['type'] !== 'KEYHOLE_FILL') return null;
  const { username, password, expectedOrigin, totp } = candidate;
  if (typeof username !== 'string' || username.length > 512) return null;
  if (typeof password !== 'string' || password.length > 4096) return null;
  if (typeof expectedOrigin !== 'string' || expectedOrigin.length > 2048) return null;
  if (totp !== undefined && (typeof totp !== 'string' || totp.length > 16)) return null;
  return {
    type: 'KEYHOLE_FILL',
    username,
    password,
    expectedOrigin,
    ...(typeof totp === 'string' ? { totp } : {}),
  };
}

/**
 * Guard against double injection — `executeScript` and declared content_scripts
 * can both load this file. Registering twice would answer each message twice
 * and stack duplicate focus listeners.
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
    // verified the tab URL; this catches an in-flight same-tab navigation.
    if (window.location.origin !== command.expectedOrigin) {
      sendResponse({ filledUsername: false, filledPassword: false, filledTotp: false });
      return false;
    }

    hideSuggestions();
    sendResponse(performFill(command.username, command.password, command.totp));
    return false;
  });

  document.addEventListener('focusin', onFocusIn, true);
  document.addEventListener('pointerdown', onPointerDown, true);
  document.addEventListener('keydown', onKeyDown, true);
  document.addEventListener('submit', onFormSubmit, true);
  // Reposition on viewport scroll/resize — do NOT dismiss. Capture-phase scroll
  // on window previously hid the menu as soon as Reddit (and many SPAs) fired
  // nested scroll events while focusing a field.
  window.addEventListener('scroll', onViewportChange, true);
  window.addEventListener('resize', onViewportChange);
}

// ---------------------------------------------------------------------------
// Field detection (shadow-DOM aware)
// ---------------------------------------------------------------------------

/**
 * Collect inputs across open shadow roots.
 *
 * Sites like Reddit wrap login fields in web components (`faceplate-text-input`)
 * whose real `<input>` lives inside an open shadow tree. Light-DOM
 * `querySelectorAll('input')` sees nothing there.
 *
 * Closed shadow roots remain unreachable by design.
 */
function deepQueryAllInputs(root: ParentNode): HTMLInputElement[] {
  const results: HTMLInputElement[] = [];
  const visit = (node: ParentNode): void => {
    for (const input of node.querySelectorAll('input')) {
      results.push(input as HTMLInputElement);
    }
    for (const el of node.querySelectorAll('*')) {
      if (el.shadowRoot) visit(el.shadowRoot);
    }
  };
  visit(root);
  return results;
}

/** Walk out of shadow trees to the nearest form-like container. */
function containingForm(input: HTMLInputElement): Element | null {
  let node: Element | null = input;
  while (node) {
    const tag = node.tagName.toLowerCase();
    if (tag === 'form' || tag === 'faceplate-form') return node;
    if (node.assignedSlot) {
      node = node.assignedSlot;
      continue;
    }
    const rootNode = node.getRootNode();
    if (rootNode instanceof ShadowRoot) {
      node = rootNode.host;
      continue;
    }
    node = node.parentElement;
  }
  return null;
}

function shadowHost(input: HTMLInputElement): Element | null {
  const root = input.getRootNode();
  return root instanceof ShadowRoot ? root.host : null;
}

function isVisible(element: HTMLElement): boolean {
  if (element.hidden) return false;
  const style = window.getComputedStyle(element);
  if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
  const rect = element.getBoundingClientRect();
  if (rect.width > 0 && rect.height > 0) return true;
  // Some web-component hosts size the control while the inner input is tiny;
  // treat a visible host as usable.
  const host = shadowHost(element as HTMLInputElement);
  if (host instanceof HTMLElement) {
    const hostStyle = window.getComputedStyle(host);
    if (hostStyle.display === 'none' || hostStyle.visibility === 'hidden') return false;
    const hostRect = host.getBoundingClientRect();
    return hostRect.width > 0 && hostRect.height > 0;
  }
  return false;
}

function isUsable(input: HTMLInputElement): boolean {
  return !input.disabled && !input.readOnly && isVisible(input);
}

function attrBlob(input: HTMLInputElement): string {
  const labelledBy = input.getAttribute('aria-labelledby');
  let labelText = '';
  if (labelledBy) {
    const scope = input.getRootNode();
    for (const id of labelledBy.split(/\s+/)) {
      const node =
        scope instanceof Document || scope instanceof ShadowRoot
          ? scope.getElementById(id)
          : document.getElementById(id);
      if (node) labelText += ` ${node.textContent ?? ''}`;
    }
  }
  if (input.id) {
    const forLabel = document.querySelector(`label[for="${cssEscape(input.id)}"]`);
    if (forLabel) labelText += ` ${forLabel.textContent ?? ''}`;
  }
  const parentLabel = input.closest('label');
  if (parentLabel) labelText += ` ${parentLabel.textContent ?? ''}`;

  const host = shadowHost(input);
  const hostBits = host
    ? [
        host.id,
        host.getAttribute('name') ?? '',
        host.getAttribute('autocomplete') ?? '',
        host.getAttribute('type') ?? '',
        host.getAttribute('aria-label') ?? '',
        host.textContent ?? '',
      ]
    : [];

  return [
    input.autocomplete,
    input.name,
    input.id,
    input.placeholder,
    input.getAttribute('aria-label') ?? '',
    input.getAttribute('aria-describedby') ?? '',
    input.getAttribute('data-testid') ?? '',
    labelText,
    ...hostBits,
  ]
    .join(' ')
    .toLowerCase();
}

/** Minimal CSS.escape polyfill for id selectors in older contexts. */
function cssEscape(value: string): string {
  if (typeof CSS !== 'undefined' && typeof CSS.escape === 'function') return CSS.escape(value);
  return value.replace(/([ !"#$%&'()*+,./:;<=>?@[\\\]^`{|}~])/g, '\\$1');
}

function autocompleteOf(input: HTMLInputElement): string {
  const host = shadowHost(input);
  return `${input.autocomplete} ${host?.getAttribute('autocomplete') ?? ''}`.toLowerCase();
}

function passwordScore(input: HTMLInputElement): number {
  if (input.type.toLowerCase() !== 'password' || !isUsable(input)) return -1;
  let score = 40;
  const ac = autocompleteOf(input);
  if (ac.includes('current-password')) score += 50;
  else if (ac.includes('new-password')) score += 20;
  else if (ac.includes('password')) score += 30;
  const hint = attrBlob(input);
  if (/\b(current[-_]?password|password|passwd|pwd|passcode)\b/.test(hint)) score += 25;
  if (/\b(confirm|repeat|verify|new[-_]?password)\b/.test(hint)) score -= 15;
  return score;
}

function usernameScore(input: HTMLInputElement, passwordField: HTMLInputElement | null, allInputs: HTMLInputElement[]): number {
  const type = input.type.toLowerCase();
  if (!['text', 'email', 'tel', 'url', ''].includes(type) || !isUsable(input)) return -1;

  let score = 10;
  const ac = autocompleteOf(input);
  if (ac.includes('username') || ac.includes('webauthn')) score += 50;
  else if (/\bemail\b/.test(ac)) score += 40;
  if (ac.includes('one-time-code') || ac.includes('one-time')) score -= 80;
  if (type === 'email') score += 30;
  if (type === 'tel') score += 10;

  const hint = attrBlob(input);
  if (/\b(user(name)?|e-?mail|login|account|identifi|userid|user[-_]?id|phone|mobile)\b/.test(hint)) {
    score += 35;
  }
  // Search / filter / OTP boxes should rarely win.
  if (/\b(search|query|filter|otp|captcha|backup|verification)\b/.test(hint)) score -= 40;
  if (/\bone[-_]?time[-_]?code\b|\b(app|backup)?otp\b/.test(hint)) score -= 50;

  if (passwordField) {
    const passwordForm = containingForm(passwordField);
    const inputForm = containingForm(input);
    if (passwordForm && inputForm && passwordForm === inputForm) score += 30;

    const passwordIndex = allInputs.indexOf(passwordField);
    const inputIndex = allInputs.indexOf(input);
    if (inputIndex >= 0 && passwordIndex >= 0 && inputIndex < passwordIndex) {
      const distance = passwordIndex - inputIndex;
      if (distance === 1) score += 25;
      else if (distance <= 3) score += 15;
      else if (distance <= 8) score += 5;
    }
  }

  return score;
}

function findPasswordField(root: ParentNode): HTMLInputElement | null {
  let best: HTMLInputElement | null = null;
  let bestScore = -1;
  for (const input of deepQueryAllInputs(root)) {
    if (input.type.toLowerCase() !== 'password') continue;
    const score = passwordScore(input);
    if (score > bestScore) {
      bestScore = score;
      best = input;
    }
  }
  return bestScore >= 0 ? best : null;
}

function findUsernameField(root: ParentNode, passwordField: HTMLInputElement | null): HTMLInputElement | null {
  const form = passwordField ? containingForm(passwordField) : null;
  const scope: ParentNode = form ?? root;
  const scopedInputs = deepQueryAllInputs(scope);
  const allInputs = scope === root ? scopedInputs : deepQueryAllInputs(root);

  let best: HTMLInputElement | null = null;
  let bestScore = -1;

  for (const input of scopedInputs) {
    if (input === passwordField) continue;
    const score = usernameScore(input, passwordField, allInputs);
    if (score > bestScore) {
      bestScore = score;
      best = input;
    }
  }

  // Multi-step / split layouts: widen to the document if the form was weak.
  if ((!best || bestScore < 25) && form && root !== form) {
    for (const input of allInputs) {
      if (input === passwordField) continue;
      const score = usernameScore(input, passwordField, allInputs);
      if (score > bestScore) {
        bestScore = score;
        best = input;
      }
    }
  }

  return bestScore >= 0 ? best : null;
}

/**
 * Resolve the real focused/clicked input.
 *
 * Listeners outside a shadow tree see a retargeted `event.target` (often the
 * custom-element host). `composedPath()` still contains the inner `<input>`
 * when the event originated there; clicks on host labels/slots may not — in
 * that case we resolve the host's shadow input (Reddit faceplate-text-input).
 */
function eventInput(event: Event): HTMLInputElement | null {
  for (const node of event.composedPath()) {
    if (node instanceof HTMLInputElement) return node;
  }
  for (const node of event.composedPath()) {
    if (!(node instanceof Element)) continue;
    if (node.shadowRoot) {
      const nested = node.shadowRoot.querySelector('input');
      if (nested instanceof HTMLInputElement) return nested;
    }
  }
  const target = event.target;
  if (target instanceof HTMLInputElement) return target;
  if (target instanceof Element && target.shadowRoot) {
    const active = target.shadowRoot.activeElement;
    if (active instanceof HTMLInputElement) return active;
    const nested = target.shadowRoot.querySelector('input');
    if (nested instanceof HTMLInputElement) return nested;
  }
  return null;
}

/** True when the focused control looks like a login username or password field. */
function isLoginField(input: HTMLInputElement | null): input is HTMLInputElement {
  if (!input || !isUsable(input)) return false;
  if (input.type.toLowerCase() === 'password') return passwordScore(input) >= 0;

  const ac = autocompleteOf(input);
  // Strong signal from the control or its shadow host — enough on its own
  // (username-only steps, Reddit, etc.).
  if (ac.includes('username') || ac.includes('webauthn') || /\bemail\b/.test(ac)) return true;

  const form = containingForm(input);
  const password = findPasswordField(form ?? document);
  const allInputs = deepQueryAllInputs(form ?? document);
  const score = usernameScore(input, password, allInputs);
  if (score >= 40) return true;
  if (password && form && containingForm(password) === form && score >= 20) return true;
  return false;
}

// ---------------------------------------------------------------------------
// Filling
// ---------------------------------------------------------------------------

/**
 * Set a value the way a user would, so React/Vue/Angular controlled inputs
 * actually register it.
 */
function setFieldValue(field: HTMLInputElement, value: string): void {
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
  if (setter) setter.call(field, value);
  else field.value = value;

  // `composed: true` so web components listening on the host (Reddit faceplate,
  // etc.) see the event cross the shadow boundary.
  field.dispatchEvent(new Event('input', { bubbles: true, composed: true }));
  field.dispatchEvent(new Event('change', { bubbles: true, composed: true }));

  const host = shadowHost(field);
  if (host && 'value' in host) {
    try {
      (host as HTMLInputElement).value = value;
    } catch {
      // Host may expose a read-only value accessor; ignore.
    }
  }
}

function findOtpField(root: ParentNode): HTMLInputElement | null {
  let best: HTMLInputElement | null = null;
  let bestScore = -1;
  for (const input of deepQueryAllInputs(root)) {
    const type = input.type.toLowerCase();
    if (!['text', 'tel', 'number', 'one-time-code', ''].includes(type) || !isUsable(input)) continue;
    if (type === 'password') continue;

    let score = 0;
    const ac = autocompleteOf(input);
    if (ac.includes('one-time-code') || ac.includes('one-time')) score += 80;
    const hint = attrBlob(input);
    if (/\b(one[-_]?time|otp|totp|2fa|mfa|authenticator|verification[-_]?code|security[-_]?code)\b/.test(hint)) {
      score += 50;
    }
    if (/\b(search|query|filter|username|email|password)\b/.test(hint)) score -= 40;
    if (input.maxLength > 0 && input.maxLength <= 8) score += 15;
    if (score > bestScore) {
      bestScore = score;
      best = input;
    }
  }
  return bestScore >= 40 ? best : null;
}

function performFill(
  username: string,
  password: string,
  totp?: string,
): { filledUsername: boolean; filledPassword: boolean; filledTotp: boolean } {
  const passwordField = findPasswordField(document);
  const usernameField = findUsernameField(document, passwordField);
  const otpField = totp && totp.length > 0 ? findOtpField(document) : null;

  let filledUsername = false;
  let filledPassword = false;
  let filledTotp = false;

  if (usernameField && username.length > 0) {
    setFieldValue(usernameField, username);
    filledUsername = true;
  }
  if (passwordField && password.length > 0) {
    setFieldValue(passwordField, password);
    filledPassword = true;
  }
  if (otpField && totp && totp.length > 0) {
    setFieldValue(otpField, totp);
    filledTotp = true;
  }

  if (otpField && filledTotp) otpField.focus();
  else if (passwordField) passwordField.focus();
  else if (usernameField) usernameField.focus();

  flash(usernameField, filledUsername);
  flash(passwordField, filledPassword);
  flash(otpField, filledTotp);

  return { filledUsername, filledPassword, filledTotp };
}

function flash(field: HTMLInputElement | null, didFill: boolean): void {
  if (!field || !didFill) return;
  const host = shadowHost(field);
  const target = host instanceof HTMLElement ? host : field;
  const previousOutline = target.style.outline;
  const previousTransition = target.style.transition;
  target.style.transition = 'outline 120ms ease';
  target.style.outline = '2px solid #0f62d0';
  window.setTimeout(() => {
    target.style.outline = previousOutline;
    target.style.transition = previousTransition;
  }, 900);
}

// ---------------------------------------------------------------------------
// Inline suggestions
// ---------------------------------------------------------------------------

let activeField: HTMLInputElement | null = null;
let suggestHost: HTMLElement | null = null;
let suggestRoot: ShadowRoot | null = null;
let suggestRequestId = 0;

function onFocusIn(event: FocusEvent): void {
  const input = eventInput(event);
  if (!isLoginField(input)) {
    // Keep the menu open when focus moves into it.
    if (suggestHost && event.target instanceof Node && suggestHost.contains(event.target)) return;
    hideSuggestions();
    return;
  }
  activeField = input;
  void showSuggestions(input);
}

function onPointerDown(event: Event): void {
  const input = eventInput(event);
  if (suggestHost) {
    for (const node of event.composedPath()) {
      if (node === suggestHost) return;
    }
  }
  // Clicking a login field should open (or keep) suggestions — never schedule a hide.
  if (isLoginField(input)) {
    activeField = input;
    void showSuggestions(input);
    return;
  }
  if (activeField && event.target instanceof Node && activeField.contains(event.target)) return;

  // Outside click: dismiss on the next tick so a suggestion button click can fire.
  window.setTimeout(() => {
    if (!suggestHost) return;
    const focused = deepActiveInput();
    if (focused && suggestHost.contains(focused)) return;
    if (isLoginField(focused) && focused === activeField) return;
    hideSuggestions();
  }, 0);
}

function onViewportChange(): void {
  if (!suggestHost || !activeField) return;
  if (!activeField.isConnected) {
    hideSuggestions();
    return;
  }
  positionSuggest(activeField);
}

function deepActiveInput(): HTMLInputElement | null {
  let active: Element | null = document.activeElement;
  while (active?.shadowRoot?.activeElement) {
    active = active.shadowRoot.activeElement;
  }
  return active instanceof HTMLInputElement ? active : null;
}

function onKeyDown(event: KeyboardEvent): void {
  if (event.key === 'Escape') hideSuggestions();
}

let activeTheme: 'light' | 'dark' | 'system' = 'system';

/**
 * Whether this frame may offer suggestions on focus.
 *
 * The script runs in subframes now, because login forms are so often iframed
 * (hoyoverse.com hosts its whole login in an `account.hoyoverse.com` frame). That
 * reintroduces an old trick: embed a real login origin in a frame too small or too
 * hidden to read, then bait a click on the suggestion. A frame the user cannot see
 * the panel in does not get one — the popup's explicit Fill still works there,
 * because that click happens in extension UI where the origin is shown.
 *
 * The service worker is what decides *which entries* a frame may see, and it
 * matches on the frame's own URL from Chrome. This is only about the click target.
 */
const MIN_FRAME_WIDTH = 200;
const MIN_FRAME_HEIGHT = 100;

function mayOfferSuggestions(): boolean {
  if (window === window.top) return true;
  return window.innerWidth >= MIN_FRAME_WIDTH && window.innerHeight >= MIN_FRAME_HEIGHT;
}

async function showSuggestions(field: HTMLInputElement): Promise<void> {
  if (!mayOfferSuggestions()) return;
  const requestId = ++suggestRequestId;
  ensureSuggestHost();
  positionSuggest(field);
  renderSuggestLoading();

  let response: SuggestResponse;
  try {
    response = (await chrome.runtime.sendMessage({ type: 'SUGGEST_FOR_PAGE' })) as SuggestResponse;
  } catch {
    // Extension context invalidated (reload) — nothing we can show.
    hideSuggestions();
    return;
  }
  if (requestId !== suggestRequestId || activeField !== field) return;

  if (response?.theme === 'light' || response?.theme === 'dark' || response?.theme === 'system') {
    activeTheme = response.theme;
  }

  if (!response || response.ok === false) {
    renderSuggestMessage('Unavailable', response?.error ?? 'Keyhole could not load suggestions.');
    return;
  }

  if (response.type === 'SUGGESTIONS' && response.locked) {
    renderSuggestMessage('Vault locked', 'Open Keyhole and unlock to autofill.');
    return;
  }

  const entries = Array.isArray(response.entries) ? response.entries : [];
  if (entries.length === 0) {
    renderSuggestMessage('No matches', 'No saved logins for this site.');
    return;
  }
  renderSuggestList(entries);
}

function ensureSuggestHost(): void {
  if (suggestHost?.isConnected && suggestRoot) return;
  suggestHost?.remove();
  suggestHost = document.createElement('div');
  suggestHost.id = 'keyhole-suggest-host';
  suggestHost.setAttribute('data-keyhole', 'suggest');
  // Closed shadow root so page CSS/JS cannot restyle or scrape the menu easily.
  suggestRoot = suggestHost.attachShadow({ mode: 'closed' });
  (document.documentElement || document.body).appendChild(suggestHost);
}

const SUGGEST_WIDTH = 300;
const SUGGEST_GAP = 10;

function positionSuggest(field: HTMLInputElement): void {
  if (!suggestHost) return;
  const host = shadowHost(field);
  const anchor = host instanceof HTMLElement ? host : field;
  const rect = anchor.getBoundingClientRect();

  // Prefer the right of the field; flip left if it would clip.
  let left = Math.round(rect.right + SUGGEST_GAP);
  if (left + SUGGEST_WIDTH > window.innerWidth - SUGGEST_GAP) {
    left = Math.round(rect.left - SUGGEST_WIDTH - SUGGEST_GAP);
  }
  left = Math.max(SUGGEST_GAP, Math.min(left, window.innerWidth - SUGGEST_WIDTH - SUGGEST_GAP));

  const panelHeight = Math.max(suggestHost.getBoundingClientRect().height, 160);
  let top = Math.round(rect.top);
  if (top + panelHeight > window.innerHeight - SUGGEST_GAP) {
    top = Math.max(SUGGEST_GAP, window.innerHeight - panelHeight - SUGGEST_GAP);
  }
  top = Math.max(SUGGEST_GAP, top);

  // `all: initial` alone sets display:inline and width is ignored — force block.
  suggestHost.style.cssText = [
    'all: initial',
    'display: block',
    'position: fixed',
    `top: ${top}px`,
    `left: ${left}px`,
    `width: ${SUGGEST_WIDTH}px`,
    'max-width: calc(100vw - 16px)',
    'z-index: 2147483646',
    'pointer-events: auto',
    'visibility: visible',
    'opacity: 1',
  ].join(';');
}

/** Keyhole vault mark — same geometry as the app Icon `vault`. */
function brandMarkSvg(): string {
  return `<svg class="mark" width="17" height="17" viewBox="0 0 64 64" aria-hidden="true" focusable="false">
    <defs>
      <mask id="kh-suggest-mark">
        <rect width="64" height="64" fill="white"/>
        <circle cx="32" cy="25" r="8" fill="black"/>
        <path d="M28.5 30.5 24 48h16l-4.5-17.5Z" fill="black"/>
      </mask>
    </defs>
    <rect x="4" y="4" width="56" height="56" rx="15" fill="currentColor" mask="url(#kh-suggest-mark)"/>
  </svg>`;
}

function resolvedColorScheme(): 'light' | 'dark' {
  if (activeTheme === 'light') return 'light';
  if (activeTheme === 'dark') return 'dark';
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

function suggestStyles(): string {
  // Explicit light/dark tokens (same hex values as popup.css) — avoid light-dark()
  // here because page color-scheme can make the panel unreadable in a shadow tree.
  return `
    :host { color-scheme: light dark; }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    .panel {
      --bg: #ffffff;
      --surface: #ffffff;
      --surface-2: #eef1f5;
      --border: #d7dee6;
      --text: #0f172a;
      --text-dim: #57646f;
      --accent: #0f62d0;
      --accent-soft: #e7f0fd;
      --accent-text: #ffffff;
      --radius: 9px;
      --shadow: 0 1px 2px rgb(15 23 42 / 8%), 0 8px 24px -6px rgb(15 23 42 / 12%);
      --dur-fast: 120ms;
      --dur-base: 200ms;
      --ease-out: cubic-bezier(0.16, 1, 0.3, 1);

      font: 13px/1.45 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      -webkit-font-smoothing: antialiased;
      color: var(--text);
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      box-shadow: var(--shadow);
      overflow: hidden;
      animation: panel-in var(--dur-base) var(--ease-out) both;
    }
    .panel[data-theme="dark"] {
      --bg: #151b23;
      --surface: #151b23;
      --surface-2: #1e262f;
      --border: #2a3341;
      --text: #e6edf3;
      --text-dim: #8b97a6;
      --accent: #4d9fff;
      --accent-soft: #14243a;
      --accent-text: #06101d;
      --shadow: 0 1px 2px rgb(0 0 0 / 50%), 0 8px 24px -6px rgb(0 0 0 / 45%);
    }
    @keyframes panel-in {
      from { opacity: 0; transform: translateX(-6px) scale(0.98); }
      to   { opacity: 1; transform: none; }
    }
    @media (prefers-reduced-motion: reduce) {
      .panel, .popup-item { animation: none !important; }
    }
    .popup-header {
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 10px 12px;
      border-bottom: 1px solid var(--border);
      background: var(--bg);
    }
    .popup-brand {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      font-weight: 700;
      color: var(--text);
    }
    .mark { color: var(--accent); flex-shrink: 0; display: block; }
    .popup-host {
      font-size: 11px;
      color: var(--text-dim);
      background: var(--surface-2);
      padding: 2px 7px;
      border-radius: 999px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      max-width: 140px;
    }
    .popup-section-label {
      margin: 8px 12px 4px;
      font-size: 10px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-dim);
    }
    .popup-list {
      list-style: none;
      margin: 0;
      padding: 0 0 4px;
      max-height: 240px;
      overflow-y: auto;
    }
    .popup-item {
      display: flex;
      align-items: center;
      gap: 8px;
      width: 100%;
      text-align: left;
      border: 0;
      border-bottom: 1px solid var(--border);
      border-radius: 0;
      background: transparent;
      padding: 8px 12px;
      cursor: pointer;
      color: inherit;
      font: inherit;
      animation: row-in var(--dur-base) var(--ease-out) both;
    }
    .popup-item:last-child { border-bottom: 0; }
    .popup-item:nth-child(1) { animation-delay: 0ms; }
    .popup-item:nth-child(2) { animation-delay: 30ms; }
    .popup-item:nth-child(3) { animation-delay: 60ms; }
    .popup-item:nth-child(n + 4) { animation-delay: 90ms; }
    @keyframes row-in {
      from { opacity: 0; transform: translateY(6px); }
      to   { opacity: 1; transform: none; }
    }
    .popup-item:hover, .popup-item:focus-visible {
      background: var(--surface-2);
      outline: none;
    }
    .popup-item:focus-visible {
      box-shadow: inset 0 0 0 2px var(--accent);
    }
    .popup-item-main { flex: 1; min-width: 0; }
    .popup-item-title {
      font-weight: 600;
      display: flex;
      align-items: center;
      gap: 6px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    .popup-item-meta {
      font-size: 11px;
      color: var(--text-dim);
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    .badge {
      font-size: 9px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      background: var(--accent);
      color: var(--accent-text);
      padding: 1px 5px;
      border-radius: 3px;
    }
    .badge.soft {
      background: var(--surface-2);
      color: var(--text-dim);
    }
    .fill-button {
      flex-shrink: 0;
      background: var(--accent);
      border: 1px solid var(--accent);
      color: var(--accent-text);
      font-weight: 600;
      font-size: 12px;
      padding: 5px 12px;
      border-radius: var(--radius);
      pointer-events: none;
    }
    .popup-item:hover .fill-button {
      filter: brightness(1.1);
    }
    .popup-center {
      padding: 20px 16px;
      text-align: center;
      color: var(--text-dim);
      font-size: 12px;
      line-height: 1.5;
    }
    .popup-center strong {
      display: block;
      color: var(--text);
      font-size: 13px;
      font-weight: 600;
      margin-bottom: 4px;
    }
  `;
}

function pageHostLabel(): string {
  try {
    return location.hostname.replace(/^www\./, '');
  } catch {
    return '';
  }
}

function renderPanelShell(bodyHtml: string): void {
  if (!suggestRoot) return;
  const scheme = resolvedColorScheme();
  const hostLabel = pageHostLabel();
  suggestRoot.innerHTML = `<style>${suggestStyles()}</style>
    <div class="panel" data-theme="${scheme}" role="dialog" aria-label="Keyhole logins">
      <div class="popup-header">
        <span class="popup-brand">${brandMarkSvg()}Keyhole</span>
        ${hostLabel ? `<span class="popup-host"></span>` : ''}
      </div>
      ${bodyHtml}
    </div>`;
  const hostEl = suggestRoot.querySelector('.popup-host');
  if (hostEl) hostEl.textContent = hostLabel;
  if (activeField) positionSuggest(activeField);
}

function renderSuggestLoading(): void {
  renderPanelShell(`<div class="popup-center">Looking up logins…</div>`);
}

function renderSuggestMessage(message: string, detail?: string): void {
  renderPanelShell(`<div class="popup-center"><strong></strong><span class="detail"></span></div>`);
  const strong = suggestRoot?.querySelector('.popup-center strong');
  if (strong) strong.textContent = message;
  const detailNode = suggestRoot?.querySelector('.popup-center .detail');
  if (detailNode) detailNode.textContent = detail ?? '';
}

function renderSuggestList(entries: SuggestEntry[]): void {
  renderPanelShell(`
    <div class="popup-section-label">Matches for this site</div>
    <div class="popup-list" role="listbox" aria-label="Matching logins"></div>
  `);
  const list = suggestRoot?.querySelector('.popup-list');
  if (!list) return;

  for (const entry of entries.slice(0, 8)) {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'popup-item';
    button.setAttribute('role', 'option');

    const main = document.createElement('div');
    main.className = 'popup-item-main';

    const title = document.createElement('div');
    title.className = 'popup-item-title';
    title.appendChild(document.createTextNode(entry.title || entry.host || 'Login'));
    // `domain` matches were saved on another host of the same site, so label them
    // instead of letting them pass as a login for this exact page.
    if (entry.matchStrength === 'exact' || entry.matchStrength === 'domain') {
      const badge = document.createElement('span');
      badge.className = entry.matchStrength === 'exact' ? 'badge' : 'badge soft';
      badge.textContent = entry.matchStrength === 'exact' ? 'exact' : 'similar';
      title.appendChild(badge);
    }

    const meta = document.createElement('div');
    meta.className = 'popup-item-meta';
    const bits = [entry.username || 'No username'];
    if (entry.host) bits.push(entry.host);
    meta.textContent = bits.join(' · ');

    main.appendChild(title);
    main.appendChild(meta);

    const fill = document.createElement('span');
    fill.className = 'fill-button';
    fill.textContent = 'Fill';

    button.appendChild(main);
    button.appendChild(fill);
    button.addEventListener('mousedown', (event) => {
      event.preventDefault();
    });
    button.addEventListener('click', () => {
      void fillFromSuggestion(entry.id);
    });
    list.appendChild(button);
  }
  if (activeField) positionSuggest(activeField);
}

async function fillFromSuggestion(entryId: string): Promise<void> {
  hideSuggestions();
  try {
    await chrome.runtime.sendMessage({ type: 'FILL_FROM_PAGE', entryId });
  } catch {
    // Ignore — the service worker may be asleep or the vault locked.
  }
}

function hideSuggestions(): void {
  suggestRequestId += 1;
  activeField = null;
  if (suggestHost) {
    suggestHost.remove();
    suggestHost = null;
    suggestRoot = null;
  }
}

// ---------------------------------------------------------------------------
// Offer to save / update after login submit
// ---------------------------------------------------------------------------

let pendingSave: PendingSave | null = null;
let saveOfferHost: HTMLElement | null = null;
let saveOfferRoot: ShadowRoot | null = null;
let lastOfferKey = '';

function onFormSubmit(event: Event): void {
  const target = event.target;
  if (!(target instanceof Element)) return;
  const form = target.closest('form') ?? (target.tagName.toLowerCase() === 'faceplate-form' ? target : null);
  if (!form) return;

  const passwordField = findPasswordField(form);
  if (!passwordField) return;

  // Skip signup / change-password flows that advertise new-password.
  const ac = autocompleteOf(passwordField);
  if (ac.includes('new-password')) return;

  const usernameField = findUsernameField(form, passwordField);
  const password = passwordField.value;
  if (password.length === 0) return;

  const username = usernameField?.value ?? '';
  let host = '';
  try {
    host = new URL(window.location.href).hostname.replace(/^www\./, '');
  } catch {
    host = window.location.hostname;
  }

  pendingSave = { username, password, host };
  // Defer so the page can finish submit handling / navigation start.
  window.setTimeout(() => void maybeOfferSave(), 400);
}

async function maybeOfferSave(): Promise<void> {
  const pending = pendingSave;
  if (!pending) return;
  // Same reasoning as the suggestion panel: no UI in a frame it cannot be read in.
  if (!mayOfferSuggestions()) return;

  const offerKey = `${pending.host}|${pending.username}|${pending.password.length}`;
  if (offerKey === lastOfferKey && saveOfferHost) return;

  let response: SuggestResponse;
  try {
    response = (await chrome.runtime.sendMessage({ type: 'SUGGEST_FOR_PAGE' })) as SuggestResponse;
  } catch {
    return;
  }

  if (response?.theme === 'light' || response?.theme === 'dark' || response?.theme === 'system') {
    activeTheme = response.theme;
  }

  if (!response || response.ok === false) return;

  if (response.locked) {
    showSaveOffer({
      mode: 'locked',
      host: pending.host,
      username: pending.username,
    });
    lastOfferKey = offerKey;
    return;
  }

  // Suggestions include same-site (`domain`) matches saved on *other* hosts. Those
  // may be offered for filling, but never as the target of an update: overwriting
  // a sibling host's password because the usernames happen to agree is quiet data
  // loss. Same-site logins get a new entry for this host instead.
  const entries = (response.entries ?? []).filter((e) => e.matchStrength !== 'domain');
  const exact = entries.find(
    (e) => e.username === pending.username && pending.username.length > 0,
  );
  const anyMatch = exact ?? entries[0];

  // If we already have this exact credential, stay quiet.
  // (Password equality is checked only after the user picks Update — we cannot
  // compare without revealing; instead skip when username matches and we just
  // filled from Keyhole? Simpler: always offer update when username matches.)
  if (anyMatch && exact) {
    showSaveOffer({
      mode: 'update',
      host: pending.host,
      username: pending.username,
      entryId: exact.id,
      title: exact.title,
    });
  } else if (anyMatch && pending.username.length === 0) {
    showSaveOffer({
      mode: 'update',
      host: pending.host,
      username: pending.username,
      entryId: anyMatch.id,
      title: anyMatch.title,
    });
  } else {
    showSaveOffer({
      mode: 'create',
      host: pending.host,
      username: pending.username,
    });
  }
  lastOfferKey = offerKey;
}

function showSaveOffer(opts: {
  mode: 'create' | 'update' | 'locked';
  host: string;
  username: string;
  entryId?: string;
  title?: string;
}): void {
  hideSaveOffer();
  const host = document.createElement('div');
  host.id = 'keyhole-save-offer';
  host.style.cssText =
    'all:initial;position:fixed;z-index:2147483646;bottom:16px;right:16px;width:min(360px,calc(100vw - 32px));font-family:system-ui,sans-serif;';
  const root = host.attachShadow({ mode: 'closed' });
  document.documentElement.appendChild(host);
  saveOfferHost = host;
  saveOfferRoot = root;

  const style = document.createElement('style');
  style.textContent = `
    :host { color-scheme: light dark; }
    .card {
      background: ${activeTheme === 'dark' ? '#1a1d23' : '#fff'};
      color: ${activeTheme === 'dark' ? '#e8eaed' : '#1a1d23'};
      border: 1px solid ${activeTheme === 'dark' ? '#333842' : '#d0d5dd'};
      border-radius: 12px;
      box-shadow: 0 8px 28px rgba(0,0,0,.18);
      padding: 14px 16px;
      font: 13px/1.4 system-ui, -apple-system, sans-serif;
    }
    .title { font-weight: 600; margin: 0 0 4px; font-size: 14px; }
    .meta { margin: 0 0 12px; opacity: .75; word-break: break-all; }
    .row { display: flex; gap: 8px; flex-wrap: wrap; justify-content: flex-end; }
    button {
      font: inherit; cursor: pointer; border-radius: 8px; border: 1px solid transparent;
      padding: 7px 12px;
    }
    .ghost {
      background: transparent;
      border-color: ${activeTheme === 'dark' ? '#333842' : '#d0d5dd'};
      color: inherit;
    }
    .primary {
      background: #0f62d0; color: #fff; border-color: #0f62d0;
    }
  `;
  root.appendChild(style);

  const card = document.createElement('div');
  card.className = 'card';
  const title = document.createElement('p');
  title.className = 'title';
  const meta = document.createElement('p');
  meta.className = 'meta';

  if (opts.mode === 'locked') {
    title.textContent = 'Unlock Keyhole to save';
    meta.textContent = `Login on ${opts.host}` + (opts.username ? ` · ${opts.username}` : '');
  } else if (opts.mode === 'update') {
    title.textContent = 'Update saved password?';
    meta.textContent = `${opts.title ?? opts.host}` + (opts.username ? ` · ${opts.username}` : '');
  } else {
    title.textContent = 'Save login in Keyhole?';
    meta.textContent = `${opts.host}` + (opts.username ? ` · ${opts.username}` : '');
  }

  const row = document.createElement('div');
  row.className = 'row';

  const dismiss = document.createElement('button');
  dismiss.type = 'button';
  dismiss.className = 'ghost';
  dismiss.textContent = 'Not now';
  dismiss.addEventListener('click', () => {
    pendingSave = null;
    hideSaveOffer();
  });
  row.appendChild(dismiss);

  if (opts.mode !== 'locked') {
    const confirm = document.createElement('button');
    confirm.type = 'button';
    confirm.className = 'primary';
    confirm.textContent = opts.mode === 'update' ? 'Update' : 'Save';
    confirm.addEventListener('click', () => {
      void confirmSave(opts.entryId);
    });
    row.appendChild(confirm);
  }

  card.appendChild(title);
  card.appendChild(meta);
  card.appendChild(row);
  root.appendChild(card);
}

async function confirmSave(entryId?: string): Promise<void> {
  const pending = pendingSave;
  if (!pending) {
    hideSaveOffer();
    return;
  }
  try {
    const response = (await chrome.runtime.sendMessage({
      type: 'SAVE_FROM_PAGE',
      username: pending.username,
      password: pending.password,
      ...(entryId ? { entryId } : {}),
    })) as { ok?: boolean; error?: string };
    if (response?.ok === false) {
      // Keep the offer so the user can retry after unlocking.
      const title = saveOfferRoot?.querySelector('.title');
      if (title) title.textContent = response.error ?? 'Could not save.';
      return;
    }
  } catch {
    // Ignore.
  }
  pendingSave = null;
  hideSaveOffer();
}

function hideSaveOffer(): void {
  if (saveOfferHost) {
    saveOfferHost.remove();
    saveOfferHost = null;
    saveOfferRoot = null;
  }
}

