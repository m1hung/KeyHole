# 🔑 Keyhole

A local-first, zero-knowledge password manager. Runs as a **native desktop app** (a portable Windows `.exe`) and as a **Chrome extension (Manifest V3)** — both sharing one audited crypto core.

They are for different jobs. The extension lives in the browser, where autofill has to happen. The desktop app is the vault you sit down with — its own window, its own icon, no browser involved, and a vault that is a real file you can back up.

No accounts. No telemetry. Your vault is a single encrypted file that never leaves your device unless you opt in to a **self-hosted sync server** ([`server/README.md`](server/README.md)) — which every surface, desktop included, can talk to. (Local app ↔ extension live sync via a shared vault file is [designed](docs/SYNC.md); manual export/import works today.)

```
core/        framework-agnostic crypto + vault (no I/O, 175 tests)
app/         the UI (Vite + React + TypeScript) — shipped by desktop/, shared with extension/
desktop/     Electron shell → portable Windows .exe, vault as a real file
extension/   Chrome MV3 extension (popup, service worker, autofill)
server/      optional self-hosted sync server
server-tray/ that server as a one-click tray app (portable .exe, no Node needed)
examples/    demo vault with a published master password
docs/        design notes (e.g. local live sync)
```

`app/` is not a product of its own — it is the renderer. `desktop/` does not fork it, it packages exactly that build and adds a main process, a preload bridge and Windows packaging; `extension/` imports its sync client, icons and stylesheet directly. Keyhole is not served to browsers or installable as a web app.

---

## Quick start

Requires Node 22+ (developed and tested on Node 24.18.0).

```sh
npm install
npm test                    # 226 tests across core + extension + server
npm run demo                # end-to-end crypto proof, printed to the terminal
npm run desktop             # build + run the native desktop app
npm run build:desktop       # portable .exe → desktop/dist/Keyhole-1.0.0-portable.exe
npm run dev:app             # renderer dev server with HMR at http://127.0.0.1:5173 (next free port if busy)
npm run server:tray         # sync server as a one-click tray app
npm run build:server-tray   # portable .exe → server-tray/dist/
npm start --workspace @keyhole/server   # or run the sync server headless at http://127.0.0.1:8787
npm run build:extension     # extension/dist, ready to load unpacked
```

`npm run desktop` is how you *use* Keyhole; `npm run dev:app` is how you *work on*
its UI, with HMR and no Electron rebuild in the loop. The dev server is a
development tool, not a way to run Keyhole — it serves the renderer to a browser
tab, where the desktop bridge is absent and the vault falls back to
`localStorage`.

### Try the demo vault

`examples/demo-vault.keyhole.json` contains five fabricated entries on
RFC 2606 reserved domains.

**Master password: `demo-master-passphrase-2026`**

This password is published deliberately — the file exists to be opened. Open the app → *Import an existing vault file*, or the extension's options page → *Import*.

---

## Threat model

Security claims are only meaningful with a stated adversary. Here is ours.

### Defended

| Threat | Defence |
|---|---|
| **Stolen vault file or disk** | Payload is AES-256-GCM encrypted under a key derived by Argon2id (64 MiB, t=3). An offline attacker must brute-force the master password at ~100 ms + 64 MiB per guess. |
| **Malware reading `chrome.storage.local` / `localStorage`** | Only ciphertext and a public header are stored. No key material is ever persisted, in any form, anywhere. |
| **Tampering with the vault file** | GCM tags authenticate both layers. The header (vault id, format version, KDF cost) is bound as associated data, so a spliced key blob or a downgraded KDF fails to decrypt. |
| **KDF downgrade** | Parameters below 16 MiB / t=2 are rejected before derivation, independently of the AAD binding. |
| **A malicious web page messaging the extension** | Every privileged handler requires `isTrustedExtensionSender`: correct extension id, a `chrome-extension://` sender URL, and no `sender.tab`. Content scripts are explicitly untrusted. `onMessageExternal` rejects everything. |
| **Credential theft via lookalike domains** | Autofill matching parses URLs and compares hosts on label boundaries. `github.com.evil.com` never matches `github.com`. Verified by 9 dedicated tests. |
| **Autofill into a page that navigated mid-flow** | The service worker re-reads the tab URL and re-runs matching immediately before dispatching, and the content script re-checks `location.origin` on arrival. |
| **XSS on a site reading a filled password** | Keyhole never pre-fills. A credential enters the DOM only after an explicit click in extension UI, and only that one credential. |
| **Shoulder-surfing / stale sessions** | Idle auto-lock, lock on browser restart, optional lock-on-hide, clipboard auto-clear. |
| **Casual snooping of an idle screen** | Hidden secrets are rendered as bullets — the real value is not in the DOM until revealed. |

### NOT defended — be honest about this

- **Keyloggers.** Anything capturing keystrokes gets the master password. Nothing in a browser can prevent this.
- **A compromised OS, or malware with process-memory access.** While unlocked, the vault key and decrypted entries are in memory by necessity.
- **Malicious extensions with broad host permissions.** Another extension with `<all_urls>` can read what Keyhole fills into a page.
- **Evil-maid attacks with a runtime memory dump.**
- **A backdoored browser or a hostile WebCrypto implementation.**
- **Forgotten master passwords.** There is no recovery, no backdoor, no reset. That is the point.
- **Rubber-hose cryptanalysis.** Obviously.

`zeroize()` scrubs the buffers we hold, but JavaScript cannot guarantee erasure — the engine may have copied a value during GC, string interning, or inside WASM linear memory. It narrows the window; it does not close it.

---

## Cryptographic design

### Key hierarchy

```
master password
      │
      ├── Argon2id(salt, m=64 MiB, t=3, p=1) ──▶ Master Key (256-bit)
      │                                                │
      │                                                │ AES-256-GCM wrap
      │                                                ▼
      │                              Vault Encryption Key (256-bit, random)
      │                                                │
      │                                                │ AES-256-GCM
      │                                                ▼
      │                                     VaultData JSON payload
```

Two layers rather than one because: unlock costs one KDF run plus a 60-byte unwrap instead of decrypting the whole payload; the wrapped key's GCM tag *is* the password verifier; and re-keying is structurally separable from re-encrypting.

### Parameters

| | Value | Rationale |
|---|---|---|
| KDF | Argon2id | Memory-hard, side-channel resistant hybrid. RFC 9106. |
| Memory | 64 MiB (`hardened`: 256 MiB) | 3.4× the OWASP 2024 floor of 19 MiB. |
| Iterations | 3 (`hardened`: 4) | ~105 ms on an M-series Mac. |
| Parallelism | 1 | hash-wasm runs single-threaded in-browser; more lanes would change the digest without buying concurrency. |
| Salt | 128-bit, random per vault | Stored in the clear. Salts are not secret. |
| Derived key | 256-bit | Feeds AES-256. |
| Cipher | AES-256-GCM (WebCrypto) | Authenticated. Platform-audited, constant-time, hardware-accelerated. |
| Nonce | 96-bit, random, fresh per encryption | Never reused; a new IV is generated on every save. |
| Auth tag | 128-bit | Full length. |

### What is stored, and where

The envelope (`VaultFile`) contains **only**:

```jsonc
{
  "format": "keyhole.vault",
  "formatVersion": 1,
  "vaultId": "<uuid>",              // public
  "createdAt": "...", "updatedAt": "...",
  "kdf": { "algorithm": "argon2id", "memoryKiB": 65536, "iterations": 3,
           "parallelism": 1, "saltB64": "...", "keyLength": 32 },
  "wrappedKey": { "ivB64": "...", "ctB64": "..." },  // VEK under the master key
  "payload":    { "ivB64": "...", "ctB64": "..." }   // entries under the VEK
}
```

Titles, usernames, passwords, URLs, notes, tags and TOTP secrets are all inside `payload`. Nothing is stored outside it except the public header above.

| Where | Contents |
|---|---|
| `%APPDATA%\Keyhole\keyhole-vault.keyhole.json` (desktop) | The encrypted envelope, written atomically (temp file + rename), with one `.bak` generation. Never stored beside the `.exe`. |
| `localStorage["keyhole.vault.v1"]` (renderer in a browser tab) | The encrypted envelope. Only reached when the desktop bridge is absent, i.e. `npm run dev:app`. |
| `chrome.storage.local["keyhole.vault.v1"]` | The encrypted envelope. 10 MB quota ≈ 40,000 entries; writes above 9 MB are refused with a clear error. |
| `chrome.storage.local["keyhole.local.v1"]` | Non-secret preferences (auto-lock minutes, theme). |
| IndexedDB `keyhole-handles` (app) | A `FileSystemFileHandle`, if you linked the vault to a file on disk. Not secret. |
| Memory, while unlocked | Non-extractable `CryptoKey` + decrypted entries. Never persisted. |

### Associated data binding

`wrappedKey` is authenticated against `vaultId | formatVersion | full KDF params`; `payload` against `vaultId | formatVersion`. So a key blob cannot be spliced between vaults, and stored KDF cost cannot be edited, without decryption failing. The payload deliberately excludes KDF params so re-wrapping stays possible without re-encrypting.

Serialisation is a fixed-order template string, not `JSON.stringify` — object key order is not a stable contract, and a reordering would silently make existing vaults unreadable.

### Why `hash-wasm` (the one crypto dependency)

WebCrypto ships no memory-hard KDF — only PBKDF2, which is GPU-friendly and the wrong tool here. So Argon2id must come from somewhere.

- **Pinned** at `4.12.0`, no transitive dependencies.
- **Inlines its WASM as base64**, so there is no separate `.wasm` fetch. This matters under MV3, where remote code is forbidden.
- **13.6× faster than pure JS** — 105 ms vs 1428 ms at production parameters.
- **Cross-verified**: `core/test/crypto.test.ts` asserts byte-identical output against `@noble/hashes` (an independent pure-JS implementation) on every test run. If the two ever diverge, CI fails.

Everything else — AES-GCM, HMAC for TOTP, all randomness — uses the platform's WebCrypto. `Math.random()` appears nowhere in this codebase.

---

## Autofill: the security-critical path

Keyhole requests **no host permissions**. Not `<all_urls>`, not a domain list. It uses `activeTab` + `scripting`, so it can only touch a page after you explicitly open the popup on it, and the content script is injected on demand rather than declared in the manifest. On every other page, Keyhole is not present at all.

```
1. You click the toolbar icon                 ← user gesture; grants activeTab
2. Popup asks the service worker for entries matching this tab
      → the SW does the matching; the page is never consulted
      → response carries metadata only (title, username, host) — no passwords
3. You click "Fill" on one specific entry     ← explicit, per-credential consent
4. Service worker:
      a. verifies the sender is our popup (not a content script, not another extension)
      b. RE-READS the tab URL and RE-RUNS matching   ← TOCTOU guard
      c. injects content.js via chrome.scripting
      d. sends exactly one credential
5. Content script re-checks location.origin, fills two fields, forgets the value
```

The content script is **4.98 KB and imports nothing** — not zod, not the core. It runs in the page's process, so every kilobyte there is attack surface. It cannot read page passwords, cannot request anything from the service worker, and holds no vault data. The build fails if it exceeds 25 KB or acquires an `import`.

---

## Running the desktop app

```sh
npm run desktop         # build the renderer and launch it in Electron
npm run build:desktop   # → desktop/dist/Keyhole-1.0.0-portable.exe (~78 MB)
```

The portable `.exe` needs no installer and no admin rights — copy it anywhere and run it. Your vault is a real file at `%APPDATA%\Keyhole\keyhole-vault.keyhole.json`, written atomically with one `.bak` generation, and it is deliberately **not** stored beside the executable: moving or deleting the `.exe` never touches your passwords.

The renderer runs on a registered secure `app://` origin with `contextIsolation` on, `nodeIntegration` off and `sandbox` on. The preload bridge exposes seven IPC verbs and nothing else, and no plaintext ever crosses it — encryption happens entirely in the renderer, so the main process only ever sees the sealed envelope. Sync to a self-hosted server works exactly as it does in the browser.

The build is unsigned, so SmartScreen warns on first run — the executable does carry Keyhole's own icon and version metadata, but only a purchased code-signing certificate silences the warning. [`desktop/README.md`](desktop/README.md) has the detail.

**Coming from the browser build?** They are different origins with separate stores, so the desktop app cannot see a browser vault. On first run it detects that case and offers to copy it across, reading — never deleting — the browser copy.

## Running the sync server, one click

```sh
npm run build:server-tray   # → server-tray/dist/Keyhole-Sync-Server-1.0.0-portable.exe
```

Double-click it: a tray icon appears and the server is running at `http://127.0.0.1:8787`. No console window, no command line, and no Node installation — the server runs on the Node that Electron bundles. The tray menu offers the status page, Start/Stop/Restart, and the data folder.

It binds **loopback only** and pins its database to `%APPDATA%\Keyhole Sync Server\data\`, both overriding the server's own defaults (`0.0.0.0`, and a path relative to the working directory). A service you launch by double-clicking should not publish itself to every network you join, and should not create a fresh empty database depending on which folder Explorer was in.

To sync from another device on the same trusted network, tick **Allow access from other devices** in the tray menu — off by default, confirmed once, remembered. To sync across networks, don't: put both machines on a WireGuard mesh instead and let `tailscale serve` front the server with a real certificate while it stays on loopback. Either way a remote client wants TLS, since the sync credential travels in a header. [`server-tray/README.md`](server-tray/README.md) covers both, and `server/docker-compose.yml` ships a Caddy profile for the public-domain case.

For a headless deployment, run `server/` directly as before — that path is unchanged.

## Working on the UI

```sh
npm run dev:app     # renderer with HMR at http://127.0.0.1:5173
```

This is a development tool, not a way to run Keyhole. There is no installable web build and nothing is served to browsers as a product: the renderer in a tab has no desktop bridge, so it falls back to `localStorage` and the *App* section of Settings — which reports where the vault file is — does not appear.

The dev server binds `127.0.0.1` only, on 5173 or the next free port; set `PORT` to pin it. `127.0.0.1` is a secure context, which is what WebCrypto requires, so no certificate is needed locally.

**First run:** choose *Create vault* (minimum 12 characters, with an explicit no-recovery acknowledgement) or *Import an existing vault file*.

Features: login and secure-note entries, fast search over title/username/URL/tags (and note bodies for secure notes — never over passwords or login notes), password generator with strength meter, TOTP codes, export/import, change master password, configurable auto-lock and clipboard clear, light/dark/system theme, local-storage status, and optional File System Access API linking so edits save straight to a real file on disk.

### What installing does and does not change

Installing is a window, not a data migration. The vault stays exactly where it was — the same encrypted envelope under the same origin's `localStorage` — so an installed Keyhole and the same URL in a tab are one app looking at one vault, not two copies drifting apart.

| | Behaviour |
|---|---|
| **Offline** | The app shell (HTML, JS, CSS, icons) is precached at install by `app/src/service-worker.js`, so a cold launch needs no server. Argon2id is WASM inlined into the bundle, so unlocking works offline too. |
| **Caching policy** | Precache only. The worker caches exactly the files a build produced, from a list fixed at build time, and performs no runtime caching ever. |
| **The sync server** | A different origin, so its requests are not cached — they are never intercepted at all. Opting in to sync is unaffected by installation, in either direction. |
| **The vault** | Untouched. Service workers cannot read `localStorage`, so the worker has no path to vault data even in principle. |
| **Updates** | A new build installs in the background and waits. It applies when every Keyhole window is closed, or immediately via *Settings → App → Update and restart* — which reloads, and therefore locks the vault. Nothing auto-reloads, because a silent reload would drop an unlocked session mid-edit. |

Regenerate the app icons from the brand mark with `npm run icons -w @keyhole/app`.

## Loading the Chrome extension

```sh
npm run build:extension
```

1. Open `chrome://extensions`
2. Enable **Developer mode** (top right)
3. **Load unpacked** → select `extension/dist`
4. Pin Keyhole to the toolbar
5. Click the icon, or press <kbd>Cmd/Ctrl</kbd>+<kbd>Shift</kbd>+<kbd>L</kbd>

First run: the popup offers *Set up Keyhole*, which opens the options page to create a vault or import one exported from the app. Both use the identical file format.

### MV3 notes

- **`'wasm-unsafe-eval'` in the CSP is required**, not optional — MV3 blocks WebAssembly compilation without it, and Argon2id is WASM. The rest of the CSP pins `script-src` to `'self'`; there is no `unsafe-eval`, no remote code, no `eval()`.
- **Service worker eviction locks the vault.** Chrome terminates idle service workers, which discards the in-memory session. An alarm-driven heartbeat keeps the worker warm while unlocked, but Chrome may still evict under memory pressure. This is fail-closed: you get the unlock screen, never a stale "unlocked" state.
- **Clipboard auto-clear is best-effort in the popup.** The popup usually closes before the timer fires. The desktop app, which stays open, clears reliably. Neither can reach OS-level clipboard history or Handoff.

---

## Manual security test checklist

Verified in a real browser during development; re-run after any change to crypto, storage, or messaging.

### Crypto & storage
- [ ] Create a vault, add an entry, then inspect `localStorage` / `chrome.storage.local` — no title, username, password, URL or note appears in plaintext. *(Automated: `vault.test.ts` "never writes plaintext into the envelope")*
- [ ] Wrong master password → "Wrong master password", stays locked, no partial data rendered.
- [ ] Corrupt one character of `payload.ctB64` → refuses to unlock.
- [ ] Edit `kdf.memoryKiB` down to `1024` → refuses to unlock.
- [ ] Copy `wrappedKey` from another vault into this one → refuses to unlock.
- [ ] Change the master password → old password rejected, all entries intact, salt/wrappedKey/payload all changed.
- [ ] Export → delete vault → import → unlocks with the same password, entries intact.
- [ ] Two saves in a row produce different `payload.ivB64`.

### Sync server tray app
- [ ] Double-click the `.exe` → tray icon appears, no console window, `http://127.0.0.1:8787` responds.
- [ ] `netstat -ano | findstr :8787` shows `127.0.0.1:8787`, **not** `0.0.0.0:8787`.
- [ ] From another machine on the same network, the address is unreachable.
- [ ] *Allow access from other devices* → Cancel → the checkbox stays unticked and the binding is unchanged.
- [ ] *Allow access from other devices* → confirm → `netstat` now shows `0.0.0.0:8787`, the tray shows the LAN URL, and *Copy server URL* copies it.
- [ ] Quit and relaunch → the tick survived; untick it → back to `127.0.0.1:8787` after the restart.
- [ ] Delete `%APPDATA%\Keyhole Sync Server\settings.json`, or corrupt it → starts loopback-only rather than exposed.
- [ ] Database lands in `%APPDATA%\Keyhole Sync Server\data\`, not next to the `.exe` or in the launch folder.
- [ ] Launch it from two different folders → the same database, same accounts, both times.
- [ ] Start it while port 8787 is already taken → the tray reports the error rather than vanishing.
- [ ] Quit from the tray, then check port 8787 → released, no orphaned process.
- [ ] Kill the tray from Task Manager → the server child dies with it. *(Verified: Electron's job object)*
- [ ] Launch a second copy → it exits instead of fighting over the port and the SQLite file.

### Desktop app
- [ ] `npm run build:desktop`, run the `.exe` → window opens, no browser chrome, no menu bar.
- [ ] DevTools console: `window.require` and `window.process` are both `undefined`; `isSecureContext` is `true`.
- [ ] `window.keyhole.vault` exposes exactly seven verbs and nothing else.
- [ ] Create a vault → `%APPDATA%\Keyhole\keyhole-vault.keyhole.json` appears; open it — ciphertext and public header only.
- [ ] Edit an entry → the file's `payload.ivB64` changes and a `.bak` holds the previous version; no `.tmp` is left behind.
- [ ] Close and relaunch → the unlock screen appears immediately, never a create-vault flash.
- [ ] Launch a second instance → it focuses the existing window instead of opening a second one.
- [ ] With a vault in the browser build and none on disk, first run offers to copy it across; declining leaves the browser copy intact.
- [ ] *Settings → App* shows the real vault path; *Show in Explorer* opens it.
- [ ] Copy a generated password → it lands on the clipboard, with no "denied clipboard access" error. *(Chromium gates `writeText` behind `clipboard-sanitized-write`; a blanket permission denial in the main process breaks every Copy button.)*
- [ ] Wait past the clear timer → the clipboard is emptied. *(Needs `clipboard-read`: without it the timer cannot tell whether the clipboard still holds Keyhole's value, and clears whatever is there.)*
- [ ] DevTools console: `navigator.permissions.query({name:'geolocation'})` still reports `denied`.
- [ ] Configure sync against a local server → *Register & upload* succeeds; the server row holds only the encrypted envelope.
- [ ] Move the `.exe` to another folder and run it → same vault, because the vault is not stored beside it.

### Renderer dev server
- [ ] `npm run dev:app` → DevTools → Application shows no service worker, no Cache Storage, and no web manifest.
- [ ] *Settings* has no *App* section in a browser tab, and no install offer anywhere in the UI.
- [ ] `npm run build --workspace @keyhole/app` → `dist/` contains no `sw.js` and no `manifest.webmanifest`.
- [ ] With sync configured, click *Sync now* → the request appears in the network log as a real request.

### Locking
- [ ] Set auto-lock to 1 minute, idle → locks; countdown appears under 60s.
- [ ] Reload the page while unlocked → locked.
- [ ] Enable lock-on-hide, switch tabs → locked.
- [ ] Restart Chrome → extension is locked.
- [ ] Copy a password, wait past the clear timer → clipboard no longer holds it.

### Extension messaging
- [ ] From a page console: `chrome.runtime.sendMessage('<ext-id>', {type:'EXPORT_VAULT'})` → rejected. *(Automated: 10 sender-validation tests)*
- [ ] `chrome://extensions` → service worker → Console shows no logged secrets.
- [ ] `chrome://extensions` shows no host-permission warning at install.

### Autofill
- [ ] Save an entry for `github.com`; open a lookalike such as `github.com.evil.example` → popup shows no match. *(Automated: 9 lookalike tests)*
- [ ] Click Fill, then navigate the tab before the fill completes → refused with a host-mismatch message.
- [ ] Fill into a React-based login form → the app registers the value (not just the DOM).
- [ ] Before clicking Fill, confirm no password is present in the page DOM.
- [ ] Try to fill on `chrome://extensions` → clean error, no crash.

---

## Development

```sh
npm test                                   # core + extension
npm run typecheck                          # tsc --noEmit, all workspaces
npm run demo                               # end-to-end crypto proof
npm run demo:vault --workspace @keyhole/core   # regenerate examples/
```

TypeScript strict mode throughout, plus `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`, `noImplicitReturns` and `noUnusedLocals`.

### About `npm audit`

`npm install` reports **16 high-severity advisories. All of them are dev-only, and none reach the shipped product.**

```sh
npm audit --omit=dev     # → found 0 vulnerabilities
```

Every one traces to a single direct dependency, `electron-builder`, and to a single advisory: [GHSA-mh99-v99m-4gvg](https://github.com/advisories/GHSA-mh99-v99m-4gvg), a denial-of-service in `brace-expansion`. The 16 "packages" are just the chain — `glob` → `minimatch` → `brace-expansion`, repeated through several parents.

**Why it is not fixed:** the advisory's vulnerable range is `<=5.0.7`. The only patched release, `5.0.8`, changed its CommonJS export from a callable function to an object (`{ expand, … }`). Every consumer here reaches it through `minimatch`, which does `const expand = require('brace-expansion')` and calls it. Forcing the override is verifiable breakage:

```
TypeError: expand is not a function
```

So there is no upgrade path until `minimatch` adopts `brace-expansion@5`. `npm audit fix --force` "solves" it by downgrading `electron-builder` to 25.x, which reintroduces a **critical** `tar` path-traversal advisory — strictly worse. Don't take that advice.

**Why it does not matter for the artifact:** `electron-builder` is a build-time tool, and `@keyhole/desktop` has no runtime dependencies whatsoever. The packaged `app.asar` is 20 entries — the renderer bundle, `main.js`, `preload.cjs`, `package.json` — and contains no `node_modules`. Verify it yourself:

```sh
npx @electron/asar list desktop/dist/win-unpacked/resources/app.asar | grep node_modules   # → no matches
```

The residual risk is a hostile *input* to your own build machine (a crafted glob pattern during packaging), not something an attacker can reach in a user's installed Keyhole.

This is deliberately **not** silenced with an `audit-level` setting in `.npmrc`. A password manager that teaches its maintainers to ignore audit output is worse off than one with a known, understood, documented finding — the next advisory might be the one that matters.

The extension build validates its own output: manifest correctness, no `<all_urls>`, CSP pins `script-src 'self'`, `wasm-unsafe-eval` present, no bare `unsafe-eval`, every referenced file exists, and the content script is ESM-free and under 25 KB.

### Explicitly out of scope for v1

Cloud sync to third-party servers, accounts on someone else's infrastructure, vault sharing, biometrics, analytics, and any form of phone-home telemetry. Networking is limited to an **optional self-hosted sync server** you run (`server/`); by default no surface makes network calls, and running the desktop `.exe` adds none — it ships with no update channel at all. Keyhole is also not distributed as a web app: there is no hosted copy, no installable build and no service worker. Local live sync between the app and extension (shared vault file) is described in [docs/SYNC.md](docs/SYNC.md).

Also out of scope for the desktop build specifically: code signing, an auto-updater, macOS and Linux packaging, and OS-keychain integration.

### The desktop build, and what it costs

Earlier versions of this document ruled out an Electron/Tauri wrapper. That is no longer true — `desktop/` ships a portable Windows `.exe` — so here is an honest accounting of what that decision buys and what it costs.

**Electron was chosen over Tauri** because it bundles Chromium: WebCrypto, the Argon2id WASM module and the File System Access API all behave exactly as they do in the browser the crypto was audited against. Tauri's WebView2 does not expose the File System Access API, which would have meant rewriting the vault-file linking against a different set of primitives — new code on the path that touches your vault, to save disk space.

**What it costs, plainly:**

- **You own the Chromium patch cadence.** A browser updates itself; a bundled Chromium does not. An old Keyhole `.exe` is an old Chromium, with whatever is known about it. Rebuild against current Electron periodically — this is the single biggest ongoing security cost of shipping a binary.
- **~86 MB, versus a few hundred KB of renderer bundle.**
- **No code signing.** The build is unsigned, so SmartScreen warns on first run. See [`desktop/README.md`](desktop/README.md) for why.
- **A build toolchain with open advisories.** `electron-builder` carries a set of high-severity transitive advisories with no upstream fix available. None of it ships — the packaged `app.asar` contains no `node_modules` at all — but `npm audit` will report them, and that is worth understanding rather than muting. See below.
- **No auto-update channel.** Deliberate — an auto-updater is a remote-code path into a password manager. Updating means replacing the `.exe` yourself.

**What it does not cost:** a second copy of the vault. The desktop app keeps exactly one vault, in `%APPDATA%\Keyhole`, and the browser build keeps its own. They are separate stores by construction (different origins), which is why the desktop app offers to import a browser vault on first run rather than pretending it found nothing.

---

## License

MIT. See [ARCHITECTURE.md](ARCHITECTURE.md) for data-flow diagrams.
