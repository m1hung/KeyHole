# 🔑 Keyhole

A local-first, zero-knowledge password manager across surfaces that share one
vault format (desktop/extension via `@keyhole/core`; iOS via a Swift port):

| Surface | What it is | Why it exists |
|---|---|---|
| **Desktop app** | A portable Windows `.exe` — its own window, its own icon, no browser. | The vault you sit down with. Your passwords are a real file you can back up. |
| **Chrome extension** | Manifest V3: popup, service worker, on-demand autofill. | Autofill has to happen in the browser. |
| **iOS app** | Native SwiftUI vault client ([`ios/`](ios/README.md)). | Use the same sealed vault on iPhone/iPad (Vault MVP; no AutoFill yet). |

No accounts. No telemetry. No phone-home of any kind. Your vault is a single
encrypted file that never leaves your device — unless you opt in to a sync
server that **you** run ([`server/`](server/README.md)), which stores encrypted
envelopes it cannot read.

**Contents** — [Quick start](#quick-start) · [Threat model](#threat-model) ·
[Cryptographic design](#cryptographic-design) · [Autofill](#autofill-the-security-critical-path) ·
[Desktop app](#the-desktop-app) · [Chrome extension](#the-chrome-extension) ·
[iOS app](ios/README.md) · [Sync server](#the-sync-server) · [Development](#development)

---

## Repository layout

```
core/         framework-agnostic crypto + vault (no I/O, 175 tests)
app/          the UI (Vite + React + TypeScript) — shipped by desktop/, shared with extension/
desktop/      Electron shell → portable Windows .exe, vault as a real file
extension/    Chrome MV3 extension (popup, service worker, autofill)
ios/          SwiftUI iOS vault MVP (KeyholeCore Swift port + KeyholeApp)
server/       optional self-hosted sync server (+ Linux/macOS launcher)
server-tray/  that server as a one-click Windows tray app (portable .exe, no Node needed)
examples/     demo vault with a published master password
docs/         design notes and the manual security checklist
```

`app/` is not a product of its own — it is the renderer. `desktop/` does not
fork it; it packages exactly that build and adds a main process, a preload
bridge and Windows packaging. `extension/` imports its sync client, icons and
stylesheet directly. Keyhole is **not** served to browsers and **not**
installable as a web app.

---

## Quick start

Requires Node 22+ (developed and tested on Node 24.18.0).

```sh
npm install
npm test                    # 245 tests: 175 core + 26 extension + 44 server
npm run demo                # end-to-end crypto proof, printed to the terminal
```

Then pick a surface:

| Command | Result |
|---|---|
| `npm run desktop` | Build the renderer and launch the native app. **This is how you use Keyhole.** |
| `npm run build:desktop` | Portable `.exe` → `desktop/dist/Keyhole-1.0.0-portable.exe` |
| `npm run build:extension` | `extension/dist`, ready to load unpacked |
| `npm run dev:app` | Renderer dev server with HMR at `http://127.0.0.1:5173`. **A development tool, not a way to run Keyhole.** |
| `npm run server:tray` | Sync server as a Windows tray app (local use) |
| `npm run build:server-tray` | Portable `.exe` → `server-tray/dist/` |
| `npm run dev:server` | Sync server on `127.0.0.1:8787` |

Deploying the sync server for real — a Linux host, a domain, HTTPS — is
[`server/DEPLOY.md`](server/DEPLOY.md).

### Try the demo vault

`examples/demo-vault.keyhole.json` holds five fabricated entries on RFC 2606
reserved domains.

> **Master password: `demo-master-passphrase-2026`**

Published deliberately — the file exists to be opened. Open the app →
*Import an existing vault file*, or the extension's options page → *Import*.

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
| **Credential theft via lookalike domains** | Autofill matching parses URLs and compares hosts on label boundaries. `github.com.evil.com` never matches `github.com`. |
| **Autofill into a page that navigated mid-flow** | The service worker re-reads the tab URL and re-runs matching immediately before dispatching, and the content script re-checks `location.origin` on arrival. |
| **XSS on a site reading a filled password** | Keyhole never pre-fills. A credential enters the DOM only after an explicit click in extension UI, and only that one credential. |
| **Shoulder-surfing / stale sessions** | Idle auto-lock, lock on browser restart, optional lock-on-hide, clipboard auto-clear. |
| **Casual snooping of an idle screen** | Hidden secrets render as bullets — the real value is not in the DOM until revealed. |

### Not defended — be honest about this

- **Keyloggers.** Anything capturing keystrokes gets the master password. Nothing in a browser can prevent this.
- **A compromised OS, or malware with process-memory access.** While unlocked, the vault key and decrypted entries are in memory by necessity.
- **Malicious extensions with broad host permissions.** Another extension with `<all_urls>` can read what Keyhole fills into a page.
- **Evil-maid attacks with a runtime memory dump.**
- **A backdoored browser or a hostile WebCrypto implementation.**
- **Forgotten master passwords.** There is no recovery, no backdoor, no reset. That is the point.
- **Rubber-hose cryptanalysis.** Obviously.

`zeroize()` scrubs the buffers we hold, but JavaScript cannot guarantee erasure
— the engine may have copied a value during GC, string interning, or inside
WASM linear memory. It narrows the window; it does not close it.

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

Two layers rather than one because: unlock costs one KDF run plus a 60-byte
unwrap instead of decrypting the whole payload; the wrapped key's GCM tag *is*
the password verifier; and re-keying is structurally separable from
re-encrypting.

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

### What is stored

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

Titles, usernames, passwords, URLs, notes, tags and TOTP secrets all live inside
`payload`. Nothing is stored outside it except the public header above.

| Where | Contents |
|---|---|
| `%APPDATA%\Keyhole\keyhole-vault.keyhole.json` (desktop) | The encrypted envelope, written atomically (temp file + rename), with one `.bak` generation. Never stored beside the `.exe`. |
| `localStorage["keyhole.vault.v1"]` (renderer in a browser tab) | The encrypted envelope. Only reached when the desktop bridge is absent, i.e. `npm run dev:app`. |
| `chrome.storage.local["keyhole.vault.v1"]` | The encrypted envelope. 10 MB quota ≈ 40,000 entries; writes above 9 MB are refused with a clear error. |
| `chrome.storage.local["keyhole.local.v1"]` | Non-secret preferences (auto-lock minutes, theme). |
| IndexedDB `keyhole-handles` | A `FileSystemFileHandle`, if you linked the vault to a file on disk. Not secret. |
| Memory, while unlocked | Non-extractable `CryptoKey` + decrypted entries. Never persisted. |

### Associated data binding

`wrappedKey` is authenticated against `vaultId | formatVersion | full KDF
params`; `payload` against `vaultId | formatVersion`. So a key blob cannot be
spliced between vaults, and stored KDF cost cannot be edited, without decryption
failing. The payload deliberately excludes KDF params so re-wrapping stays
possible without re-encrypting.

Serialisation is a fixed-order template string, not `JSON.stringify` — object
key order is not a stable contract, and a reordering would silently make
existing vaults unreadable.

### Why `hash-wasm` (the one crypto dependency)

WebCrypto ships no memory-hard KDF — only PBKDF2, which is GPU-friendly and the
wrong tool here. So Argon2id must come from somewhere.

- **Pinned** at `4.12.0`, no transitive dependencies.
- **Inlines its WASM as base64**, so there is no separate `.wasm` fetch. This matters under MV3, where remote code is forbidden.
- **13.6× faster than pure JS** — 105 ms vs 1428 ms at production parameters.
- **Cross-verified**: `core/test/crypto.test.ts` asserts byte-identical output against `@noble/hashes` (an independent pure-JS implementation) on every test run. If the two ever diverge, CI fails.

Everything else — AES-GCM, HMAC for TOTP, all randomness — uses the platform's
WebCrypto. `Math.random()` appears nowhere in this codebase.

---

## Autofill: the security-critical path

Keyhole requests **no host permissions**. Not `<all_urls>`, not a domain list.
It uses `activeTab` + `scripting`, so it can only touch a page after you
explicitly open the popup on it, and the content script is injected on demand
rather than declared in the manifest. On every other page, Keyhole is not
present at all.

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

The content script **imports nothing** — not zod, not the core. It runs in the
page's process, so every kilobyte there is attack surface. It cannot read page
passwords, cannot request anything from the service worker, and holds no vault
data. The build fails if it exceeds 25 KB or acquires an `import` (currently
20.1 KB).

---

## The desktop app

```sh
npm run desktop         # build the renderer and launch it in Electron
npm run build:desktop   # → desktop/dist/Keyhole-1.0.0-portable.exe (~86 MiB)
```

The portable `.exe` needs no installer and no admin rights — copy it anywhere
and run it. Your vault is a real file at
`%APPDATA%\Keyhole\keyhole-vault.keyhole.json`, written atomically with one
`.bak` generation, and deliberately **not** stored beside the executable: moving
or deleting the `.exe` never touches your passwords.

The renderer runs on a registered secure `app://` origin with
`contextIsolation` on, `nodeIntegration` off and `sandbox` on. The preload
bridge exposes seven IPC verbs and nothing else, and no plaintext ever crosses
it — encryption happens entirely in the renderer, so the main process only ever
sees the sealed envelope.

The build is unsigned, so SmartScreen warns on first run. The executable carries
Keyhole's own icon and version metadata, but only a purchased code-signing
certificate silences that warning. [`desktop/README.md`](desktop/README.md) has
the detail.

**Coming from the browser build?** They are different origins with separate
stores, so the desktop app cannot see a browser vault. On first run it detects
that case and offers to copy it across, reading — never deleting — the browser
copy.

### What Electron costs

Earlier versions of this document ruled out an Electron/Tauri wrapper. That is
no longer true, so here is the honest accounting.

**Electron over Tauri**, because it bundles Chromium: WebCrypto, the Argon2id
WASM module and the File System Access API all behave exactly as they do in the
browser the crypto was audited against. Tauri's WebView2 does not expose the
File System Access API, which would have meant rewriting vault-file linking
against different primitives — new code on the path that touches your vault, to
save disk space.

- **You own the Chromium patch cadence.** A browser updates itself; a bundled Chromium does not. An old Keyhole `.exe` is an old Chromium, with whatever is known about it. Rebuild against current Electron periodically — the single biggest ongoing security cost of shipping a binary.
- **~86 MiB**, versus a few hundred KB of renderer bundle.
- **No code signing**, so SmartScreen warns on first run.
- **A build toolchain with open advisories.** None of it ships — see [About `npm audit`](#about-npm-audit).
- **No auto-update channel.** Deliberate: an auto-updater is a remote-code path into a password manager. Updating means replacing the `.exe` yourself.

**What it does not cost:** a second copy of the vault. The desktop app keeps
exactly one, in `%APPDATA%\Keyhole`.

---

## The Chrome extension

```sh
npm run build:extension
```

1. Open `chrome://extensions`
2. Enable **Developer mode** (top right)
3. **Load unpacked** → select `extension/dist`
4. Pin Keyhole to the toolbar
5. Click the icon, or press <kbd>Cmd/Ctrl</kbd>+<kbd>Shift</kbd>+<kbd>L</kbd>

First run: the popup offers *Set up Keyhole*, which opens the options page to
create a vault or import one exported from the app. Both use the identical file
format.

**To sign out**, use *Delete vault and start over* — in the vault window's
*Sync → Danger zone*, and on the unlock screen itself, since a forgotten master
password is the main reason to want it. It erases the encrypted vault, the
mirrored preferences and the saved sync account from `chrome.storage.local`;
exported files and the copy on a sync server are untouched. There is no
master-password prompt on this path by design, so the typed `DELETE`
confirmation is what stands between a stray click and a destroyed vault.

### MV3 notes

- **`'wasm-unsafe-eval'` in the CSP is required**, not optional — MV3 blocks WebAssembly compilation without it, and Argon2id is WASM. The rest of the CSP pins `script-src` to `'self'`; there is no `unsafe-eval`, no remote code, no `eval()`.
- **Service worker eviction locks the vault.** Chrome terminates idle service workers, which discards the in-memory session. An alarm-driven heartbeat keeps the worker warm while unlocked, but Chrome may still evict under memory pressure. This is fail-closed: you get the unlock screen, never a stale "unlocked" state.
- **Clipboard auto-clear is best-effort in the popup.** The popup usually closes before the timer fires. The desktop app, which stays open, clears reliably. Neither can reach OS-level clipboard history or Handoff.

---

## The sync server

Sync is optional. Keyhole works fully offline; the server exists so several
devices can share one vault, and it is meant to be **yours** — it stores
encrypted envelopes and can read none of them.
Reference: [`server/README.md`](server/README.md).

### A real deployment

One Linux host, a domain you control, HTTPS from a real certificate, every
device pointing at the same URL from any network:

```sh
KEYHOLE_DOMAIN=sync.example.com docker compose -f server/docker-compose.yml --profile tls up -d
```

Caddy terminates TLS and reaches the sync container over the compose network;
the sync container is never published to the internet.
**[`server/DEPLOY.md`](server/DEPLOY.md) walks the whole thing through** — DNS
prerequisites, enrolling devices, closing registration, and backups.

If your devices can join a WireGuard mesh instead (Tailscale, Netbird, plain
WireGuard), that is usually the better answer: `tailscale serve --bg
http://127.0.0.1:8787` fronts the server with a real certificate while it stays
bound to loopback — no domain, no open ports, no Caddy. Remote clients need TLS
either way, since the desktop app's `app://` origin is a secure context and will
block a plain-`http://` request whatever the server permits.

Registration is open by default so a fresh deploy is usable. On an
internet-facing host, close it the moment your devices are enrolled:

```sh
KEYHOLE_ALLOW_REGISTRATION=false docker compose -f server/docker-compose.yml up -d
```

Then confirm it — the status page's **Registration** row should read `Closed`.
`DEPLOY.md` says this louder, and means it.

### One click, no terminal

**Windows** — a tray app that needs no Docker, no domain and no Node
installation:

```sh
npm run build:server-tray   # → server-tray/dist/Keyhole-Sync-Server-1.0.0-portable.exe
```

Double-click it and the server is running at `http://127.0.0.1:8787`, with a
tray menu for the status page, Start/Stop/Restart and the data folder. Ticking
*Allow access from other devices* is a real decision —
[`server-tray/README.md`](server-tray/README.md) covers what it does and does
not get you.

**Linux/macOS** — [`server/start-keyhole-server.sh`](server/start-keyhole-server.sh),
double-clickable from a file manager:

```sh
server/start-keyhole-server.sh [start|stop|restart|status|logs]
```

Where a `keyhole-sync.service` user unit exists, every subcommand drives systemd
rather than spawning a process beside it, so the icon and `systemctl --user`
cannot disagree about what is running. Without a unit, `start` runs the server
in the foreground — which is what makes it work on a machine that has never been
set up. It checks for Node 22.5+, installs dependencies on first run, and
reports through `notify-send`, because a launcher click has no terminal to print
to.

Both launchers **bind loopback only** and pin the database to an absolute path,
overriding the server's own defaults. A service you launch by double-clicking
should not publish itself to every network you join, and should not create a
fresh empty database depending on which folder the file manager was in.

### Headless, no Docker

```sh
npm start --workspace @keyhole/server   # 0.0.0.0:8787, ./data/keyhole.sqlite
npm run dev:server                      # same, bound to 127.0.0.1
```

Node 22.5+, no build step — Node runs the TypeScript directly and SQLite is
built in. Put it behind a TLS-terminating proxy; the sync credential travels in
an `Authorization` header.

> **Each way of starting it keeps its own database** — the Docker volume,
> `%APPDATA%`, the repo's `server/data/`, and a path relative to your working
> directory. An account registered against one is invisible to the others, which
> looks exactly like having lost it. Set `KEYHOLE_DB` to an absolute path if you
> want them to share; the tray app and the shell launcher pin their own
> deliberately.

### Stopping and restarting it remotely

`KEYHOLE_CONTROL=true` adds a second listener (default port `8788`) with exactly
two actions — stop and restart — so the status dashboard can drive the server
without a terminal. There is deliberately no `start`: if the process is not
running, nothing is there to answer.

It is a separate listener rather than two more API routes because the API is a
blob store that cannot act on the machine, and this can:

- **Loopback only, and not settable from the environment.** A proxy fronts the API port and not this one, so exposing the API does not carry a remote kill switch with it.
- **A bearer token, not the vault credential.** Regenerated every boot, written `0600` beside the database. Control over the server is a different power from reading a vault, and should not be implied by it.
- **CORS for the dashboard's own local origin and nothing else**, so a page on another site cannot drive it through a browser running here.
- **The token is withheld from anything that arrived through a proxy.** Viewed through `tailscale serve`, the page has no controls and no token in its source.

It defaults to **off**. The same reasoning that keeps the bind address explicit:
this should be a decision, not something inherited from a default.

---

## Working on the UI

```sh
npm run dev:app     # renderer with HMR at http://127.0.0.1:5173
```

This is a development tool, not a way to run Keyhole. There is no installable
web build and nothing is served to browsers as a product: the renderer in a tab
has no desktop bridge, so it falls back to `localStorage`, and the *App* section
of Settings — which reports where the vault file is — does not appear.

The dev server binds `127.0.0.1` only, on 5173 or the next free port; set `PORT`
to pin it. `127.0.0.1` is a secure context, which is what WebCrypto requires, so
no certificate is needed locally.

**First run:** choose *Create vault* (minimum 12 characters, with an explicit
no-recovery acknowledgement) or *Import an existing vault file*.

**Features:** login and secure-note entries; fast search over
title/username/URL/tags (and note bodies for secure notes — never over passwords
or login notes); password generator with strength meter; TOTP codes;
export/import; change master password; configurable auto-lock and clipboard
clear; light/dark/system theme; and optional File System Access API linking so
edits save straight to a real file on disk.

Regenerate the app icons from the brand mark with `npm run icons -w @keyhole/app`.

---

## Development

```sh
npm test                                       # 245 tests across core + extension + server
npm run typecheck                              # tsc --noEmit, all workspaces
npm run demo                                   # end-to-end crypto proof
npm run demo:vault --workspace @keyhole/core   # regenerate examples/
```

TypeScript strict mode throughout, plus `noUncheckedIndexedAccess`,
`exactOptionalPropertyTypes`, `noImplicitReturns` and `noUnusedLocals`.

The extension build validates its own output: manifest correctness, no
`<all_urls>`, CSP pins `script-src 'self'`, `wasm-unsafe-eval` present, no bare
`unsafe-eval`, every referenced file exists, and the content script is ESM-free
and under 25 KB. It then boots the service worker and checks that a content
script sender is rejected.

Server sources run under Node's type stripping, which does **not** support
parameter properties, enums, or namespaces. Vitest transpiles properly and will
happily pass code that then fails to boot — so run the server, not just the
tests.

**[Manual security checklist](docs/SECURITY-CHECKLIST.md)** — re-run it after
any change to crypto, storage, or messaging.

### About `npm audit`

`npm install` reports **16 high-severity advisories. All of them are dev-only,
and none reach the shipped product.**

```sh
npm audit --omit=dev     # → found 0 vulnerabilities
```

Every one traces to a single direct dependency, `electron-builder`, and a single
advisory: [GHSA-mh99-v99m-4gvg](https://github.com/advisories/GHSA-mh99-v99m-4gvg),
a denial-of-service in `brace-expansion`. The 16 "packages" are just the chain —
`glob` → `minimatch` → `brace-expansion`, repeated through several parents.

**Why it is not fixed:** the vulnerable range is `<=5.0.7`. The only patched
release, `5.0.8`, changed its CommonJS export from a callable function to an
object. Every consumer here reaches it through `minimatch`, which does
`const expand = require('brace-expansion')` and calls it, so forcing the
override is verifiable breakage (`TypeError: expand is not a function`). There
is no upgrade path until `minimatch` adopts `brace-expansion@5`.
`npm audit fix --force` "solves" it by downgrading `electron-builder` to 25.x,
which reintroduces a **critical** `tar` path-traversal advisory — strictly
worse. Don't take that advice.

**Why it does not matter for the artifact:** `electron-builder` is a build-time
tool, and `@keyhole/desktop` has no runtime dependencies whatsoever. The packaged
`app.asar` contains no `node_modules` at all. Verify it yourself:

```sh
npx @electron/asar list desktop/dist/win-unpacked/resources/app.asar | grep node_modules   # → no matches
```

The residual risk is a hostile *input* to your own build machine (a crafted glob
pattern during packaging), not something an attacker can reach in an installed
Keyhole.

This is deliberately **not** silenced with an `audit-level` setting in `.npmrc`.
A password manager that teaches its maintainers to ignore audit output is worse
off than one with a known, understood, documented finding — the next advisory
might be the one that matters.

### Out of scope for v1

Cloud sync to third-party servers, accounts on someone else's infrastructure,
vault sharing, biometrics, analytics, and any form of phone-home telemetry.
Networking is limited to the **optional self-hosted sync server** you run; by
default no surface makes network calls, and running the desktop `.exe` adds none
— it ships with no update channel at all. Keyhole is also not distributed as a
web app: there is no hosted copy, no installable build and no service worker.

Out of scope for the desktop build specifically: code signing, an auto-updater,
macOS and Linux packaging, and OS-keychain integration.

Local live sync between the app and extension through a shared vault file is
[designed but not shipped](docs/SYNC.md) — manual export/import works today, and
so does the sync server.

---

## License

MIT. See [ARCHITECTURE.md](ARCHITECTURE.md) for data-flow diagrams.
