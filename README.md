# 🔑 Keyhole

A local-first, zero-knowledge password manager. Runs as a **local web app** and as a **Chrome extension (Manifest V3)**, sharing one audited crypto core.

No accounts. No cloud sync. No telemetry. No network calls of any kind. Your vault is a single encrypted file that never leaves your device. (Local app ↔ extension live sync via a shared vault file is [designed](docs/SYNC.md); manual export/import works today.)

```
core/        framework-agnostic crypto + vault (no I/O, 135 tests)
app/         local web app (Vite + React + TypeScript)
extension/   Chrome MV3 extension (popup, service worker, autofill)
examples/    demo vault with a published master password
docs/        design notes (e.g. local live sync)
```

---

## Quick start

Requires Node 22+ (developed and tested on Node 24.18.0).

```sh
npm install
npm test                    # 143 tests across core + extension
npm run demo                # end-to-end crypto proof, printed to the terminal
npm run dev:app             # local web app at http://127.0.0.1:5173
npm run build:extension     # extension/dist, ready to load unpacked
```

### Try the demo vault

`examples/demo-vault.keyhole.json` contains five fabricated entries on
RFC 2606 reserved domains.

**Master password: `demo-master-passphrase-2026`**

This password is published deliberately — the file exists to be opened. Open the web app → *Import an existing vault file*, or the extension's options page → *Import*.

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
| `localStorage["keyhole.vault.v1"]` (web app) | The encrypted envelope. Nothing else. |
| `chrome.storage.local["keyhole.vault.v1"]` | The encrypted envelope. 10 MB quota ≈ 40,000 entries; writes above 9 MB are refused with a clear error. |
| `chrome.storage.local["keyhole.local.v1"]` | Non-secret preferences (auto-lock minutes, theme). |
| IndexedDB `keyhole-handles` (web app) | A `FileSystemFileHandle`, if you linked the vault to a file on disk. Not secret. |
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

## Running the local web app

```sh
npm run dev:app     # http://127.0.0.1:5173
npm run build --workspace @keyhole/app
```

The dev server binds to `127.0.0.1` only. WebCrypto requires a secure context, so serve any production build over `https://` or `localhost`.

**First run:** choose *Create vault* (minimum 12 characters, with an explicit no-recovery acknowledgement) or *Import an existing vault file*.

Features: entry CRUD, fast search over title/username/URL/tags (never over passwords or notes), password generator with strength meter, TOTP codes, export/import, change master password, configurable auto-lock and clipboard clear, light/dark/system theme, and optional File System Access API linking so edits save straight to a real file on disk.

## Loading the Chrome extension

```sh
npm run build:extension
```

1. Open `chrome://extensions`
2. Enable **Developer mode** (top right)
3. **Load unpacked** → select `extension/dist`
4. Pin Keyhole to the toolbar
5. Click the icon, or press <kbd>Cmd/Ctrl</kbd>+<kbd>Shift</kbd>+<kbd>L</kbd>

First run: the popup offers *Set up Keyhole*, which opens the options page to create a vault or import one exported from the web app. Both use the identical file format.

### MV3 notes

- **`'wasm-unsafe-eval'` in the CSP is required**, not optional — MV3 blocks WebAssembly compilation without it, and Argon2id is WASM. The rest of the CSP pins `script-src` to `'self'`; there is no `unsafe-eval`, no remote code, no `eval()`.
- **Service worker eviction locks the vault.** Chrome terminates idle service workers, which discards the in-memory session. An alarm-driven heartbeat keeps the worker warm while unlocked, but Chrome may still evict under memory pressure. This is fail-closed: you get the unlock screen, never a stale "unlocked" state.
- **Clipboard auto-clear is best-effort in the popup.** The popup usually closes before the timer fires. The web app, which stays open, clears reliably. Neither can reach OS-level clipboard history or Handoff.

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

The extension build validates its own output: manifest correctness, no `<all_urls>`, CSP pins `script-src 'self'`, `wasm-unsafe-eval` present, no bare `unsafe-eval`, every referenced file exists, and the content script is ESM-free and under 25 KB.

### Explicitly out of scope for v1

Cloud sync, accounts, vault sharing, biometrics, analytics, and any form of phone-home. There is no networking code in this repository — `connect-src` is pinned to `'self'` in both the app and the extension. Local live sync between the web app and extension (shared vault file, no network) is designed in [docs/SYNC.md](docs/SYNC.md) and not fully wired yet.

---

## License

MIT. See [ARCHITECTURE.md](ARCHITECTURE.md) for data-flow diagrams.
