# @keyhole/desktop

Keyhole as a native Windows application: one portable `.exe`, no installer, no
admin rights, and no browser.

```sh
npm run desktop            # build the renderer and run it in Electron
npm run build:desktop      # produce desktop/dist/Keyhole-1.0.0-portable.exe
```

The renderer is the *same* React app as `@keyhole/app` — same components, same
`@keyhole/core`, same audited crypto. This workspace adds a main process, a
preload bridge, and packaging. It does not fork the UI.

---

## Where the vault lives

```
%APPDATA%\Keyhole\keyhole-vault.keyhole.json      the vault (encrypted)
%APPDATA%\Keyhole\keyhole-vault.keyhole.json.bak  the previous version
```

A real file, deliberately — you can back it up, copy it to another machine, or
open it with the browser build's *Import*. It is the identical `VaultFile`
envelope every other Keyhole surface reads.

It does **not** live beside the `.exe`. Moving or deleting the executable never
touches the vault, and a portable binary run from a USB stick does not silently
carry your passwords with it.

Every write goes to a temp file and is then renamed over the target, so an
interrupted save leaves either the old vault or the new one — never half of one.
The previous generation is kept as `.bak`.

### Coming from the browser build

The browser app and the desktop app are **different origins with different
stores**, so the desktop app cannot see a vault created in a browser tab. On a
first run where that situation is detected, the app offers to copy it across.
The browser copy is only ever read, never deleted.

To move a vault manually: browser build → *Settings → Backup → Export*, then
desktop → *Open a different vault file*.

---

## Security posture

The renderer is treated as untrusted, in the same spirit as the extension's
content script.

| | |
|---|---|
| `contextIsolation` | on |
| `nodeIntegration` | off |
| `sandbox` | on |
| `webviewTag` | off |
| Preload surface | 7 IPC verbs, all validated in main (`src/preload.cjs`) |
| Origin | `app://keyhole` — a registered **secure** standard scheme, so WebCrypto behaves exactly as on `https://` |
| Navigation | anything off-origin is refused; `https://` links open in the real browser |
| OS permissions | camera, microphone, geolocation and notifications are all denied outright |
| Instances | single-instance lock, so two windows cannot race writes to the vault |

**No plaintext crosses the IPC boundary.** Encryption happens entirely in the
renderer; the main process only ever receives the sealed envelope as JSON text.
It never holds the master password, a derived key, or a decrypted entry.

`file://` was rejected as the renderer origin: it yields an opaque origin, which
breaks storage partitioning and makes CORS against the sync server
unpredictable.

---

## Sync

Unchanged and fully supported. The desktop build talks to the self-hosted server
in `server/` exactly as the browser build does — the server reflects the request
`Origin`, so `app://keyhole` needs no server-side configuration.

Note that `http://` sync servers work only on loopback (`127.0.0.1` /
`localhost`), which Chromium treats as a trustworthy origin. A server on another
machine must be `https://`. That is the same rule the browser build follows, not
a new desktop restriction.

---

## Packaging notes

The build is **unsigned** (`signExecutable: false`), but the executable's
resources *are* edited, so it carries Keyhole's icon and version metadata:

```
ProductName    Keyhole
CompanyName    Keyhole
LegalCopyright MIT
```

`CompanyName` comes from `author` in `package.json`. Without it electron-builder
leaves Electron's default and the binary claims to originate from *GitHub, Inc.*
— false attribution is worse than a blank field, especially on an unsigned
password manager.

**SmartScreen will still warn on first run** ("More info" → "Run anyway"). The
only real fix is Authenticode signing, which needs a purchased certificate and a
decision about where the private key lives — a procurement and key-custody
question, not a build flag.

> Historical note: earlier revisions used `signAndEditExecutable: false`, which
> disables signing *and* resource editing together, producing a binary labelled
> "Electron". electron-builder 26 split the two knobs; `signExecutable: false` is
> the one you want.

---

## Updating

There is no auto-updater and nothing phones home. A new version is a new `.exe`
that you drop in place of the old one; the vault in `%APPDATA%` is untouched by
the swap.
