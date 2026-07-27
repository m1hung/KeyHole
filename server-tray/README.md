# @keyhole/server-tray

The Keyhole sync server as a one-click Windows app. Double-click the `.exe`, a
tray icon appears, the server is running. No console window, no command line,
and **no Node installation required** — the server runs on the Node that Electron
already bundles.

```sh
npm run server:tray          # bundle + run from source
npm run build:server-tray    # → server-tray/dist/Keyhole-Sync-Server-1.0.0-portable.exe
```

Right-click (or left-click) the tray icon for: status, **Open status page**,
**Copy server URL**, Start / Stop / Restart, **Show data folder**, About, Quit.

---

## Defaults, and why they are what they are

| | Value | Why |
|---|---|---|
| Address | `http://127.0.0.1:8787` | **Loopback only.** Not reachable from other machines. |
| Database | `%APPDATA%\Keyhole Sync Server\data\keyhole.sqlite` | An absolute path, pinned by the tray app. |
| Registration | Open | The server's own default; close it once your accounts exist. |

Both of the first two **override the server's own defaults**, deliberately:

- `KEYHOLE_HOST` normally defaults to `0.0.0.0`. That is a reasonable default for
  a deliberate deployment behind a firewall, and a bad one for something you
  launch by double-clicking — it would publish a password-sync service to every
  network you join, including untrusted Wi-Fi. Putting it on the LAN should be a
  decision, not a side effect. The tray app forces `127.0.0.1` and does not read
  `KEYHOLE_HOST`.
- `KEYHOLE_DB` normally defaults to `./data/keyhole.sqlite`, **relative to the
  working directory** — and the working directory of a double-clicked executable
  is wherever Explorer happened to be. Left alone, launching from two folders
  would silently create two separate empty databases, which looks exactly like
  losing every account you had registered.

`KEYHOLE_PORT` *is* still honoured, since a port clash is a real problem with no
security dimension.

### Using it from another device

You can't, by design, without a deliberate change. If you want the extension on
another machine to sync, either run the server the normal way
(`npm start -w @keyhole/server`, which binds `0.0.0.0`) behind a firewall you
control, or put a reverse proxy with TLS in front of it. Chromium only allows
plain `http://` to a *loopback* origin — any other host must be `https://`, so a
bare LAN IP will be refused by the browser regardless.

---

## How it works

```
Keyhole Sync Server.exe          Electron main process — tray icon only, no window
  └── keyhole-server.mjs         child process: ELECTRON_RUN_AS_NODE=1 + the bundled server
```

**The server runs out-of-process on purpose.** `server/src/index.ts` calls
`process.exit(1)` when it cannot bind, and Fastify's error paths assume they own
the process. In-process, a port clash would take the tray down with it — a user
would double-click the `.exe` and watch nothing happen, with nowhere to look.
Out-of-process it becomes a status line and a Restart menu item.

Killing the tray app takes the server with it (verified — Electron's job object
handles the child), so there is no orphaned listener holding port 8787.

### The bundle

`scripts/bundle.mjs` compiles `server/src/index.ts` and its one dependency
(`fastify`) into a single `server-dist/keyhole-server.mjs` with esbuild. Two
consequences worth knowing:

- The packaged app contains **no `node_modules`** — same property the desktop
  build has, and checkable in one command.
- Output is **ESM**, not CommonJS, because the server's entrypoint awaits
  `app.listen()` at the top level and esbuild cannot express top-level await in
  CJS. The alternative was a hand-written boot shim, i.e. a second copy of the
  startup sequence that could drift from the one `npm start` uses.

`node:sqlite` is marked external — it is built into Node and must not be inlined.
Fastify and `avvio` are CommonJS and call `require()` at load time, so the bundle
carries a `createRequire` banner; without it the server dies on first import with
`Dynamic require of "node:events" is not supported`.

---

## Packaging

Unsigned, like the desktop build, but resource-edited so the `.exe` carries
Keyhole's icon and version strings. SmartScreen will warn on first run. See
[`../desktop/README.md`](../desktop/README.md) for the full explanation.

## What this does not do

No auto-start on login, no Windows service registration, no TLS termination, and
no auto-update. Each is a real feature; none is needed to make the server
one-click, and a background service that survives reboots is a materially
different security proposition from a tray app you can see and quit.
