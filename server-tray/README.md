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
| Address | `http://127.0.0.1:8787` | **Loopback only**, until you tick *Allow access from other devices*. |
| Database | `%APPDATA%\Keyhole Sync Server\data\keyhole.sqlite` | An absolute path, pinned by the tray app. |
| Registration | Open | The server's own default; close it once your accounts exist. |

Both of the first two **override the server's own defaults**, deliberately:

- `KEYHOLE_HOST` normally defaults to `0.0.0.0`. That is a reasonable default for
  a deliberate deployment behind a firewall, and a bad one for something you
  launch by double-clicking — it would publish a password-sync service to every
  network you join, including untrusted Wi-Fi. Putting it on the LAN should be a
  decision, not a side effect. So the tray app ignores `KEYHOLE_HOST` entirely
  and takes the bind address from the menu tick below: exposure is something you
  can see in the UI, not an environment variable you set once and forget.
- `KEYHOLE_DB` normally defaults to `./data/keyhole.sqlite`, **relative to the
  working directory** — and the working directory of a double-clicked executable
  is wherever Explorer happened to be. Left alone, launching from two folders
  would silently create two separate empty databases, which looks exactly like
  losing every account you had registered.

`KEYHOLE_PORT` *is* still honoured, since a port clash is a real problem with no
security dimension.

---

## Using it from another device

Tray menu → **Allow access from other devices**. It is off by default, asks for
confirmation once, remembers the answer in
`%APPDATA%\Keyhole Sync Server\settings.json`, and restarts the server on
`0.0.0.0`. The tray then shows the LAN URL, and **Copy server URL** copies that
instead of the loopback one. Untick it to go back to loopback.

**The tick alone is not enough to make a browser connect.** Chromium treats only
loopback as a trustworthy origin, so the web app and the extension refuse plain
`http://` to any other host. A bare `http://192.168.1.x:8787` will be rejected by
the client before the server is ever contacted. You also do not *want* it: the
vault payload is encrypted end-to-end, but the sync credential travels in an
`Authorization` header and plain HTTP hands it to anyone on the network.

So the tick is step one of two. Step two is TLS:

**With a domain you control** — run the server under Docker instead, with the
bundled proxy profile:

```bash
KEYHOLE_DOMAIN=sync.example.com docker compose -f server/docker-compose.yml --profile tls up -d
```

Caddy gets and renews the certificate; clients use `https://sync.example.com`.

**LAN only, no domain** — install Caddy on this machine and put it in front of
the tray app, which keeps running exactly as it does now:

```bash
caddy reverse-proxy --from keyhole.local --to 127.0.0.1:8787 --internal-certs
```

`--internal-certs` issues from Caddy's own CA, so every client device must trust
that root certificate and resolve `keyhole.local` to this machine. Trusting a
private CA on each device is a real decision — if you have a domain, the first
option is far less surprising. Note that with a proxy on loopback in front, the
tray tick can stay **off**: only Caddy needs to reach the server.

Either way: close registration once your devices are enrolled. The tray app
passes its environment through to the server, so a user-level
`KEYHOLE_ALLOW_REGISTRATION=false` in Windows' environment variables takes effect
on the next launch. And check that the Windows firewall profile for the network
in question is one you actually trust — an exposed server is only as private as
the network it is exposed on.

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
