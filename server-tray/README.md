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

Two different problems hide behind that sentence, and they want different
answers: reaching the server *on the network you are both on*, and reaching it
*from somewhere else*. Start with the second — it is the common case, and the
answer is better.

### From another network: a mesh VPN

Put both machines on a WireGuard mesh (Tailscale below; plain WireGuard or
Netbird work the same way) and let it carry the connection. No ports are
forwarded, nothing is published to the internet, and only your own devices can
route to the address at all.

With Tailscale specifically, its proxy can also terminate HTTPS with a real
certificate, which means **the tray tick stays off and the server never leaves
loopback**:

```bash
tailscale serve --bg http://127.0.0.1:8787
```

The proxy connects from `127.0.0.1`, so the only thing listening on a network
interface is Tailscale. Clients use `https://<this-machine>.<your-tailnet>.ts.net`.

- Needs MagicDNS and HTTPS certificates enabled in the Tailscale admin console.
- Flag syntax has moved between Tailscale versions; check `tailscale serve --help`.
- Use `serve`, **not** `funnel`. Funnel publishes to the public internet, which
  is the thing this approach exists to avoid.

The certificate is issued for a name you control through Tailscale, so there is
no private CA for client devices to trust — which is the tedious part of every
other no-domain option below.

The tray menu will still report loopback, because it only knows its own bind
address and cannot discover the `.ts.net` name. Type that into the client
yourself.

### On the same network: the tray tick

Tray menu → **Allow access from other devices**. It is off by default, asks for
confirmation once, remembers the answer in
`%APPDATA%\Keyhole Sync Server\settings.json`, and restarts the server on
`0.0.0.0`. The tray then shows the LAN URL, and **Copy server URL** copies that
instead of the loopback one. Untick it to go back to loopback.

This is the right tool for a laptop and a phone on a home network you trust. It
is the wrong tool for crossing networks: it binds every interface, including
whatever café Wi-Fi you join next.

**The tick does not give you TLS, and you want TLS.** The vault payload is
encrypted end-to-end either way, but the sync credential travels in an
`Authorization` header — plain HTTP over a network hands it to anyone listening.
Separately, the desktop app runs on the `app://` scheme, a secure context, so an
`http://` request from it is mixed content and the browser engine blocks it; a
bare `http://192.168.1.x:8787` will not work there regardless of what the server
allows.

So on a plain LAN the tick is step one of two, and step two is a certificate:

**With a domain you control** — run the server under Docker instead, with the
bundled proxy profile:

```bash
KEYHOLE_DOMAIN=sync.example.com docker compose -f server/docker-compose.yml --profile tls up -d
```

Caddy gets and renews the certificate; clients use `https://sync.example.com`.

**No domain** — install Caddy on this machine and put it in front of the tray
app, which keeps running exactly as it does now:

```bash
caddy reverse-proxy --from keyhole.local --to 127.0.0.1:8787 --internal-certs
```

`--internal-certs` issues from Caddy's own CA, so every client device must trust
that root certificate and resolve `keyhole.local` to this machine. Trusting a
private CA on each device is a real decision, and it is exactly the work
`tailscale serve` removes. With a proxy on loopback in front, the tray tick can
stay **off** here too: only Caddy needs to reach the server.

### Whichever route you take

Enroll your devices while everything is still on loopback, then close
registration. The tray app passes its environment through to the server, so a
user-level `KEYHOLE_ALLOW_REGISTRATION=false` in Windows' environment variables
takes effect on the next launch. Anything reachable by more than one machine
should not be accepting new accounts.

And if you bound to `0.0.0.0`, check that the Windows firewall profile for the
network in question is one you actually trust — an exposed server is only as
private as the network it is exposed on.

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
