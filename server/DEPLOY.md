# Deploying the Keyhole sync server

The canonical deployment: one Linux host, a domain you control, HTTPS from a
real certificate, and every device — extension and desktop app alike — pointing
at the same URL from any network.

```
your-host (DNS: sync.example.com)
  └── Caddy :80/:443  ──terminates TLS──▶  keyhole-sync :8787
                                              └── keyhole-data volume (SQLite)

clients, from anywhere:  https://sync.example.com
```

The sync container is never published to the internet. Caddy reaches it over the
compose network; the only host port it binds is `127.0.0.1:8787`, for you.

---

## What you need first

- A host with Docker and the compose plugin.
- A DNS **A/AAAA record already resolving to it**. Caddy proves control of the
  name over HTTP, so this must be true *before* you start, not after.
- Ports **80 and 443** reachable from the internet. 80 is not optional — it is
  how the certificate is issued and renewed.

Node is not required on the host. The image carries its own.

---

## 1. Bring it up

The compose file builds from the repository root, so clone the whole repo:

```bash
git clone https://github.com/m1hung/KeyHole.git
cd KeyHole
```

```bash
KEYHOLE_DOMAIN=sync.example.com docker compose -f server/docker-compose.yml --profile tls up -d
```

Two containers start: the sync server and Caddy. Certificate issuance takes a
few seconds on first run.

Check it end to end from your own machine, not the host — that is the path
clients actually take:

```bash
curl https://sync.example.com/api/v1/health
```

`{"ok":true,"service":"keyhole-sync","apiVersion":1}` means DNS, the
certificate, the proxy and the server are all working.

If it fails, narrow it down on the host first:

```bash
docker compose -f server/docker-compose.yml --profile tls logs caddy
```

A certificate error is almost always DNS not yet pointing at the host, or port
80 blocked upstream by a cloud firewall or security group.

---

## 2. Enroll your devices

Registration is **open by default**, which is what makes this step possible and
what makes step 3 urgent.

On each device, point the client at `https://sync.example.com`:

- **Extension** — Options → Sync server. It will ask for permission to access
  that origin; that prompt is expected.
- **Desktop app** — Settings → Sync server.

On the first device, *Register & upload*. On every device after that, *Sync now*.

Then confirm the server sees exactly the accounts you expect, and nothing else:

```bash
curl -s https://sync.example.com/ | grep -A1 Accounts
```

---

## 3. Close registration — same session

```bash
KEYHOLE_DOMAIN=sync.example.com KEYHOLE_ALLOW_REGISTRATION=false \
  docker compose -f server/docker-compose.yml --profile tls up -d
```

Do not leave this for later. Until it is done, anyone who finds the host can
create an account on it. The window is exactly as long as you make it — and a
host with a DNS record gets found by scanners in hours, not weeks.

Verify: the status page's **Registration** row should read `Closed`.

To enroll another device afterwards, flip it back to `true`, enroll, and close
it again.

---

## 4. Back up the volume

The `keyhole-data` volume is the entire service. Its contents are encrypted
envelopes the server cannot read — but they are still the only copy of your sync
state, and losing them means every device falls back to its local vault with no
common history.

SQLite runs in WAL mode, so copying `keyhole.sqlite` out from under a running
server can miss committed data. Take a consistent snapshot with SQLite's own
`VACUUM INTO`, which needs no downtime and no extra tooling — `node:sqlite` is
built into the runtime the image already has:

```bash
docker compose -f server/docker-compose.yml exec keyhole-sync node -e 'const {DatabaseSync}=require("node:sqlite");const db=new DatabaseSync("/data/keyhole.sqlite");db.prepare("VACUUM INTO ?").run("/tmp/keyhole-backup.sqlite");db.close()'
```

Then lift it out of the container and off the host:

```bash
docker compose -f server/docker-compose.yml cp keyhole-sync:/tmp/keyhole-backup.sqlite ./keyhole-backup.sqlite
```

It writes to `/tmp` rather than `/data` on purpose — a backup inside the volume
would end up inside every later backup.

The simpler alternative, if you would rather not run anything clever: stop the
container, copy the volume, start it again. A few seconds of downtime on a
personal sync server is a fair price for a backup script you can read at a
glance.

Restoring is the reverse: stop the container, put the file back as
`keyhole.sqlite` in the volume with no `-wal` or `-shm` beside it, start it.

---

## Configuration

Everything is environment variables; see [`README.md`](README.md) for the full
table. The ones that matter in production:

| Variable | Set it to | Why |
|---|---|---|
| `KEYHOLE_ALLOW_REGISTRATION` | `false`, after enrolling | The single most important setting on an internet-facing host. |
| `KEYHOLE_DB` | `/data/keyhole.sqlite` | Already set by the image; only change it if you change the volume. |
| `KEYHOLE_AUTH_ATTEMPTS` | leave at `10` | Failed auths per IP before a cool-off. Lower it if you like; it is a rate limit, not a lockout. |

`KEYHOLE_HOST` stays `0.0.0.0` **inside the container** — that is a container's
private network, not your host's. The host-level exposure is decided by the
`ports:` mapping, which publishes only to `127.0.0.1`.

---

## What the server can and cannot see

Unchanged by deployment, and worth re-reading before you put it on a public
address: [`README.md`](README.md#what-the-server-can-and-cannot-see). It stores
ciphertext and a public header. It can withhold updates or serve a stale
envelope; it cannot forge one, and it cannot read a password. Clients refuse a
version lower than the highest they have seen, which is what closes the rollback
attack.

That is the honest boundary. A host you control is still a host — keep it
patched, keep SSH keys tight, and keep registration closed.

---

## Not using Docker?

The server is a Node process with one dependency and no build step, so systemd
works fine: `node --experimental-strip-types server/src/index.ts` with
`KEYHOLE_HOST=127.0.0.1`, behind Caddy or nginx doing TLS on the same host. You
own the unit file, the Node version and the certificate renewal that the compose
path handles for you — which is the trade.
