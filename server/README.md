# Keyhole sync server

A versioned blob store for encrypted vaults. It authenticates devices, hands
back the envelope you gave it, and refuses stale writes. It cannot read your
vault — not "does not", *cannot*: no key ever reaches it.

```sh
docker compose -f server/docker-compose.yml up -d
```

Or without Docker (Node 22.5+, no build step — Node runs the TypeScript
directly and SQLite is built in):

```sh
npm start --workspace @keyhole/server
```

---

## What the server can and cannot see

| | |
|---|---|
| **Cannot see** | Titles, usernames, passwords, URLs, notes, tags, TOTP secrets, folder names. All of it lives inside `payload`, encrypted with a key the server never receives. |
| **Can see** | The envelope's public header — vault id, format version, KDF parameters, timestamps — plus ciphertext size, your account id, and when you sync. |
| **Can do** | Withhold updates, or serve an *older* envelope to try to roll a device back to a previous password. It cannot forge one: GCM would fail. Clients must refuse a version lower than the highest they have seen. |

That last row is the honest cost of syncing. A server you do not control is a
new adversary, which is why this one is meant to be yours.

**Put it behind HTTPS.** The auth secret travels in an `Authorization` header.
The vault stays encrypted over plain HTTP, but an eavesdropper would capture
your sync credential.

---

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `KEYHOLE_HOST` | `0.0.0.0` | Bind address |
| `KEYHOLE_PORT` | `8787` | Port |
| `KEYHOLE_DB` | `./data/keyhole.sqlite` | SQLite file |
| `KEYHOLE_MAX_ENVELOPE_BYTES` | `16777216` | Largest accepted envelope |
| `KEYHOLE_AUTH_ATTEMPTS` | `10` | Failed auths per IP before cool-off |
| `KEYHOLE_AUTH_WINDOW_MS` | `60000` | Cool-off window |
| `KEYHOLE_ALLOW_REGISTRATION` | `true` | **Set `false` once your devices are enrolled** |

---

## API

Base path `/api/v1`. Auth is HTTP Basic: `base64(accountId:syncAuthSecret)`,
where the secret is `deriveSyncAuthSecret()` from `@keyhole/core` — HKDF'd from
the same Argon2id output as the master key, and useless for decryption.

### `GET /health`
`200 { ok, service, apiVersion }`

### `GET /prelogin?account=<id>`
`200 { kdf }` — the KDF parameters needed to derive the auth secret on a device
with no local state.

Unauthenticated by necessity: you need the salt before you can derive the
secret that would authenticate you. It answers for unknown accounts too, with
stable decoy parameters, so it cannot be used to enumerate accounts.

> **Clients must validate these parameters against their own cost floor.**
> A hostile server that could serve cheap KDF parameters would harvest an auth
> secret weak enough to brute-force. `assertKdfParamsAcceptable()` in
> `@keyhole/core` is exactly this check.

### `POST /account`
Body `{ accountId, authSecret, envelope }` → `201 { accountId, version, updatedAt }`

`accountId` is 3–64 chars of `a-z 0-9 . _ - @`, lowercased. `409` if taken,
`403` if registration is disabled.

### `GET /vault`
`200 { envelope, version, updatedAt }`

### `PUT /vault`
Body `{ envelope, expectedVersion }` → `200 { version, updatedAt }`

`409 { error, version, envelope, updatedAt }` when `expectedVersion` is not
current: another device wrote first. The current envelope comes back with the
conflict so the client can merge and retry in one round trip rather than two.

The version is monotonic and the check happens inside the `UPDATE` statement,
so two simultaneous writers cannot both win.

---

## Sync loop

```
1. GET /vault
2. If remote version == last synced version and nothing changed locally → done
3. Decrypt both sides, mergeVaultData(local, remote)   ← @keyhole/core
4. Re-encrypt under the local VEK
5. PUT /vault { envelope, expectedVersion: remoteVersion }
6. On 409 → the response already carries the winner; go to 3
```

Merging happens on the client because the client is the only party that can
read anything. See `core/src/sync.ts`; the merge is symmetric and idempotent,
so step 6 converges rather than ping-ponging.

---

## Development

```sh
npm test --workspace @keyhole/server        # 23 tests
npm run typecheck --workspace @keyhole/server
```

Sources run under Node's type stripping, which does **not** support parameter
properties, enums, or namespaces. Vitest transpiles properly and will happily
pass code that then fails to boot — so run the server, not just the tests.
