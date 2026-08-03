# Keyhole desktop

Electron desktop app for Keyhole, and the **source of truth** for TypeScript
crypto (`@keyhole/core`) and shared sync/UI (`@keyhole/shared`).

This repository was split from the original monorepo. Sibling products:

| Repo | Path (local) | Role |
|------|--------------|------|
| **keyhole-desktop** (this repo) | `Keyhole/` | Desktop + published TS libraries + format vectors |
| [keyhole-extension](../keyhole-extension) | `../keyhole-extension` | Chromium MV3 extension |
| [keyhole-server](../keyhole-server) | `../keyhole-server` | Sync server + tray |
| [keyhole-ios](../keyhole-ios) | `../keyhole-ios` | iOS app + Swift `KeyholeCore` |

## Layout

```
core/       @keyhole/core     — crypto, vault, TOTP, URL match (no I/O)
shared/     @keyhole/shared   — sync HTTP client + shared React UI
app/        @keyhole/app      — desktop renderer (Vite)
desktop/    @keyhole/desktop  — Electron shell + portable Windows packaging
vectors/    format-contract fixtures for iOS
```

## Develop

```bash
npm ci
npm run typecheck
npm test
npm run demo
npm run pack:vectors
npm run desktop          # Electron
npm run build:desktop    # portable .exe (Windows)
```

## Publish libraries

`@keyhole/core` and `@keyhole/shared` are published from this repo (see
`.github/workflows/publish-libs.yml`). Tag `v*`, `core-v*`, or `shared-v*` with
`NPM_TOKEN` configured.

After a format-affecting release:

1. Publish libs + attach `vectors/dist/keyhole-vectors-*.tar.gz` to the GitHub Release
2. Refresh `keyhole-extension` vendor tarballs or npm pins
3. Port Swift if needed, then `keyhole-ios/scripts/sync-vectors.sh`

## Release order

```
format change → desktop core bump + vectors
             → extension bumps pins + ships
             → iOS ports Swift + verifies vectors + ships
             → server only if HTTP API changed
```

See [ARCHITECTURE.md](ARCHITECTURE.md) and [SECURITY.md](SECURITY.md).
