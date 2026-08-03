# Four-repository layout

Keyhole is split across four product repositories. Cross-repo coupling is
limited to:

| From → To | Mechanism |
|-----------|-----------|
| desktop → extension | npm (`@keyhole/core`, `@keyhole/shared`) or vendored `*.tgz` |
| desktop → iOS | `vectors/` release assets (`MANIFEST.json` + sealed vaults) |
| any client → server | HTTP sync API (encrypted envelopes only) |

## Local checkouts (sibling directories)

```
Projects/
  Keyhole/              # keyhole-desktop (this repo)
  keyhole-extension/
  keyhole-server/
  keyhole-ios/
```

## Refreshing extension vendor packages

```bash
cd Keyhole
npm run build:libs
npm pack --workspace @keyhole/core --pack-destination ../keyhole-extension/vendor
npm pack --workspace @keyhole/shared --pack-destination ../keyhole-extension/vendor
```

## Refreshing iOS vectors

```bash
cd keyhole-ios
./scripts/sync-vectors.sh ../Keyhole/vectors
# or KEYHOLE_VECTORS_URL=... ./scripts/sync-vectors.sh
```
