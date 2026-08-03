# Keyhole vault-format vectors

Sealed interchange fixtures proving TypeScript `@keyhole/core` and Swift
`KeyholeCore` open the same envelopes.

## Contents

- `MANIFEST.json` — format constants + fixture checksums
- `demo-vault.keyhole.json` — published demo vault (master password in the manifest)

## Regenerate

From the desktop repo root:

```bash
npm run pack:vectors
```

Attach `dist/keyhole-vectors-*.tar.gz` to the desktop release that bumps format
or schema versions.

## iOS sync

```bash
# sibling checkout
../keyhole-ios/scripts/sync-vectors.sh ./vectors

# or from a release asset
KEYHOLE_VECTORS_URL=https://github.com/.../releases/download/.../keyhole-vectors-1.0.0.tar.gz \
  ./scripts/sync-vectors.sh
```
