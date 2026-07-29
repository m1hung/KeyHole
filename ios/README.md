# Keyhole iOS

Native SwiftUI vault client. Crypto lives in `KeyholeCore` — a Swift port of
[`@keyhole/core`](../core/) that keeps the same sealed envelope format
(`keyhole.vault` / formatVersion 1 / schemaVersion 2), AAD templates, Argon2id
parameters, and AES-GCM `ct||tag` layout as the desktop app and extension.

**Requires a Mac with Xcode 15+** (iOS 17). This tree is authored so it can be
checked out on any OS; build and run only on macOS.

## Layout

```
ios/
  Package.swift              # KeyholeCore + CArgon2 + tests
  Sources/
    CArgon2/                 # PHC Argon2 reference (C), via SPM
    KeyholeCore/             # types, crypto, vault, TOTP, generator, merge
  Tests/KeyholeCoreTests/    # demo vault unlock + merge vectors
  KeyholeApp/                # SwiftUI app (XcodeGen project.yml)
  README.md
```

## Open in Xcode

### Option A — XcodeGen (recommended)

```sh
cd ios/KeyholeApp
brew install xcodegen   # once
xcodegen generate       # reads project.yml → Keyhole.xcodeproj
open Keyhole.xcodeproj
```

Select the **KeyholeApp** scheme, an iOS 17 simulator or device, then Run.
The generated `.xcodeproj` is gitignored — regenerate after pulling.

### Option B — Package only (crypto tests)

```sh
cd ios
swift test
```

`swift test` exercises `KeyholeCore`, including unlocking the demo vault
bundled at `Tests/KeyholeCoreTests/Fixtures/demo-vault.keyhole.json` (byte-identical
copy of [`examples/demo-vault.keyhole.json`](../examples/demo-vault.keyhole.json))
with `demo-master-passphrase-2026`. The first unlock pays the interactive
Argon2id cost (~64 MiB) and can take a few seconds.

> **Note:** There is no checked-in `.xcodeproj` — generate it with XcodeGen
> (Option A) or wire an App target manually (Option C). Build/run only on macOS.

### Option C — Manual app target

1. `File → Open` → `ios/Package.swift` (resolves `KeyholeCore`).
2. Create a new iOS App project next to it, or add an App target that depends on
   the local package product `KeyholeCore`.
3. Add every file under `KeyholeApp/KeyholeApp/` to that target.
4. Set deployment target to iOS 17+, bundle id e.g. `app.keyhole.vault`.

## Try the demo vault

1. Run the app → create a throwaway vault, or stay on the locked/empty screen.
2. **Settings → Import vault…** and pick
   [`examples/demo-vault.keyhole.json`](../examples/demo-vault.keyhole.json)
   (copy it to the Mac / Files first).
3. Unlock with master password: `demo-master-passphrase-2026`.

## Security notes (MVP)

- Only the sealed envelope is written under Application Support
  (`Keyhole/keyhole-vault.keyhole.json`, plus `.bak`). Writes are temp + replace.
- Master password, MK, VEK, and sync auth secret are memory-only and cleared on
  lock.
- Auto-lock follows vault settings (`autoLockMinutes`, optional `lockOnHide`).
- Clipboard secrets clear after `clipboardClearSeconds` when the app is still
  alive (same honesty limits as desktop).
- Optional sync talks to your self-hosted server (`/api/v1/health`, `prelogin`,
  `account`, `vault`) with the same HKDF sync-auth derivation as desktop.

## Out of scope (this MVP)

- AutoFill Credential Provider
- Face ID / Keychain-wrapped unlock of the vault key
- App Store signing / CI

## Argon2 embedding

`CArgon2` vendors the [PHC Argon2](https://github.com/P-H-C/phc-winner-argon2)
reference sources (`argon2id_hash_raw`) with `ARGON2_NO_THREADS` (parallelism is
already `1` in Keyhole presets). License: CC0 / Apache-2.0 (see upstream).
