# Icon source

The supplied artwork for Keyhole's icon set, kept here as the reference
original. The app does not load these at runtime — `app/src/components/Icon.tsx`
inlines the path data so icons ship as part of the JS bundle with no extra
network or file requests, and inherit `currentColor` from their container.

The brand mark (`vault`) is defined in `docs/brand/` — keep `vault.svg` and
`Icon.tsx` in step with `docs/brand/logo-mark.svg`.

If you change one of these files, mirror the edit into `Icon.tsx`.

| File | `IconName` | Used for |
|---|---|---|
| `vault.svg` | `vault` | Brand mark (keyhole cutout), Vault tab, extension toolbar icon |
| `login.svg` | `key` | Login entries, Logins filter, New login |
| `generator.svg` | `generator` | Generator tab |
| `settings.svg` | `settings` | Settings tab, popup options |
| `secure-note.svg` | `secureNote` | Secure notes, Notes filter, New note |
| `local-server.svg` | `localServer` | Local storage status, unlock “stays on device” badge |
| `sprite.svg` | — | Combined `<symbol>` sheet, kept for reference |

`Icon.tsx` additionally defines copy, check, eye, eyeOff, lock, user, refresh,
chevronLeft, clock, plus and trash, drawn to the same grammar (24x24, fill none,
stroke `currentColor`, width 1.75, round caps and joins).
