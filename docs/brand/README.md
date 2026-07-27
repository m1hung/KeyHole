# Brand mark

Canonical Keyhole logo assets. Source originals live here; runtime surfaces
inline or rasterize them rather than fetching at request time.

| File | Use |
|---|---|
| `logo-mark.svg` | Brand mark (`currentColor`). Inlined as `Icon` name `vault`, extension toolbar PNGs, server status heading |
| `favicon.svg` | App tab icon (`app/public/favicon.svg`) and server status favicon |
| `logo-lockup.svg` | Mark + wordmark for docs / marketing |
| `logo-mark-512.png` | Raster master of the mark |
| `preview.svg` / `preview.png` | Light + dark lockup preview |

When the mark changes, also update:

1. `app/src/components/Icon.tsx` (`vault` branch)
2. `docs/icons/vault.svg` and `docs/icons/sprite.svg`
3. `server/src/status-page.ts`
4. Extension icons via `npm run icons -w extension`
