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
5. Installed-app icons via `npm run icons -w @keyhole/app`
6. iOS app icon + in-app mark via `node ios/KeyholeApp/scripts/render-ios-icons.mjs`

The two icon scripts are independent on purpose. The extension's rasterises this
SVG with `sharp`; the app's redraws the same geometry from scratch in
`app/scripts/render-icons.mjs` rather than add an image dependency to the
workspace users audit most. That means **the geometry is transcribed in two
places** — change the mark here and the app script needs the same edit by hand.
