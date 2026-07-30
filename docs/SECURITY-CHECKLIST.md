# Manual security test checklist

Verified in a real browser during development; re-run after any change to
crypto, storage, or messaging. Items marked *(Automated)* also have test
coverage — the manual check confirms the behaviour end to end, in a real
runtime, which a unit test cannot.

Back to the [README](../README.md).

---

## Crypto & storage

- [ ] Create a vault, add an entry, then inspect `localStorage` / `chrome.storage.local` — no title, username, password, URL or note appears in plaintext. *(Automated: `vault.test.ts` "never writes plaintext into the envelope")*
- [ ] Wrong master password → "Wrong master password", stays locked, no partial data rendered.
- [ ] Corrupt one character of `payload.ctB64` → refuses to unlock.
- [ ] Edit `kdf.memoryKiB` down to `1024` → refuses to unlock.
- [ ] Copy `wrappedKey` from another vault into this one → refuses to unlock.
- [ ] Change the master password → old password rejected, all entries intact, salt/wrappedKey/payload all changed.
- [ ] Export → delete vault → import → unlocks with the same password, entries intact.
- [ ] Two saves in a row produce different `payload.ivB64`.

## Desktop app

- [ ] `npm run build:desktop`, run the `.exe` → window opens, no browser chrome, no menu bar.
- [ ] DevTools console: `window.require` and `window.process` are both `undefined`; `isSecureContext` is `true`.
- [ ] `window.keyhole.vault` exposes exactly seven verbs and nothing else.
- [ ] Create a vault → `%APPDATA%\Keyhole\keyhole-vault.keyhole.json` appears; open it — ciphertext and public header only.
- [ ] Edit an entry → the file's `payload.ivB64` changes and a `.bak` holds the previous version; no `.tmp` is left behind.
- [ ] Close and relaunch → the unlock screen appears immediately, never a create-vault flash.
- [ ] Launch a second instance → it focuses the existing window instead of opening a second one.
- [ ] With a vault in the browser build and none on disk, first run offers to copy it across; declining leaves the browser copy intact.
- [ ] *Settings → App* shows the real vault path; *Show in Explorer* opens it.
- [ ] Copy a generated password → it lands on the clipboard, with no "denied clipboard access" error. *(Chromium gates `writeText` behind `clipboard-sanitized-write`; a blanket permission denial in the main process breaks every Copy button.)*
- [ ] Wait past the clear timer → the clipboard is emptied. *(Needs `clipboard-read`: without it the timer cannot tell whether the clipboard still holds Keyhole's value, and clears whatever is there.)*
- [ ] DevTools console: `navigator.permissions.query({name:'geolocation'})` still reports `denied`.
- [ ] Configure sync against a local server → *Register & upload* succeeds; the server row holds only the encrypted envelope.
- [ ] Move the `.exe` to another folder and run it → same vault, because the vault is not stored beside it.

## Locking

- [ ] Set auto-lock to 1 minute, idle → locks; countdown appears under 60s.
- [ ] Reload the page while unlocked → locked.
- [ ] Enable lock-on-hide, switch tabs → locked.
- [ ] Restart Chrome → extension is locked.
- [ ] Copy a password, wait past the clear timer → clipboard no longer holds it.

## Extension messaging

- [ ] From a page console: `chrome.runtime.sendMessage('<ext-id>', {type:'EXPORT_VAULT'})` → rejected. *(Automated: sender-validation tests in `messages.test.ts`)*
- [ ] Same with `{type:'RESET_VAULT'}` → rejected, vault intact. *(Automated: build smoke test)*
- [ ] `chrome://extensions` → service worker → Console shows no logged secrets.
- [ ] `chrome://extensions` shows no host-permission warning at install.

## Autofill

- [ ] Save an entry for `github.com`; open a lookalike such as `github.com.evil.example` → popup shows no match. *(Automated: lookalike tests in `url-match.test.ts`)*
- [ ] Click Fill, then navigate the tab before the fill completes → refused with a host-mismatch message.
- [ ] Fill into a React-based login form → the app registers the value (not just the DOM).
- [ ] Before clicking Fill, confirm no password is present in the page DOM.
- [ ] Try to fill on `chrome://extensions` → clean error, no crash.

## Extension sign-out

- [ ] *Sync → Danger zone → Delete vault and start over* → the confirm button stays disabled until `DELETE` is typed.
- [ ] Confirm → the create-vault screen appears, and `chrome.storage.local` holds none of `keyhole.vault.v1`, `keyhole.local.v1`, `keyhole.sync.v1`.
- [ ] Reopen the vault window → the sync server URL and account id fields are back to defaults, not the previous owner's.
- [ ] Lock, then reset from the *unlock* screen → same result without ever entering the master password.
- [ ] Popup while locked → *Forgot your master password?* opens the vault window rather than resetting anything itself.
- [ ] Reopen the popup after a reset → *No vault in this browser yet*, not a stale entry list.

## Sync server — Windows tray app

- [ ] Double-click the `.exe` → tray icon appears, no console window, `http://127.0.0.1:8787` responds.
- [ ] `netstat -ano | findstr :8787` shows `127.0.0.1:8787`, **not** `0.0.0.0:8787`.
- [ ] From another machine on the same network, the address is unreachable.
- [ ] *Allow access from other devices* → Cancel → the checkbox stays unticked and the binding is unchanged.
- [ ] *Allow access from other devices* → confirm → `netstat` now shows `0.0.0.0:8787`, the tray shows the LAN URL, and *Copy server URL* copies it.
- [ ] Quit and relaunch → the tick survived; untick it → back to `127.0.0.1:8787` after the restart.
- [ ] Delete `%APPDATA%\Keyhole Sync Server\settings.json`, or corrupt it → starts loopback-only rather than exposed.
- [ ] Database lands in `%APPDATA%\Keyhole Sync Server\data\`, not next to the `.exe` or in the launch folder.
- [ ] Launch it from two different folders → the same database, same accounts, both times.
- [ ] Start it while port 8787 is already taken → the tray reports the error rather than vanishing.
- [ ] Quit from the tray, then check port 8787 → released, no orphaned process.
- [ ] Kill the tray from Task Manager → the server child dies with it. *(Verified: Electron's job object)*
- [ ] Launch a second copy → it exits instead of fighting over the port and the SQLite file.

## Sync server — Linux/macOS launcher and control plane

- [ ] Double-click `start-keyhole-server.sh` from a file manager → the server comes up and a browser opens on the status page.
- [ ] Launch it from two different working directories → the same database both times, because paths resolve from the script's own location.
- [ ] Click the launcher again while it is running → "Already running", one process, no port collision.
- [ ] With a `keyhole-sync.service` present, `stop` / `restart` / `status` agree with `systemctl --user status keyhole-sync`.
- [ ] `restart` under systemd → the pid moves, `Result=success`, and the restart is not recorded as a crash.
- [ ] `ss -ltnp` shows the control listener on `127.0.0.1:8788` only, and it is unreachable over the tailnet.
- [ ] An unauthenticated `POST` to the control listener → `401`.
- [ ] The dashboard on `127.0.0.1` carries Stop/Restart and a token; the same page through `tailscale serve` carries neither, and neither appears in its source.
- [ ] Clicking Restart in the browser → the pid moves, the token rotates, the page reloads with no console errors.
- [ ] Clicking Stop → the unit is inactive and both ports are free.

## Renderer dev server

- [ ] `npm run dev:app` → DevTools → Application shows no service worker, no Cache Storage, and no web manifest.
- [ ] *Settings* has no *App* section in a browser tab, and no install offer anywhere in the UI.
- [ ] `npm run build --workspace @keyhole/app` → `dist/` contains no `sw.js` and no `manifest.webmanifest`.
- [ ] With sync configured, click *Sync now* → the request appears in the network log as a real request.

## Breach check (opt-in network)

- [ ] With *Allow Have I Been Pwned password checks* **off**, interact with the vault (unlock, edit, health scan, autofill) → DevTools network log shows **no** request to `api.pwnedpasswords.com`.
- [ ] Enable the setting → still no request until you click *Check passwords*.
- [ ] Click *Check passwords* once → exactly one range request per unique password checked; URL path is five hex characters only; request carries `Add-Padding: true`; no account id or vault metadata in headers/body.
- [ ] Results appear in the health panel and vanish on lock / reload (not written into the vault file).
- [ ] Extension: first use prompts for `https://api.pwnedpasswords.com/*` via `optional_host_permissions`; denying it shows an error and makes no request.

## Trash retention

- [ ] Unlock a vault with an entry trashed 31+ days ago → it is gone and a tombstone exists; an entry trashed yesterday remains in the trash. *(Automated for the extension unlock path; confirm desktop and iOS manually.)*
