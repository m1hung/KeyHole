# Keyhole — Local live sync (design)

Cloud sync, accounts, and any network transport remain **out of scope**. This
document covers syncing the web app and the Chrome extension through a
**shared vault file on disk** — the same encrypted `VaultFile` envelope both
surfaces already read and write today.

Status: **design + core primitives**. Adapters and UI are not wired yet.

---

## Goal

When the user links both clients to the same `.keyhole.json` file:

1. An edit in the web app appears in the extension (and vice versa) without a
   manual export/import step.
2. Only ciphertext moves. Unlock state, the VEK, and decrypted entries never
   leave the process that unlocked them.
3. Fail closed on conflict or identity mismatch — never splice envelopes from
   different vaults, never silently drop the newer side.

Non-goals for v1 of this design: entry-level CRDT merge, multi-device cloud,
biometrics, or syncing while both sides hold divergent *unlocked* sessions
without user choice.

---

## Why a shared file (and not messaging)

| Approach | Fits Keyhole? | Notes |
|---|---|---|
| **Shared `.keyhole.json`** | Yes | Already the export format. Zero new trust boundary. Works offline. |
| `externally_connectable` (localhost → extension) | Weak | Lets a web origin talk to the vault holder. Expands attack surface. |
| Native Messaging host | Heavy | Extra install; still a process Keyhole would have to trust. |
| Cloud / accounts | No | Explicitly out of scope. |

The web app already persists via the File System Access API when linked
(`app/src/storage.ts`). Live sync extends that idea: **the file is the
canonical mirror; each client keeps a local cache for cold start.**

```
┌─────────────────┐         ┌──────────────────────────┐         ┌──────────────────┐
│  Web app        │  read/  │  keyhole-vault.keyhole.  │  read/  │  Extension       │
│  localStorage   │◄───────►│  json  (user-owned file) │◄───────►│  chrome.storage  │
│  cache          │  write  │                          │  write  │  .local cache    │
└─────────────────┘         └──────────────────────────┘         └──────────────────┘
                                      ▲
                                      │ same vaultId
                                      │ compare updatedAt + payload blob
```

---

## MV3 constraint (the hard part)

The **service worker** is the sole unlocked-session holder. It must not pull
DOM / File System Access APIs into its bundle (see the Rollup isolation fix).

Chrome also does not give service workers a durable `FileSystemFileHandle`
today the way an extension page does.

So the extension splits roles:

| Role | Where | Responsibility |
|---|---|---|
| Session + crypto | Service worker | Unlock, CRUD, autofill. Reads/writes **only** `chrome.storage.local`. |
| File link + mirror | Options page (and later an offscreen document) | Holds the `FileSystemFileHandle`, polls/reads/writes the file, copies envelopes into `chrome.storage.local`. |
| Popup | Popup | Unchanged messaging to the SW. |

The web app already combines UI + file handle in one document; no split needed.

### Warm path while the options page is closed

Phase 1 can require the options tab (or a “Sync” surface) to be open for
file↔cache mirroring. Phase 2 should move the mirror loop into a Chromium
**offscreen document** created by the SW via `chrome.offscreen`, so polling
continues without a visible tab. The SW still never imports React or FSA
directly — it only messages the offscreen page.

---

## Ordering rule (envelope-level LWW)

Decrypted entry merge is impossible without unlocking. Sync therefore operates
on the **encrypted envelope** only, using pure helpers in `@keyhole/core`
(`compareEnvelopes` / `decideSync`):

1. **`vaultId` must match.** Different ids → `unrelated` → refuse. Never
   overwrite vault A with vault B because the user pointed both at one path.
2. **Same `updatedAt` and identical payload IV+ciphertext** → `same` → noop.
3. **Same `updatedAt` but different payload** → `divergent` → conflict UI
   (clock collision or partial write). User picks a side or exports both.
4. **Different `updatedAt`** → newer wins (`a-newer` / `b-newer`). Adopt the
   newer envelope wholesale into the losing cache/file.

`updatedAt` is already written on every `saveVault` / create / re-key as an ISO
timestamp. Clients must use the envelope’s field, not the OS mtime — mtimes
are not authenticated and can move under backup tools.

### Unlocked session after adopting a newer envelope

If the client is **locked**: replace the cached envelope; next unlock uses it.

If the client is **unlocked** and the adopted envelope is newer:

- Prefer **lock + prompt to unlock again** (fail closed, simplest, matches
  “session discarded on every exit from Unlocked”).
- Do **not** attempt to decrypt the new payload with the in-memory VEK unless
  `wrappedKey` is byte-identical to the previous envelope (same master wrap).
  Even then, re-decrypting in place is a later optimisation — v1 locks.

If the local unlocked session has **unsaved** edits… Keyhole already persists
on every mutation, so this should not happen. If a write to the file fails
after local cache update, surface an error and retry; do not claim synced.

---

## Link lifecycle

### First-time link (either client)

1. User chooses *Link vault file* (open existing) or *Save vault file* (create).
2. Persist `FileSystemFileHandle` in IndexedDB (web app already does this;
   extension options gets the same pattern under the extension origin).
3. On link:
   - If file empty/missing and local cache exists → write cache → file.
   - If file exists and local cache empty → copy file → cache.
   - If both exist → `decideSync(local, file)` and apply (or conflict UI).

### Ongoing

Triggers to run `mirrorOnce()`:

- After every successful local save (push cache → file when permission held).
- On window focus / `visibilitychange` (pull file → cache).
- Periodic poll while the mirror host is alive (e.g. 5–15 s; no sub-second).
- Extension: `chrome.alarms` wake → message offscreen/options to poll.

Permission: Chromium drops FSA grants across restarts. Re-prompt on the next
user gesture; until granted, operate on cache only and show “file sync paused”.

### Unlink

Forget the handle. Caches remain independent again (today’s behaviour).

---

## Threat model additions

| Threat | Handling |
|---|---|
| User links the wrong file (different `vaultId`) | `unrelated` → refuse overwrite; show vault ids. |
| Attacker swaps file contents for another vault’s ciphertext | Same — id mismatch or wrong password on next unlock. |
| Attacker truncates / corrupts the file | `parseVaultFile` fails; keep last good cache; error toast. |
| TOCTOU between read and write | Write via `createWritable` atomically where supported; after write, re-read and confirm `updatedAt`/payload match what we intended. |
| Mirror host compromised | Still only moves envelopes already on disk / in extension storage — no keys. |

Sync does **not** weaken the “no key material persisted” rule. Handles and
paths are not secret; envelopes stay ciphertext.

---

## Implementation phases

### Phase 0 — this PR slice

- [x] Design doc (`docs/SYNC.md`)
- [x] Pure `compareEnvelopes` / `decideSync` in `@keyhole/core` + tests
- [x] Pointer from `ARCHITECTURE.md`

### Phase 1 — web app polish

- [ ] Explicit “Linked file” status in Settings (path name, last mirrored at)
- [ ] Pull-on-focus using the existing handle
- [ ] Conflict dialog when `decideSync` returns `conflict`

### Phase 2 — extension mirror host

- [ ] Options: link/unlink file handle (IndexedDB)
- [ ] `mirrorOnce` between handle and `chrome.storage.local`
- [ ] SW message: `VAULT_CACHE_UPDATED` so a locked popup refreshes; unlocked → lock

### Phase 3 — unattended mirror

- [ ] `offscreen` document + alarm-driven poll
- [ ] Build guard: offscreen bundle must not share a chunk graph with the SW
      in a way that pulls `document` into the worker (same class of bug as the
      React hoist fix)

### Phase 4 — UX

- [ ] Onboarding copy: “Link the same file in the app and the extension”
- [ ] README: manual export/import remains the fallback; live sync is opt-in

---

## API sketch (core — pure)

```ts
compareEnvelopes(a: VaultFile, b: VaultFile):
  'same' | 'a-newer' | 'b-newer' | 'divergent' | 'unrelated'

decideSync(local: VaultFile, remote: VaultFile):
  { action: 'noop' | 'adopt-remote' | 'push-local' | 'conflict' | 'refuse'; reason: string }
```

Adapters (app / extension only — **not** in core) own I/O:

```ts
interface EnvelopeCache {
  load(): Promise<VaultFile | null>;
  save(file: VaultFile): Promise<void>;
}

interface EnvelopeFile {
  read(): Promise<VaultFile | null>;
  write(file: VaultFile): Promise<void>;
  permissionState(): Promise<'granted' | 'prompt' | 'unavailable'>;
}
```

---

## Open questions

1. **Poll interval** — 5 s vs 15 s vs focus-only for Phase 1. Prefer focus +
   post-save push first; add poll when offscreen lands.
2. **Same `wrappedKey`, newer payload while unlocked** — skip re-prompt and
   re-decrypt in place? Attractive, but easy to get wrong; defer.
3. **Safari / Firefox** — FSA and offscreen are Chromium-centric. Keep
   export/import as the universal path; treat live sync as Chromium-enhanced.
