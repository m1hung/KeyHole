/**
 * Keyhole offline shell.
 *
 * NOT part of the module graph — nothing imports this. The `keyhole-offline-shell`
 * plugin in vite.config.ts reads this file at build time, substitutes the two
 * `__TOKENS__` below with the real asset list and a build id, and emits the
 * result as dist/sw.js. In dev there is no service worker at all.
 *
 * What this worker does: serve the app shell from a cache so Keyhole opens with
 * no network, like an installed application.
 *
 * What it deliberately does NOT do, and why:
 *
 *  - **No runtime caching.** Only the exact files built into this release are
 *    cached, and the list is fixed at build time. A response the worker was not
 *    told about is never written to disk. The optional sync server is a different
 *    origin, so its responses are not merely uncached — they are never even
 *    inspected; those requests fall through to the network untouched.
 *
 *  - **No `skipWaiting()` on install.** `useVault.syncNow` pulls its sync code in
 *    via dynamic `import()`, so a page built from release A can request a chunk
 *    at any time. Activating release B underneath it would delete A's chunks and
 *    turn "Sync now" into a 404. A new worker therefore waits until every Keyhole
 *    window is closed, unless the user explicitly asks for the update (see the
 *    message handler), which reloads and so gets a consistent set of assets.
 *
 * The vault itself is out of reach here regardless: it lives in localStorage,
 * which service workers cannot read.
 */

/* eslint-env serviceworker */

const BUILD_ID = '__BUILD_ID__';
const CACHE_NAME = `keyhole-shell-${BUILD_ID}`;
const CACHE_PREFIX = 'keyhole-shell-';

/** Build-relative paths, injected by the build. */
const PRECACHE_PATHS = __PRECACHE__;

// Resolved against the registration scope rather than assuming a root deploy,
// so serving Keyhole from a subpath needs no change here.
const SCOPE = self.registration.scope;
const SHELL_URL = new URL('index.html', SCOPE).href;
const PRECACHE_URLS = PRECACHE_PATHS.map((path) => new URL(path, SCOPE).href);
const PRECACHE_SET = new Set(PRECACHE_URLS);

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) =>
      // `cache: 'reload'` so a stale HTTP-cache entry cannot be baked into a
      // fresh release's precache.
      cache.addAll(PRECACHE_URLS.map((url) => new Request(url, { cache: 'reload' }))),
    ),
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    (async () => {
      const keys = await caches.keys();
      await Promise.all(
        keys
          .filter((key) => key.startsWith(CACHE_PREFIX) && key !== CACHE_NAME)
          .map((key) => caches.delete(key)),
      );
      await self.clients.claim();
    })(),
  );
});

self.addEventListener('fetch', (event) => {
  const { request } = event;
  if (request.method !== 'GET') return;

  let url;
  try {
    url = new URL(request.url);
  } catch {
    return;
  }

  // Anything off-origin — the sync server above all — is none of our business.
  if (url.origin !== self.location.origin) return;

  // Navigations always resolve to the shell: the app is a single page, and this
  // is what makes a cold offline launch work.
  if (request.mode === 'navigate') {
    event.respondWith(cacheFirst(SHELL_URL, request));
    return;
  }

  // Ignore the query string when matching: precached paths never carry one, and
  // a cache-busting suffix should still hit the cache.
  const key = url.origin + url.pathname;
  if (!PRECACHE_SET.has(key)) return;

  event.respondWith(cacheFirst(key, request));
});

/**
 * Cache-first, network as fallback. Cache-first is the point — the whole cache
 * is one immutable release, and freshness is handled by installing a new worker,
 * not by re-fetching individual files.
 */
async function cacheFirst(key, request) {
  const cache = await caches.open(CACHE_NAME);
  const cached = await cache.match(key);
  if (cached) return cached;
  return fetch(request);
}

/**
 * Explicit opt-in to an update. The page reloads right after, which locks the
 * vault — so this is only ever triggered by a button the user pressed knowing
 * that, never automatically.
 */
self.addEventListener('message', (event) => {
  if (event.data && event.data.type === 'KEYHOLE_ACTIVATE_UPDATE') {
    self.skipWaiting();
  }
});
