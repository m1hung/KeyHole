/**
 * Extension build.
 *
 * Three Vite passes, because MV3 runs each context in a different environment
 * and they must not share a chunk graph:
 *
 *   pass 1 (ESM)  — popup.html, options.html
 *                   DOM pages. React lives here and only here.
 *
 *   pass 2 (ESM)  — service-worker.js
 *                   No DOM. Bundled standalone: when this shared chunks with
 *                   pass 1, Rollup put its `export *` helper in the React chunk
 *                   and the worker died at load with "document is not defined".
 *
 *   pass 3 (IIFE) — content.js
 *                   Injected via chrome.scripting into the page's process, so it
 *                   must be a classic script with no imports and stay tiny.
 *
 * Afterwards manifest.json and the icons are copied verbatim, and the output is
 * validated — including actually booting the service worker — so a broken build
 * fails here rather than at "Load unpacked".
 */

import { cp, mkdir, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { build } from 'vite';
import react from '@vitejs/plugin-react';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..');
const outDir = join(root, 'dist');

await rm(outDir, { recursive: true, force: true });
await mkdir(outDir, { recursive: true });

const shared = {
  root,
  configFile: false,
  plugins: [react()],
  resolve: { extensions: ['.ts', '.tsx', '.js', '.jsx', '.json'] },
  define: { 'process.env.NODE_ENV': '"production"' },
};

console.log('▸ pass 1/3  popup + options (ESM, DOM)');
await build({
  ...shared,
  build: {
    outDir,
    emptyOutDir: false,
    target: 'es2022',
    minify: false, // reviewable output: a password manager should be auditable
    rollupOptions: {
      input: {
        popup: join(root, 'popup.html'),
        options: join(root, 'options.html'),
      },
      output: {
        entryFileNames: '[name].js',
        chunkFileNames: 'chunks/[name]-[hash].js',
        assetFileNames: 'assets/[name][extname]',
      },
    },
  },
});

/**
 * The service worker gets its OWN self-contained bundle. It must not share a
 * chunk graph with the DOM pages.
 *
 * When it was a third entry in pass 1, Rollup hoisted its `export *` helper
 * (`__exportAll`) into the same chunk as React — so importing the vault core
 * transitively pulled React DOM into the worker, and the worker died at load
 * with "document is not defined". No listener registered, so the popup hung on
 * "Loading…" forever.
 *
 * `inlineDynamicImports` forces one file with no imports, which makes that
 * class of leak structurally impossible rather than merely unlikely.
 */
console.log('▸ pass 2/3  service worker (ESM, self-contained, no DOM)');
await build({
  ...shared,
  build: {
    outDir,
    emptyOutDir: false,
    target: 'es2022',
    minify: false,
    lib: {
      entry: join(root, 'src/background/service-worker.ts'),
      formats: ['es'],
      fileName: () => 'service-worker.js',
    },
    rollupOptions: {
      output: { inlineDynamicImports: true },
    },
  },
});

console.log('▸ pass 3/3  content script (IIFE, self-contained)');
await build({
  ...shared,
  build: {
    outDir,
    emptyOutDir: false,
    target: 'es2022',
    // Minify the injected script — every kilobyte runs in the page process.
    minify: true,
    lib: {
      entry: join(root, 'src/content/autofill.ts'),
      formats: ['iife'],
      name: 'KeyholeAutofill',
      fileName: () => 'content.js',
    },
    rollupOptions: {
      output: { extend: true },
    },
  },
});

console.log('▸ copying manifest and icons');
await cp(join(root, 'manifest.json'), join(outDir, 'manifest.json'));
await cp(join(root, 'icons'), join(outDir, 'icons'), { recursive: true });

// ---------------------------------------------------------------------------
// Validation — catch packaging mistakes before Chrome does
// ---------------------------------------------------------------------------

console.log('▸ validating output');
const manifest = JSON.parse(await readFile(join(outDir, 'manifest.json'), 'utf8'));
const problems = [];

const mustExist = [
  manifest.background?.service_worker,
  manifest.action?.default_popup,
  manifest.options_ui?.page,
  'content.js',
  ...Object.values(manifest.icons ?? {}),
];

for (const file of mustExist) {
  if (!file) continue;
  try {
    await stat(join(outDir, file));
  } catch {
    problems.push(`missing referenced file: ${file}`);
  }
}

if (manifest.manifest_version !== 3) problems.push('manifest_version must be 3');
if (manifest.host_permissions?.includes('<all_urls>')) problems.push('<all_urls> host permission is not allowed');

const csp = manifest.content_security_policy?.extension_pages ?? '';
if (!csp.includes("script-src 'self'")) problems.push("CSP must pin script-src to 'self'");
// Negative lookbehind so the required 'wasm-unsafe-eval' is not mistaken for
// the forbidden bare 'unsafe-eval'.
if (/(?<!wasm-)unsafe-eval/.test(csp)) problems.push("CSP must not allow bare 'unsafe-eval'");
// Argon2id runs in WebAssembly, which MV3 gates behind this token.
if (!csp.includes('wasm-unsafe-eval')) problems.push("CSP needs 'wasm-unsafe-eval' for the Argon2id WASM module");

/**
 * The service worker runs with no DOM. Any reference to `document` or `window`
 * means DOM code leaked into the worker bundle, which kills it at load time and
 * manifests as a popup stuck on "Loading…" — a miserable thing to debug from
 * the symptom, so it is caught here instead.
 */
const sw = await readFile(join(outDir, manifest.background.service_worker), 'utf8');
if (/^\s*import\s.*from\s/m.test(sw)) {
  problems.push('service-worker.js imports a shared chunk; it must be self-contained');
}
for (const global of ['document', 'window']) {
  // Match real global usage, not substrings inside identifiers or strings.
  const hits = sw.match(new RegExp(`(?<![\\w.$"'\`])${global}\\s*(\\.|\\[)`, 'g'));
  if (hits) {
    problems.push(`service-worker.js references \`${global}\` ${hits.length}x — DOM code leaked into the worker`);
  }
}

// The content script must be genuinely self-contained: a stray `import` would
// throw at injection time, which is awkward to debug from a live page.
const content = await readFile(join(outDir, 'content.js'), 'utf8');
if (/^\s*import\s/m.test(content) || /^\s*export\s/m.test(content)) {
  problems.push('content.js contains ESM syntax; it must be a classic script');
}
// The content script runs in the page's process, so its size is attack surface.
// A regression that pulls zod or the core back in would blow past this.
const contentKb = Buffer.byteLength(content) / 1024;
if (contentKb > 25) {
  problems.push(`content.js is ${contentKb.toFixed(0)} KB; it must stay dependency-free (<25 KB)`);
}

/**
 * Smoke test: actually boot the service worker and drive one round trip.
 *
 * The static checks above can be fooled; executing the bundle cannot. This
 * catches any load-time crash — the failure mode that presents to a user as a
 * popup stuck on "Loading…" with nothing useful in the console.
 */
console.log('▸ smoke-testing the service worker');
{
  const store = {};
  const messageListeners = [];
  const noop = () => {};
  const previousChrome = globalThis.chrome;
  globalThis.chrome = {
    runtime: {
      id: 'smoketestidsmoketestidsmoketesti',
      onMessage: { addListener: (f) => messageListeners.push(f) },
      onMessageExternal: { addListener: noop },
      onStartup: { addListener: noop },
      onInstalled: { addListener: noop },
    },
    storage: {
      local: {
        get: async (key) => (store[key] !== undefined ? { [key]: store[key] } : {}),
        set: async (obj) => void Object.assign(store, obj),
        remove: async (key) => void delete store[key],
      },
      session: {
        get: async (key) => (store[`session:${key}`] !== undefined ? { [key]: store[`session:${key}`] } : {}),
        set: async (obj) => {
          for (const [k, v] of Object.entries(obj)) store[`session:${k}`] = v;
        },
        remove: async (key) => void delete store[`session:${key}`],
      },
    },
    alarms: { create: async () => {}, clear: async () => {}, onAlarm: { addListener: noop } },
    action: { setBadgeText: async () => {}, setBadgeBackgroundColor: async () => {} },
    tabs: {
      get: async () => ({ url: 'https://example.com/' }),
      sendMessage: async () => ({}),
      query: async () => [{ id: 1, url: 'https://example.com/', active: true }],
      onActivated: { addListener: noop },
      onUpdated: { addListener: noop },
    },
    scripting: { executeScript: async () => {} },
    windows: {
      onRemoved: { addListener: noop },
      onFocusChanged: { addListener: noop },
      create: async () => ({}),
      update: async () => ({}),
      WINDOW_ID_NONE: -1,
    },
  };

  try {
    await import(pathToFileURL(join(outDir, manifest.background.service_worker)).href);
    if (messageListeners.length === 0) {
      problems.push('service worker registered no onMessage listener');
    } else {
      const sender = { id: chrome.runtime.id, url: `chrome-extension://${chrome.runtime.id}/popup.html` };
      const reply = await new Promise((resolve) => {
        const timer = setTimeout(() => resolve({ timedOut: true }), 5000);
        messageListeners[0]({ type: 'GET_STATE' }, sender, (r) => {
          clearTimeout(timer);
          resolve(r);
        });
      });
      if (reply?.timedOut) problems.push('service worker did not answer GET_STATE within 5s');
      else if (reply?.ok !== true) problems.push(`service worker rejected GET_STATE: ${JSON.stringify(reply)}`);
      else console.log(`  ✓ worker booted and answered GET_STATE (locked=${reply.locked})`);

      // A content script must never get a privileged answer.
      const hostile = { id: chrome.runtime.id, url: 'https://evil.example/', tab: { id: 1 } };
      const denied = await new Promise((resolve) => {
        messageListeners[0]({ type: 'EXPORT_VAULT' }, hostile, resolve);
      });
      if (denied?.ok !== false) problems.push('service worker answered a content-script sender!');
      else console.log('  ✓ content-script sender rejected');

      // Content scripts may ask for suggestions, but only for their own tab.
      const suggest = await new Promise((resolve) => {
        messageListeners[0]({ type: 'SUGGEST_FOR_PAGE' }, hostile, resolve);
      });
      if (suggest?.ok !== true || suggest?.type !== 'SUGGESTIONS' || suggest?.locked !== true) {
        problems.push('service worker did not handle SUGGEST_FOR_PAGE from a content script');
      } else console.log('  ✓ content-script SUGGEST_FOR_PAGE handled (vault locked)');
    }
  } catch (err) {
    problems.push(`service worker crashed on load: ${err.message}`);
  } finally {
    globalThis.chrome = previousChrome;
  }
}

if (problems.length > 0) {
  console.error('\n✗ build validation failed:');
  for (const problem of problems) console.error(`  - ${problem}`);
  process.exit(1);
}

const report = { builtAt: new Date().toISOString(), files: mustExist.filter(Boolean) };
await writeFile(join(outDir, 'build-info.json'), JSON.stringify(report, null, 2));

console.log(`\n✓ extension built to ${outDir}`);
console.log('  Load it with chrome://extensions → Developer mode → Load unpacked\n');
