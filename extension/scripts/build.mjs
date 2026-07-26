/**
 * Extension build.
 *
 * Two Vite passes are required, because MV3 imposes different module formats on
 * different contexts:
 *
 *   pass 1 (ESM)  — popup.html, options.html, service-worker.js
 *                   The service worker is declared "type": "module", so ESM and
 *                   shared chunks are fine.
 *
 *   pass 2 (IIFE) — content.js
 *                   Content scripts injected via chrome.scripting.executeScript
 *                   are classic scripts. They cannot use `import`, so this pass
 *                   inlines every dependency into one self-contained file.
 *
 * Afterwards manifest.json and the icons are copied verbatim, and the output is
 * validated so a broken build fails here rather than at "Load unpacked".
 */

import { cp, mkdir, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
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

console.log('▸ pass 1/2  popup + options + service worker (ESM)');
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
        'service-worker': join(root, 'src/background/service-worker.ts'),
      },
      output: {
        entryFileNames: '[name].js',
        chunkFileNames: 'chunks/[name]-[hash].js',
        assetFileNames: 'assets/[name][extname]',
      },
    },
  },
});

console.log('▸ pass 2/2  content script (IIFE, self-contained)');
await build({
  ...shared,
  build: {
    outDir,
    emptyOutDir: false,
    target: 'es2022',
    minify: false,
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

if (problems.length > 0) {
  console.error('\n✗ build validation failed:');
  for (const problem of problems) console.error(`  - ${problem}`);
  process.exit(1);
}

const report = { builtAt: new Date().toISOString(), files: mustExist.filter(Boolean) };
await writeFile(join(outDir, 'build-info.json'), JSON.stringify(report, null, 2));

console.log(`\n✓ extension built to ${outDir}`);
console.log('  Load it with chrome://extensions → Developer mode → Load unpacked\n');
