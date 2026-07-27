import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineConfig, type Plugin } from 'vite';
import react from '@vitejs/plugin-react';

const here = dirname(fileURLToPath(import.meta.url));
const publicDir = resolve(here, 'public');

/**
 * Emits dist/sw.js from src/service-worker.js, substituting the list of files
 * this build actually produced and an id that changes whenever any of them do.
 *
 * Written by hand rather than pulled from a PWA plugin: the whole worker is a
 * precache list and three event handlers, and for a password manager the code
 * that sits between the app and the network is worth being able to read in one
 * sitting. See src/service-worker.js for the behavioural rationale.
 */
function offlineShell(): Plugin {
  return {
    name: 'keyhole-offline-shell',
    apply: 'build',
    // Run after Vite's own HTML plugin so index.html is already in the bundle.
    enforce: 'post',
    generateBundle(_options, bundle) {
      const publicFiles = listFiles(publicDir);

      const precache = [
        // Stated explicitly rather than trusted to be in `bundle`, because it is
        // the one entry an offline cold start cannot do without.
        'index.html',
        // Source maps are devtools-only; caching them would roughly double the
        // installed size for no offline benefit.
        ...Object.keys(bundle).filter((name) => !name.endsWith('.map')),
        ...publicFiles.map((file) => file.path),
      ];

      // Chunk filenames are content-hashed, so their names alone track changes.
      // Public files are not, so fold their contents in — otherwise editing an
      // icon or the manifest would leave every installed client on the old copy.
      const fingerprint = createHash('sha256');
      for (const name of [...new Set(precache)].sort()) fingerprint.update(name);
      for (const file of publicFiles) fingerprint.update(file.hash);
      const buildId = fingerprint.digest('hex').slice(0, 12);

      const source = readFileSync(resolve(here, 'src/service-worker.js'), 'utf8')
        .replace(/__PRECACHE__/g, JSON.stringify([...new Set(precache)].sort(), null, 2))
        .replace(/__BUILD_ID__/g, buildId);

      this.emitFile({ type: 'asset', fileName: 'sw.js', source });
    },
  };
}

/** Every file under `dir`, as scope-relative POSIX paths plus a content hash. */
function listFiles(dir: string, prefix = ''): { path: string; hash: string }[] {
  const out: { path: string; hash: string }[] = [];
  for (const name of readdirSync(dir)) {
    const absolute = join(dir, name);
    const relative = prefix ? `${prefix}/${name}` : name;
    if (statSync(absolute).isDirectory()) {
      out.push(...listFiles(absolute, relative));
    } else {
      out.push({
        path: relative,
        hash: createHash('sha256').update(readFileSync(absolute)).digest('hex'),
      });
    }
  }
  return out;
}

export default defineConfig({
  // Pinned to this file's directory so the server behaves identically no
  // matter which directory it is launched from.
  root: here,
  // Relative asset URLs, so a built Keyhole runs from any path it is served at
  // rather than only from a domain root.
  base: './',
  plugins: [react(), offlineShell()],
  server: {
    /**
     * 5173 is a convenience default, not a requirement — Keyhole has no OAuth
     * redirect, webhook, or fixed-origin CORS rule tied to a port, and
     * `localhost` is a secure context (which WebCrypto needs) on any port.
     *
     * So honour PORT when a supervisor assigns one, and do not use strictPort:
     * failing outright on a busy port buys nothing here and produces a confusing
     * "port in use" crash instead of just moving over.
     */
    port: Number(process.env['PORT']) || 5173,
    // Local-first: never expose the dev server beyond this machine.
    host: '127.0.0.1',
    strictPort: false,
  },
  /**
   * `npm run app` serves the built app from here. This is the mode that matters
   * for installing: a browser will only offer to install, and will only register
   * a service worker, from a secure context — which 127.0.0.1 is, without a
   * certificate.
   */
  preview: {
    port: Number(process.env['PORT']) || 4173,
    host: '127.0.0.1',
    strictPort: false,
  },
  build: {
    outDir: resolve(here, 'dist'),
    target: 'es2022',
    sourcemap: true,
    emptyOutDir: true,
  },
  // The core is consumed as TypeScript source from the workspace, so Vite must
  // transpile it rather than treat it as a pre-built dependency.
  optimizeDeps: { exclude: ['@keyhole/core'] },
});
