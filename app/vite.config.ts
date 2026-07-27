import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

const here = dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  // Pinned to this file's directory so the server behaves identically no
  // matter which directory it is launched from.
  root: here,
  // Relative asset URLs, so a built Keyhole runs from any path it is loaded
  // from — including the desktop build's app:// scheme, which has no host.
  base: './',
  plugins: [react()],
  /**
   * The dev server exists to develop this renderer, which the desktop build
   * ships. Keyhole is not served to browsers as a product, so there is no
   * preview server and nothing here is a deployment target.
   */
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
