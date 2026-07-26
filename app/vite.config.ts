import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

const here = dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  // Pinned to this file's directory so the server behaves identically no
  // matter which directory it is launched from.
  root: here,
  plugins: [react()],
  server: {
    port: 5173,
    // Local-first: never expose the dev server beyond this machine.
    host: '127.0.0.1',
    strictPort: true,
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
