import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // Node 24 exposes WebCrypto, TextEncoder and btoa/atob as globals, so the
    // core runs unmodified in both Node and the browser. No jsdom needed.
    environment: 'node',
    include: ['test/**/*.test.ts'],
    // Argon2id at production cost plus the 500-entry round trip comfortably
    // exceed vitest's 5s default on slower hardware.
    testTimeout: 30_000,
  },
});
