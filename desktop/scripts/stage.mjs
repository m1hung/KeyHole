/**
 * Copy the built renderer from app/dist into desktop/renderer, and the app icon
 * into desktop/build for electron-builder.
 *
 * Why stage instead of pointing Electron at ../app/dist directly: electron-builder
 * resolves `files` globs relative to the package being built, and reaching up
 * out of a workspace to pull in a sibling's build output is where monorepo
 * packaging reliably goes wrong. One copy step buys a self-contained package
 * directory that behaves identically unpacked (dev) and inside the asar (built).
 *
 * The service worker is deliberately dropped: `app://` is not registered with
 * `allowServiceWorkers`, so sw.js could not register anyway, and shipping an
 * offline shell inside an app that is already offline would be dead weight that
 * looks like a caching layer to anyone auditing this.
 */

import { cp, mkdir, rm, readdir } from 'node:fs/promises';
import { basename, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const source = resolve(here, '..', '..', 'app', 'dist');
const target = resolve(here, '..', 'renderer');

const EXCLUDED = new Set(['sw.js', 'manifest.webmanifest']);

let built;
try {
  built = await readdir(source);
} catch {
  console.error(`No renderer build at ${source}.\nRun: npm run build --workspace @keyhole/app`);
  process.exit(1);
}

if (!built.includes('index.html')) {
  console.error(`${source} exists but has no index.html — is the app build complete?`);
  process.exit(1);
}

await rm(target, { recursive: true, force: true });
await mkdir(target, { recursive: true });

await cp(source, target, {
  recursive: true,
  filter: (src) => {
    const name = basename(src);
    // Source maps roughly triple the package size and are devtools-only.
    if (name.endsWith('.map')) return false;
    return !EXCLUDED.has(name);
  },
});

const staged = await readdir(target);
console.log(`Staged ${staged.length} entries into desktop/renderer`);

/**
 * electron-builder wants its icon under buildResources. Taken from the app's
 * generated icon set rather than kept as a fourth committed copy of the mark —
 * `npm run icons -w @keyhole/app` remains the single place it is produced.
 */
const iconSource = resolve(here, '..', '..', 'app', 'public', 'icons', 'icon-512.png');
const iconTarget = resolve(here, '..', 'build', 'icon.png');
await mkdir(dirname(iconTarget), { recursive: true });
try {
  await cp(iconSource, iconTarget);
  console.log('Staged build/icon.png from the app icon set');
} catch {
  console.error(`Missing ${iconSource}. Run: npm run icons -w @keyhole/app`);
  process.exit(1);
}
