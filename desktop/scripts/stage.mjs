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
 * There used to be an exclusion list here for sw.js and the web manifest. The
 * app build no longer emits either — Keyhole is not an installable web app — so
 * the copy is now unconditional apart from source maps.
 */

import { cp, mkdir, rm, readdir } from 'node:fs/promises';
import { basename, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const source = resolve(here, '..', '..', 'app', 'dist');
const target = resolve(here, '..', 'renderer');

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
  // Source maps roughly triple the package size and are devtools-only.
  filter: (src) => !basename(src).endsWith('.map'),
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
