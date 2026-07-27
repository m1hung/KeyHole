/**
 * Bundle @keyhole/server into a single JavaScript file the tray app can launch.
 *
 * Why bundle rather than ship the server's source plus node_modules:
 *
 *  - The server is TypeScript run through Node's type stripping. Relying on that
 *    inside a packaged asar adds two failure modes (resolution and stripping) to
 *    a path whose only job is to start.
 *  - It keeps the packaged app free of `node_modules` entirely, which is the same
 *    property the desktop build has and the thing that makes "no dependency of
 *    this app ships" checkable in one command.
 *
 * The output is written outside the asar (see electron-builder.yml) so the child
 * process launches an ordinary file on disk, with no archive semantics involved.
 */

import { cp, rm, mkdir, stat } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';

const here = dirname(fileURLToPath(import.meta.url));
const entry = resolve(here, '..', '..', 'server', 'src', 'index.ts');
const outfile = resolve(here, '..', 'server-dist', 'keyhole-server.mjs');

await rm(resolve(here, '..', 'server-dist'), { recursive: true, force: true });
await mkdir(dirname(outfile), { recursive: true });

const result = await build({
  entryPoints: [entry],
  outfile,
  bundle: true,
  platform: 'node',
  // Electron 43 ships Node 24, so nothing needs downlevelling.
  target: 'node22',
  /**
   * ESM, emitted as `.mjs`.
   *
   * Not a style preference: the server's entrypoint awaits `app.listen()` at the
   * top level, which esbuild cannot express in CommonJS. Emitting ESM keeps the
   * server's real entrypoint as the entrypoint — the alternative was a
   * hand-written boot shim here, i.e. a second copy of the startup sequence that
   * could drift from the one `npm start` uses.
   *
   * The `.mjs` extension makes the module type unambiguous regardless of the
   * nearest package.json's `type` field, which in a packaged app is not ours to
   * predict.
   */
  format: 'esm',
  /**
   * Built into Node, and not something esbuild should try to resolve or inline.
   * `node:sqlite` in particular is the server's whole storage layer.
   */
  external: ['node:sqlite'],
  /**
   * Fastify and avvio are CommonJS and call `require()` at load time. In ESM
   * output esbuild replaces that with a shim that throws — but the shim first
   * checks whether a real `require` is in scope, so defining one here hands it
   * a working implementation instead.
   *
   * Without this the bundle dies on its first import with
   * `Dynamic require of "node:events" is not supported`.
   */
  banner: {
    js: [
      "import { createRequire as __keyholeCreateRequire } from 'node:module';",
      'const require = __keyholeCreateRequire(import.meta.url);',
    ].join('\n'),
  },
  minify: false, // a server you self-host should be readable
  sourcemap: false,
  legalComments: 'none',
  logLevel: 'warning',
  metafile: true,
});

const { size } = await stat(outfile);
const inputs = Object.keys(result.metafile.outputs[Object.keys(result.metafile.outputs)[0]].inputs).length;
console.log(`Bundled ${inputs} modules → server-dist/keyhole-server.mjs (${(size / 1024).toFixed(0)} KB)`);

/**
 * Icons, taken from the app's generated set rather than committed again here.
 * `tray.png` is what sits in the notification area; `icon.png` is what
 * electron-builder embeds in the .exe.
 *
 * Both come from the same 512px source. There used to be a 192px variant to
 * take the tray from, but that existed for the web manifest and went with it —
 * and main.js resizes to 16px before handing it to Tray anyway, so which raster
 * it downsamples from was never load-bearing.
 */
const iconSource = resolve(here, '..', '..', 'app', 'public', 'icons', 'icon-512.png');
const buildDir = resolve(here, '..', 'build');
await mkdir(buildDir, { recursive: true });
try {
  await cp(iconSource, resolve(buildDir, 'tray.png'));
  await cp(iconSource, resolve(buildDir, 'icon.png'));
  console.log('Staged build/tray.png and build/icon.png from the app icon set');
} catch {
  console.error(`Missing ${iconSource}. Run: npm run icons -w @keyhole/app`);
  process.exit(1);
}
