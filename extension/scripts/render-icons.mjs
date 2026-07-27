/**
 * Regenerate extension toolbar PNGs from docs/brand/logo-mark.svg.
 *
 * Usage: npm run icons -w extension
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import sharp from 'sharp';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const repoRoot = join(root, '..');
const outDir = join(root, 'icons');

/** App accent — light theme azure from app/src/styles.css */
const ACCENT = '#0f62d0';

const mark = readFileSync(join(repoRoot, 'docs/brand/logo-mark.svg'), 'utf8').replace(
  /fill="currentColor"/g,
  `fill="${ACCENT}"`,
);

async function render(size) {
  // Source mark is 64×64; scale to the toolbar size.
  const svg = mark
    .replace(/width="64"/, `width="${size}"`)
    .replace(/height="64"/, `height="${size}"`);

  const png = await sharp(Buffer.from(svg)).resize(size, size).png().toBuffer();
  const dest = join(outDir, `icon-${size}.png`);
  writeFileSync(dest, png);
  console.log(`wrote ${dest} (${png.length} bytes)`);
}

for (const size of [16, 32, 48, 128]) {
  await render(size);
}
