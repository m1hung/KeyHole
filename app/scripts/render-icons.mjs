/**
 * Regenerate app/public/icons/icon-512.png from the brand mark.
 *
 * It is the single raster this repo builds from: both Electron packages stage
 * their icons from it (desktop/scripts/stage.mjs, server-tray/scripts/bundle.mjs).
 * The 192px, maskable and apple-touch variants went with the installable web
 * build — they existed for the web manifest that referenced them.
 *
 * Usage: npm run icons -w @keyhole/app
 *
 * Why this rasterises the mark by hand instead of shelling out to a library:
 * the mark is four primitives (rounded rect, circle, trapezoid, and a cutout),
 * Node ships zlib, and PNG's uncompressed-scanline path is ~40 lines. Adding a
 * native image dependency to the *app* workspace to redraw four shapes would be
 * a worse trade — and the app is the one workspace whose dependency list users
 * are most likely to audit. The extension keeps its sharp-based script; this is
 * deliberately independent of it.
 *
 * Geometry is transcribed from docs/brand/logo-mark.svg (64×64 viewBox). If the
 * mark changes there, change it here too.
 */

import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { deflateSync } from 'node:zlib';

const outDir = join(dirname(fileURLToPath(import.meta.url)), '..', 'public', 'icons');

/**
 * Both colours come from app/src/styles.css. The icon is drawn opaque rather
 * than with a transparent keyhole: an installed app icon gets composited onto
 * unknown backgrounds (taskbar, dock, launcher, splash screen), and a see-through
 * cutout dissolves the mark against half of them.
 */
const BG = [0x0d, 0x11, 0x17]; // --bg, dark
const FG = [0x4d, 0x9f, 0xff]; // --accent, dark

// --------------------------------------------------------------------------
// Mark geometry, in the 64-unit space of logo-mark.svg
// --------------------------------------------------------------------------

const RECT_INSET = 4;
const RECT_SIDE = 56;
const RECT_RADIUS = 15;

/** Trapezoid of the keyhole's shaft: "M28.5 30.5 24 48h16l-4.5-17.5Z". */
const SHAFT = [
  [28.5, 30.5],
  [24, 48],
  [40, 48],
  [35.5, 30.5],
];

function inRoundedRect(x, y) {
  const min = RECT_INSET;
  const max = RECT_INSET + RECT_SIDE;
  if (x < min || x > max || y < min || y > max) return false;
  // Clamp to the rectangle of corner-arc centres; inside iff within one radius
  // of the nearest such centre. Degenerates correctly along the flat edges.
  const cx = Math.min(Math.max(x, min + RECT_RADIUS), max - RECT_RADIUS);
  const cy = Math.min(Math.max(y, min + RECT_RADIUS), max - RECT_RADIUS);
  const dx = x - cx;
  const dy = y - cy;
  return dx * dx + dy * dy <= RECT_RADIUS * RECT_RADIUS;
}

function inBow(x, y) {
  const dx = x - 32;
  const dy = y - 25;
  return dx * dx + dy * dy <= 8 * 8;
}

function inShaft(x, y) {
  let negative = false;
  let positive = false;
  for (let i = 0; i < SHAFT.length; i += 1) {
    const [ax, ay] = SHAFT[i];
    const [bx, by] = SHAFT[(i + 1) % SHAFT.length];
    const cross = (bx - ax) * (y - ay) - (by - ay) * (x - ax);
    if (cross < 0) negative = true;
    if (cross > 0) positive = true;
  }
  // Convex polygon: inside iff every edge sees the point on the same side.
  return !(negative && positive);
}

function inMark(x, y) {
  return inRoundedRect(x, y) && !inBow(x, y) && !inShaft(x, y);
}

// --------------------------------------------------------------------------
// Rasteriser
// --------------------------------------------------------------------------

/** Samples per axis. 4× (16 per pixel) is enough to hide stair-stepping at 192px. */
const SUPERSAMPLE = 4;

/**
 * @param size   output edge length in pixels
 * @param extent how much of that edge the 64-unit mark spans (1 = full bleed)
 */
function render(size, extent) {
  const span = size * extent;
  const offset = (size - span) / 2;
  const step = 1 / SUPERSAMPLE;
  const rgba = Buffer.alloc(size * size * 4);

  for (let py = 0; py < size; py += 1) {
    for (let px = 0; px < size; px += 1) {
      let hits = 0;
      for (let sy = 0; sy < SUPERSAMPLE; sy += 1) {
        for (let sx = 0; sx < SUPERSAMPLE; sx += 1) {
          const u = ((px + (sx + 0.5) * step - offset) / span) * 64;
          const v = ((py + (sy + 0.5) * step - offset) / span) * 64;
          if (u >= 0 && u <= 64 && v >= 0 && v <= 64 && inMark(u, v)) hits += 1;
        }
      }
      const coverage = hits / (SUPERSAMPLE * SUPERSAMPLE);
      const i = (py * size + px) * 4;
      for (let ch = 0; ch < 3; ch += 1) {
        rgba[i + ch] = Math.round(BG[ch] + (FG[ch] - BG[ch]) * coverage);
      }
      rgba[i + 3] = 255;
    }
  }
  return rgba;
}

// --------------------------------------------------------------------------
// Minimal PNG encoder (8-bit RGBA, no filtering)
// --------------------------------------------------------------------------

const CRC_TABLE = (() => {
  const table = new Int32Array(256);
  for (let n = 0; n < 256; n += 1) {
    let c = n;
    for (let k = 0; k < 8; k += 1) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c;
  }
  return table;
})();

function crc32(buf) {
  let c = -1;
  for (let i = 0; i < buf.length; i += 1) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ -1) >>> 0;
}

function chunk(type, data) {
  const out = Buffer.alloc(data.length + 12);
  out.writeUInt32BE(data.length, 0);
  out.write(type, 4, 'ascii');
  data.copy(out, 8);
  out.writeUInt32BE(crc32(out.subarray(4, 8 + data.length)), 8 + data.length);
  return out;
}

function encodePng(size, rgba) {
  const stride = size * 4;
  const raw = Buffer.alloc((stride + 1) * size);
  for (let y = 0; y < size; y += 1) {
    raw[y * (stride + 1)] = 0; // filter type: none
    rgba.copy(raw, y * (stride + 1) + 1, y * stride, (y + 1) * stride);
  }

  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 6; // colour type: truecolour with alpha
  // bytes 10–12 stay zero: deflate, adaptive filtering, no interlace

  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr),
    chunk('IDAT', deflateSync(raw, { level: 9 })),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

// --------------------------------------------------------------------------

/** `extent: 1` keeps the SVG's own 4/64 inset and bleeds to the edge. */
const TARGETS = [{ file: 'icon-512.png', size: 512, extent: 1 }];

mkdirSync(outDir, { recursive: true });

for (const { file, size, extent } of TARGETS) {
  const png = encodePng(size, render(size, extent));
  const dest = join(outDir, file);
  writeFileSync(dest, png);
  console.log(`wrote ${dest} (${png.length} bytes)`);
}
