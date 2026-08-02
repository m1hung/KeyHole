/**
 * Generate iOS brand assets from the same geometry as app/scripts/render-icons.mjs
 * (docs/brand/logo-mark.svg).
 *
 * Writes:
 *  - AppIcon.png (1024) — azure fills the icon; keyhole cutout matches desktop mark
 *  - KeyholeMark.png (512) — white mark on transparent for template tinting
 */

import { writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { deflateSync } from 'node:zlib';

const here = dirname(fileURLToPath(import.meta.url));
const assets = join(here, '../KeyholeApp/Resources/Assets.xcassets');

const BG = [0x0d, 0x11, 0x17];
const FG = [0x4d, 0x9f, 0xff];
const WHITE = [0xff, 0xff, 0xff];

const RECT_INSET = 4;
const RECT_SIDE = 56;
const RECT_RADIUS = 15;
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
  return !(negative && positive);
}

function inMark(x, y) {
  return inRoundedRect(x, y) && !inBow(x, y) && !inShaft(x, y);
}

const SUPERSAMPLE = 4;

/**
 * @param {'padded' | 'fullBleed'} mode
 *   padded — full 64×64 SVG viewBox (in-app mark)
 *   fullBleed — azure fills the canvas; only the keyhole cutout shows the dark bg
 */
function render(size, { foreground, background, transparentOutside = false, mode = 'padded' }) {
  const step = 1 / SUPERSAMPLE;
  const rgba = Buffer.alloc(size * size * 4);

  for (let py = 0; py < size; py += 1) {
    for (let px = 0; px < size; px += 1) {
      let hits = 0;
      for (let sy = 0; sy < SUPERSAMPLE; sy += 1) {
        for (let sx = 0; sx < SUPERSAMPLE; sx += 1) {
          const nx = (px + (sx + 0.5) * step) / size;
          const ny = (py + (sy + 0.5) * step) / size;
          let u;
          let v;
          if (mode === 'fullBleed') {
            // Map the canvas onto the mark’s inner rect so the keyhole stays
            // proportioned, then treat every pixel as “inside” the plate.
            u = RECT_INSET + nx * RECT_SIDE;
            v = RECT_INSET + ny * RECT_SIDE;
            if (!inBow(u, v) && !inShaft(u, v)) hits += 1;
          } else {
            u = nx * 64;
            v = ny * 64;
            if (u >= 0 && u <= 64 && v >= 0 && v <= 64 && inMark(u, v)) hits += 1;
          }
        }
      }
      const coverage = hits / (SUPERSAMPLE * SUPERSAMPLE);
      const i = (py * size + px) * 4;
      if (transparentOutside) {
        for (let ch = 0; ch < 3; ch += 1) rgba[i + ch] = foreground[ch];
        rgba[i + 3] = Math.round(255 * coverage);
      } else {
        for (let ch = 0; ch < 3; ch += 1) {
          rgba[i + ch] = Math.round(background[ch] + (foreground[ch] - background[ch]) * coverage);
        }
        rgba[i + 3] = 255;
      }
    }
  }
  return rgba;
}

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
    raw[y * (stride + 1)] = 0;
    rgba.copy(raw, y * (stride + 1) + 1, y * stride, (y + 1) * stride);
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8;
  ihdr[9] = 6;
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr),
    chunk('IDAT', deflateSync(raw, { level: 9 })),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

const appIcon = encodePng(
  1024,
  render(1024, { foreground: FG, background: BG, mode: 'fullBleed' }),
);
const mark = encodePng(
  512,
  render(512, { foreground: WHITE, background: BG, transparentOutside: true, mode: 'padded' }),
);

const appIconPath = join(assets, 'AppIcon.appiconset/AppIcon.png');
const markPath = join(assets, 'KeyholeMark.imageset/KeyholeMark.png');
writeFileSync(appIconPath, appIcon);
writeFileSync(markPath, mark);
console.log(`wrote ${appIconPath} (${appIcon.length} bytes)`);
console.log(`wrote ${markPath} (${mark.length} bytes)`);
