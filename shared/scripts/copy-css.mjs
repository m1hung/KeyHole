import { copyFile, mkdir } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const src = resolve(here, '../src/styles.css');
const dest = resolve(here, '../dist/styles.css');
await mkdir(dirname(dest), { recursive: true });
await copyFile(src, dest);
console.log('copied styles.css → dist/styles.css');
