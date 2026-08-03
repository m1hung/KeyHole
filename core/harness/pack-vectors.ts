/**
 * Pack vault-format interchange vectors for release.
 *
 * Desktop owns the TypeScript crypto; iOS consumes these sealed fixtures to
 * prove the Swift port still opens what TS wrote.
 *
 *   npm run pack:vectors --workspace @keyhole/core
 *
 * Writes `vectors/` at the repo root (demo vault + MANIFEST.json) and a
 * `vectors/dist/keyhole-vectors-*.tar.gz` release asset.
 */

import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { copyFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { FORMAT_VERSION, SCHEMA_VERSION, VAULT_FORMAT_ID } from '../src/index.ts';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, '../..');
const demoSrc = resolve(repoRoot, 'examples/demo-vault.keyhole.json');
const outDir = resolve(repoRoot, 'vectors');
const distDir = resolve(outDir, 'dist');

const DEMO_MASTER_PASSWORD = 'demo-master-passphrase-2026';

const demoBytes = await readFile(demoSrc);
const demoSha256 = createHash('sha256').update(demoBytes).digest('hex');

const manifest = {
  package: '@keyhole/vectors',
  version: '1.0.0',
  description: 'Sealed vault fixtures for Keyhole TS ↔ Swift format contract tests',
  format: {
    vaultFormatId: VAULT_FORMAT_ID,
    formatVersion: FORMAT_VERSION,
    schemaVersion: SCHEMA_VERSION,
  },
  fixtures: [
    {
      id: 'demo-vault',
      file: 'demo-vault.keyhole.json',
      masterPassword: DEMO_MASTER_PASSWORD,
      sha256: demoSha256,
      notes:
        'Fabricated entries on RFC 2606 reserved domains. Published master password — intended to be opened.',
    },
  ],
  consumers: {
    ios: 'Copy fixtures into Tests/KeyholeCoreTests/Fixtures/ (see scripts/sync-vectors.sh)',
    typescript: 'examples/demo-vault.keyhole.json is the canonical checked-in copy',
  },
};

await mkdir(outDir, { recursive: true });
await mkdir(distDir, { recursive: true });
await copyFile(demoSrc, resolve(outDir, 'demo-vault.keyhole.json'));
await writeFile(resolve(outDir, 'MANIFEST.json'), `${JSON.stringify(manifest, null, 2)}\n`);

const archiveName = `keyhole-vectors-${manifest.version}.tar.gz`;
const archivePath = resolve(distDir, archiveName);
const tar = spawnSync(
  'tar',
  ['-czf', archivePath, '-C', outDir, 'MANIFEST.json', 'demo-vault.keyhole.json'],
  { encoding: 'utf8' },
);
if (tar.status !== 0) {
  throw new Error(`tar failed: ${tar.stderr || tar.stdout}`);
}

console.log(`Wrote ${outDir}/MANIFEST.json`);
console.log(`Wrote ${outDir}/demo-vault.keyhole.json`);
console.log(`Wrote ${archivePath}`);
console.log(`demo sha256: ${demoSha256}`);
