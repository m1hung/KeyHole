/**
 * Regenerates `examples/demo-vault.keyhole.json`.
 *
 * Every credential inside is fabricated and points at RFC 2606 / RFC 6761
 * reserved example domains. The master password is published in the README on
 * purpose — this file exists to be opened by anyone evaluating Keyhole.
 *
 *   npm run demo:vault --workspace @keyhole/core
 */

import { mkdir, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createEntry, createVault, saveVault, updateSettings } from '../src/index.ts';

const DEMO_MASTER_PASSWORD = 'demo-master-passphrase-2026';

const here = dirname(fileURLToPath(import.meta.url));
const outPath = resolve(here, '../../examples/demo-vault.keyhole.json');

const { file, session } = await createVault(DEMO_MASTER_PASSWORD);

let data = session.data;
data = updateSettings(data, { autoLockMinutes: 15, clipboardClearSeconds: 30 });

const demoEntries = [
  {
    title: 'GitHub',
    username: 'octocat@example.com',
    password: 'k9#Wq2$mZx7!vRn4Lp8T',
    urls: ['https://github.com/login'],
    tags: ['dev'],
    notes: 'Fake entry. Recovery codes would live here.',
    // RFC 6238 Appendix B test seed — published in the RFC, not a real secret.
    totpSecret: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',
  },
  {
    title: 'Example Bank',
    username: 'j.doe@example.com',
    password: 'Tq4!nB8@wE2#kM6$zY9x',
    urls: ['https://bank.example.com', 'https://secure.bank.example.com'],
    tags: ['finance'],
    notes: 'Fake entry for demo purposes.',
  },
  {
    title: 'Example Mail',
    username: 'j.doe@example.net',
    password: 'Hv7$rL3!pQ9@sD5#tN2w',
    urls: ['https://mail.example.net'],
    tags: ['personal'],
  },
  {
    title: 'Staging server (SSH)',
    username: 'deploy',
    password: 'Xm2@kR8!wT5#nB4$qL7v',
    urls: ['https://staging.example.org'],
    tags: ['dev', 'infra'],
    notes: 'Fake entry. Never store real production credentials in a demo file.',
  },
  {
    title: 'Weak password (for the strength meter)',
    username: 'test@example.com',
    password: 'password123',
    urls: ['https://shop.example.com'],
    tags: ['demo'],
    notes: 'Deliberately weak so the strength meter has something to complain about.',
  },
];

for (const entry of demoEntries) {
  data = createEntry(data, entry).data;
}

session.data = data;
const sealed = await saveVault(session, file);

await mkdir(dirname(outPath), { recursive: true });
await writeFile(outPath, JSON.stringify(sealed, null, 2) + '\n');

// Sanity check: the whole point is that nothing readable escapes.
const serialized = JSON.stringify(sealed);
for (const secret of [DEMO_MASTER_PASSWORD, 'octocat@example.com', 'GitHub', 'password123']) {
  if (serialized.includes(secret)) throw new Error(`Demo vault leaked plaintext: ${secret}`);
}

console.log(`Wrote ${outPath}`);
console.log(`  entries         ${data.entries.length}`);
console.log(`  master password ${DEMO_MASTER_PASSWORD}`);
console.log(`  size            ${serialized.length} bytes`);
console.log(`  kdf             argon2id m=${sealed.kdf.memoryKiB / 1024} MiB t=${sealed.kdf.iterations} p=${sealed.kdf.parallelism}`);
console.log('  plaintext leak check: passed');
