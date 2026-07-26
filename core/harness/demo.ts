/**
 * End-to-end proof harness.
 *
 * Runs the exact lifecycle from the spec against the real crypto — no mocks,
 * no stubs — and prints what is actually stored on disk so the "zero-knowledge"
 * claim can be inspected rather than taken on trust.
 *
 *   npm run demo
 */

import {
  changeMasterPassword,
  createEntry,
  createVault,
  estimateStrength,
  findMatchingEntries,
  generatePassword,
  generateTotp,
  saveVault,
  searchEntries,
  unlockVault,
  updateEntry,
  type VaultFile,
} from '../src/index.ts';
import { DecryptionError } from '../src/errors.ts';

const MASTER_PASSWORD = 'correct horse battery staple';
const WRONG_PASSWORD = 'correct horse battery stapl3';

let step = 0;
const pass = (msg: string) => console.log(`  \x1b[32m✓\x1b[0m ${msg}`);
const info = (msg: string) => console.log(`    \x1b[90m${msg}\x1b[0m`);
const heading = (msg: string) => console.log(`\n\x1b[1m${++step}. ${msg}\x1b[0m`);

function assert(condition: boolean, message: string): asserts condition {
  if (!condition) {
    console.error(`\n\x1b[31m✗ FAILED: ${message}\x1b[0m`);
    process.exit(1);
  }
}

async function main(): Promise<void> {
  console.log('\n\x1b[1m\x1b[36mKeyhole — core crypto end-to-end proof\x1b[0m');
  console.log('\x1b[90mArgon2id (hash-wasm) + AES-256-GCM (WebCrypto)\x1b[0m');

  // -------------------------------------------------------------------------
  heading('Create vault');
  const t0 = performance.now();
  const created = await createVault(MASTER_PASSWORD);
  const kdfMs = performance.now() - t0;
  let file: VaultFile = created.file;
  const session = created.session;

  pass(`vault created in ${kdfMs.toFixed(0)} ms (dominated by Argon2id)`);
  info(`vaultId    ${file.vaultId}`);
  info(`kdf        argon2id m=${file.kdf.memoryKiB / 1024} MiB t=${file.kdf.iterations} p=${file.kdf.parallelism}`);
  info(`salt       ${file.kdf.saltB64} (128-bit, random, not secret)`);

  // -------------------------------------------------------------------------
  heading('Add entries');
  const generated = generatePassword({
    length: 20,
    lowercase: true,
    uppercase: true,
    digits: true,
    symbols: true,
    excludeAmbiguous: false,
  });
  const strength = estimateStrength(generated);

  let data = createEntry(session.data, {
    title: 'GitHub',
    username: 'octocat',
    password: generated,
    urls: ['https://github.com/login'],
    tags: ['dev'],
    notes: 'Recovery codes stored offline.',
    // RFC 6238 test seed — fake, published in the RFC, safe to commit.
    totpSecret: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',
  }).data;
  data = createEntry(data, {
    title: 'Example Bank',
    username: 'jdoe@example.com',
    password: 'Tr0ub4dor&3-but-longer',
    urls: ['https://bank.example.com'],
    tags: ['finance'],
  }).data;
  session.data = data;

  pass(`added ${data.entries.length} entries`);
  info(`generated password: ${generated}`);
  info(`strength: ${strength.bits} bits (${strength.label}) — offline crack ${strength.crackTimeDisplay}`);

  // -------------------------------------------------------------------------
  heading('Save (encrypt) and inspect what lands on disk');
  file = await saveVault(session, file);
  const onDisk = JSON.stringify(file);

  pass(`envelope is ${onDisk.length} bytes of JSON`);
  info(`payload iv  ${file.payload.ivB64} (96-bit, fresh per save)`);
  info(`payload ct  ${file.payload.ctB64.slice(0, 56)}… (+128-bit GCM tag)`);

  const mustNotAppear = [MASTER_PASSWORD, generated, 'octocat', 'GitHub', 'jdoe@example.com', 'Recovery codes'];
  for (const secret of mustNotAppear) {
    assert(!onDisk.includes(secret), `plaintext "${secret}" leaked into the vault file`);
  }
  pass('no plaintext found in the envelope (checked master password, secrets, usernames, titles, notes)');

  // -------------------------------------------------------------------------
  heading('Lock');
  // "Locking" is simply discarding the session. Only `file` survives below.
  const lockedFile: VaultFile = JSON.parse(JSON.stringify(file)) as VaultFile;
  pass('session dropped; only the encrypted envelope remains');

  // -------------------------------------------------------------------------
  heading('Unlock with the WRONG password');
  const wrongResult = await unlockVault(lockedFile, WRONG_PASSWORD).catch((e: unknown) => e);
  assert(wrongResult instanceof DecryptionError, 'wrong password did not produce a DecryptionError');
  pass('rejected — GCM tag verification failed');
  info(`error: ${(wrongResult as Error).message}`);
  info('no partial plaintext was produced (fail closed)');

  // -------------------------------------------------------------------------
  heading('Unlock with the CORRECT password and read entries back');
  const reopened = await unlockVault(lockedFile, MASTER_PASSWORD);
  assert(reopened.data.entries.length === 2, 'entry count changed across the round trip');

  const github = reopened.data.entries.find((e) => e.title === 'GitHub');
  assert(github !== undefined, 'GitHub entry missing after unlock');
  assert(github.password === generated, 'password did not survive the round trip');
  assert(github.username === 'octocat', 'username did not survive the round trip');
  assert(github.notes === 'Recovery codes stored offline.', 'notes did not survive the round trip');

  pass('unlocked and verified');
  info(`title      ${github.title}`);
  info(`username   ${github.username}`);
  info(`password   ${github.password}  ← byte-identical to what we stored`);
  info(`notes      ${github.notes}`);

  // -------------------------------------------------------------------------
  heading('Derived features on the unlocked vault');
  const totp = await generateTotp(github.totpSecret!);
  pass(`TOTP code ${totp.code} (${totp.secondsRemaining}s remaining)`);

  const found = searchEntries(reopened.data, 'git');
  assert(found.length === 1 && found[0]!.title === 'GitHub', 'search returned the wrong result');
  pass(`search "git" → ${found.map((e) => e.title).join(', ')}`);

  const matches = findMatchingEntries(reopened.data.entries, 'https://github.com/session');
  assert(matches.length === 1, 'autofill matching returned the wrong number of entries');
  pass(`autofill match for github.com → ${matches[0]!.entry.title} (${matches[0]!.strength})`);

  const spoofed = findMatchingEntries(reopened.data.entries, 'https://github.com.evil.com/login');
  assert(spoofed.length === 0, 'lookalike domain matched — credential theft bug');
  pass('autofill match for github.com.evil.com → none (lookalike rejected)');

  // -------------------------------------------------------------------------
  heading('Edit an entry and persist');
  reopened.data = updateEntry(reopened.data, github.id, { password: 'rotated-password-value' });
  file = await saveVault(reopened, lockedFile);
  const afterEdit = await unlockVault(file, MASTER_PASSWORD);
  assert(afterEdit.data.entries.find((e) => e.id === github.id)?.password === 'rotated-password-value', 'edit lost');
  pass('edit persisted and re-read correctly');

  // -------------------------------------------------------------------------
  heading('Change master password');
  const NEW_PASSWORD = 'an-entirely-different-master-passphrase';
  const rekeyed = await changeMasterPassword(file, MASTER_PASSWORD, NEW_PASSWORD);

  assert(rekeyed.file.kdf.saltB64 !== file.kdf.saltB64, 'salt was not rotated');
  assert(rekeyed.file.wrappedKey.ctB64 !== file.wrappedKey.ctB64, 'wrapped key was not rotated');
  assert(rekeyed.file.payload.ctB64 !== file.payload.ctB64, 'payload was not re-encrypted');

  const oldResult = await unlockVault(rekeyed.file, MASTER_PASSWORD).catch((e: unknown) => e);
  assert(oldResult instanceof DecryptionError, 'old master password still works');

  const withNew = await unlockVault(rekeyed.file, NEW_PASSWORD);
  assert(withNew.data.entries.length === 2, 'entries lost during re-key');
  pass('salt, wrapped key and payload all rotated');
  pass('old password rejected; new password works; all entries preserved');

  // -------------------------------------------------------------------------
  heading('Tamper detection');
  const cases: Array<[string, VaultFile]> = [
    ['flipped a ciphertext byte', mutate(rekeyed.file, (f) => (f.payload.ctB64 = flipB64(f.payload.ctB64)))],
    ['downgraded KDF cost to m=1 MiB', mutate(rekeyed.file, (f) => (f.kdf.memoryKiB = 1024))],
    ['swapped the vault id', mutate(rekeyed.file, (f) => (f.vaultId = '00000000-0000-4000-8000-000000000000'))],
  ];
  for (const [label, tampered] of cases) {
    const result = await unlockVault(tampered, NEW_PASSWORD).catch((e: unknown) => e);
    assert(result instanceof Error, `tamper case "${label}" was accepted`);
    pass(`${label} → rejected (${result.constructor.name})`);
  }

  console.log('\n\x1b[1m\x1b[32mAll checks passed.\x1b[0m\n');
}

function mutate(file: VaultFile, fn: (f: VaultFile) => void): VaultFile {
  const copy = JSON.parse(JSON.stringify(file)) as VaultFile;
  fn(copy);
  return copy;
}

function flipB64(b64: string): string {
  const bytes = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  bytes[0] = (bytes[0] ?? 0) ^ 0xff;
  return btoa(String.fromCharCode(...bytes));
}

main().catch((err: unknown) => {
  console.error('\n\x1b[31mHarness crashed:\x1b[0m', err);
  process.exit(1);
});
