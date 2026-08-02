/**
 * Format-2 vaults: Secret Key binding and the Recovery Kit.
 *
 * The invariant this file exists to defend is not "the crypto works" — it is
 * "nobody is ever locked out of a vault they still hold the credentials for".
 * Every test below is a way that could happen.
 */

import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { beforeAll, describe, expect, it } from 'vitest';

import {
  changeMasterPassword,
  createEntry,
  createVault,
  recoverWithKit,
  saveVault,
  unlockVault,
  unlockWithRecoveryCode,
  upgradeToV2,
  vaultHasRecoveryKit,
  vaultRequiresSecretKey,
  type RecoveryKit,
} from '../src/vault.ts';
import { deriveSyncAuthSecret, defaultKdfParams } from '../src/crypto.ts';
import { parseSecret } from '../src/secret-key.ts';
import { DecryptionError, ValidationError, VaultFormatError } from '../src/errors.ts';
import type { VaultFile } from '../src/types.ts';

const PASSWORD = 'correct horse battery staple';
const NEW_PASSWORD = 'a different sufficiently long password';

const DEMO_PATH = resolve(dirname(fileURLToPath(import.meta.url)), '../../examples/demo-vault.keyhole.json');
const DEMO_PASSWORD = 'demo-master-passphrase-2026';

/** A v2 vault holding one entry, so "did the data survive?" is answerable. */
async function makeV2(): Promise<{ file: VaultFile; kit: RecoveryKit }> {
  const created = await createVault(PASSWORD, { formatVersion: 2 });
  const { data } = createEntry(created.session.data, { title: 'GitHub', password: 'hunter2' });
  created.session.data = data;
  const file = await saveVault(created.session, created.file);
  return { file, kit: created.kit! };
}

// ---------------------------------------------------------------------------

describe('format 1 still works', () => {
  it('opens the committed demo vault with the password alone', async () => {
    const demo = JSON.parse(await readFile(DEMO_PATH, 'utf8')) as VaultFile;
    expect(demo.formatVersion).toBe(1);

    const session = await unlockVault(demo, DEMO_PASSWORD);
    expect(session.data.entries.length).toBeGreaterThan(0);
  });

  it('is what createVault writes by default', async () => {
    const { file, kit } = await createVault(PASSWORD);
    expect(file.formatVersion).toBe(1);
    expect(kit).toBeNull();
    expect(vaultRequiresSecretKey(file)).toBe(false);
    expect(vaultHasRecoveryKit(file)).toBe(false);
    await expect(unlockVault(file, PASSWORD)).resolves.toBeDefined();
  });

  it('refuses a Secret Key it has no use for, rather than ignoring it', async () => {
    const { file } = await createVault(PASSWORD);
    const { kit } = await makeV2();
    await expect(unlockVault(file, PASSWORD, kit.secretKey)).rejects.toThrow(/does not use a Secret Key/);
  });
});

describe('format 2 unlock', () => {
  let file: VaultFile;
  let kit: RecoveryKit;

  beforeAll(async () => {
    ({ file, kit } = await makeV2());
  });

  it('writes a Secret Key-bound envelope carrying a Recovery Kit', () => {
    expect(file.formatVersion).toBe(2);
    expect(vaultRequiresSecretKey(file)).toBe(true);
    expect(vaultHasRecoveryKit(file)).toBe(true);
    expect(kit.secretKey).toMatch(/^KH2SK-/);
    expect(kit.recoveryCode).toMatch(/^KH2RC-/);
  });

  it('opens with the password and the Secret Key', async () => {
    const session = await unlockVault(file, PASSWORD, kit.secretKey);
    expect(session.data.entries[0]?.password).toBe('hunter2');
  });

  it('accepts the Secret Key as raw bytes as well as a typed string', async () => {
    await expect(unlockVault(file, PASSWORD, parseSecret('secret-key', kit.secretKey))).resolves.toBeDefined();
  });

  it('does not consume a caller-supplied key buffer', async () => {
    // Regression: zeroizing the caller's array made every unlock after the first
    // fail, and only on the paths that pass bytes rather than a string.
    const bytes = parseSecret('secret-key', kit.secretKey);
    await unlockVault(file, PASSWORD, bytes);
    await expect(unlockVault(file, PASSWORD, bytes)).resolves.toBeDefined();
  });

  it('says the Secret Key is missing instead of blaming the password', async () => {
    // The whole reason this check runs before the KDF: otherwise a user with a
    // perfectly correct password is told their password is wrong.
    await expect(unlockVault(file, PASSWORD)).rejects.toThrow(ValidationError);
    await expect(unlockVault(file, PASSWORD)).rejects.toThrow(/needs its Secret Key/);
  });

  it('refuses a correct password with the wrong Secret Key', async () => {
    const other = await makeV2();
    await expect(unlockVault(file, PASSWORD, other.kit.secretKey)).rejects.toThrow(DecryptionError);
  });

  it('refuses the correct Secret Key with the wrong password', async () => {
    await expect(unlockVault(file, 'not the master password', kit.secretKey)).rejects.toThrow(DecryptionError);
  });

  it('rejects a typo in the Secret Key as a typo', async () => {
    const typo = kit.secretKey.slice(0, -1) + (kit.secretKey.endsWith('0') ? '9' : '0');
    await expect(unlockVault(file, PASSWORD, typo)).rejects.toThrow(/typo/);
  });
});

describe('recovery', () => {
  it('opens a vault with the Recovery Code alone', async () => {
    const { file, kit } = await makeV2();
    const session = await unlockWithRecoveryCode(file, kit.recoveryCode);
    expect(session.data.entries[0]?.password).toBe('hunter2');
  });

  it('refuses a Recovery Code from another vault', async () => {
    const { file } = await makeV2();
    const other = await makeV2();
    await expect(unlockWithRecoveryCode(file, other.kit.recoveryCode)).rejects.toThrow(DecryptionError);
  });

  it('says so plainly when no kit was ever issued', async () => {
    const { file, kit } = await createVault(PASSWORD);
    expect(kit).toBeNull();
    await expect(unlockWithRecoveryCode(file, 'KH2RC-0000-0000-0000-0000-0000-0000-0000')).rejects.toThrow(
      /No Recovery Kit/,
    );
  });

  it('restores a vault whose master password is gone, and reissues the kit', async () => {
    const { file, kit } = await makeV2();

    const recovered = await recoverWithKit(file, kit.recoveryCode, NEW_PASSWORD);
    expect(recovered.session.data.entries[0]?.password).toBe('hunter2');

    // The new credentials work...
    await expect(unlockVault(recovered.file, NEW_PASSWORD, recovered.kit.secretKey)).resolves.toBeDefined();
    // ...and the ones that were just replaced do not.
    await expect(unlockVault(recovered.file, PASSWORD, kit.secretKey)).rejects.toThrow(DecryptionError);
    await expect(unlockWithRecoveryCode(recovered.file, kit.recoveryCode)).rejects.toThrow(DecryptionError);
    expect(recovered.kit.secretKey).not.toBe(kit.secretKey);
  });
});

describe('changing the master password keeps the Recovery Kit honest', () => {
  // The bug this guards against is silent: the vault keeps working perfectly and
  // only the recovery path is dead, so nothing surfaces it until the one moment
  // the user has nothing else left to try.
  let original: { file: VaultFile; kit: RecoveryKit };
  let changed: { file: VaultFile; kit: RecoveryKit | null };

  beforeAll(async () => {
    original = await makeV2();
    changed = await changeMasterPassword(original.file, PASSWORD, NEW_PASSWORD, {
      secretKey: original.kit.secretKey,
    });
  });

  it('issues a replacement kit', () => {
    expect(changed.kit).not.toBeNull();
    expect(changed.kit!.recoveryCode).not.toBe(original.kit.recoveryCode);
  });

  it('leaves the OLD Recovery Code unable to open the vault', async () => {
    await expect(unlockWithRecoveryCode(changed.file, original.kit.recoveryCode)).rejects.toThrow(DecryptionError);
  });

  it('leaves the NEW Recovery Code able to open it', async () => {
    const session = await unlockWithRecoveryCode(changed.file, changed.kit!.recoveryCode);
    expect(session.data.entries[0]?.password).toBe('hunter2');
  });

  it('keeps the Secret Key, which is a device factor and not a password', () => {
    expect(changed.kit!.secretKey).toBe(original.kit.secretKey);
  });

  it('keeps the entries and the envelope version', async () => {
    expect(changed.file.formatVersion).toBe(2);
    const session = await unlockVault(changed.file, NEW_PASSWORD, original.kit.secretKey);
    expect(session.data.entries[0]?.title).toBe('GitHub');
  });

  it('still rotates the VEK, so the pre-change envelope is a dead snapshot', () => {
    expect(changed.file.wrappedKey.ctB64).not.toBe(original.file.wrappedKey.ctB64);
    expect(changed.file.payload.ctB64).not.toBe(original.file.payload.ctB64);
  });
});

describe('upgrading a format-1 vault', () => {
  it('binds it to a new Secret Key and keeps the entries', async () => {
    const created = await createVault(PASSWORD);
    const { data } = createEntry(created.session.data, { title: 'Bank', password: 'swordfish' });
    created.session.data = data;
    const v1 = await saveVault(created.session, created.file);

    const upgraded = await upgradeToV2(v1, PASSWORD);
    expect(upgraded.file.formatVersion).toBe(2);
    expect(vaultHasRecoveryKit(upgraded.file)).toBe(true);

    const session = await unlockVault(upgraded.file, PASSWORD, upgraded.kit.secretKey);
    expect(session.data.entries[0]?.password).toBe('swordfish');
    await expect(unlockVault(upgraded.file, PASSWORD)).rejects.toThrow(/needs its Secret Key/);
  });

  it('rotates the VEK so a stolen pre-upgrade copy does not follow the vault forward', async () => {
    const { file: v1 } = await createVault(PASSWORD);
    const upgraded = await upgradeToV2(v1, PASSWORD);
    // Same vault id, but nothing about the old envelope opens the new one.
    expect(upgraded.file.vaultId).toBe(v1.vaultId);
    expect(upgraded.file.wrappedKey.ctB64).not.toBe(v1.wrappedKey.ctB64);
    expect(upgraded.file.payload.ctB64).not.toBe(v1.payload.ctB64);
  });

  it('refuses to upgrade a vault that is already bound', async () => {
    const { file } = await makeV2();
    await expect(upgradeToV2(file, PASSWORD)).rejects.toThrow(/already uses a Secret Key/);
  });
});

describe('tampering', () => {
  it('refuses a v2 envelope downgraded to v1 rather than accepting weaker derivation', async () => {
    const { file } = await makeV2();
    // Strip the kit too, so the envelope is *shape*-valid as a v1 file and the only
    // thing left to reject it is the authenticated header.
    const { recoveryKdf: _kdf, recoveryWrappedKey: _blob, ...rest } = file;
    const downgraded = { ...rest, formatVersion: 1 } as VaultFile;

    await expect(unlockVault(downgraded, PASSWORD)).rejects.toThrow(DecryptionError);
  });

  it('rejects a v1 envelope carrying a Recovery Kit', async () => {
    const { file } = await makeV2();
    await expect(unlockVault({ ...file, formatVersion: 1 }, PASSWORD)).rejects.toThrow(VaultFormatError);
  });

  it('rejects half a Recovery Kit', async () => {
    const { file } = await makeV2();
    const { recoveryWrappedKey: _dropped, ...half } = file;
    await expect(unlockVault(half, PASSWORD, 'x')).rejects.toThrow(/incomplete Recovery Kit/);
  });

  it('refuses a wrappedKey spliced in from another v2 vault', async () => {
    const a = await makeV2();
    const b = await makeV2();
    const spliced = { ...a.file, wrappedKey: b.file.wrappedKey };
    await expect(unlockVault(spliced, PASSWORD, b.kit.secretKey)).rejects.toThrow(DecryptionError);
  });
});

describe('cross-implementation vectors', () => {
  // One format, two independent implementations. These are the only tests on this
  // side that would notice them drifting apart. The Swift half of the pair lives in
  // ios/Tests/KeyholeCoreTests/VaultV2Tests.swift and opens a TypeScript-written
  // vault; this one goes the other way.
  //
  // Regenerate with:
  //   KEYHOLE_WRITE_VECTORS=1 swift test --filter testEmitSwiftVector
  //
  // If a regeneration is ever needed to make an *existing* build pass, that is a
  // compatibility break, not a stale fixture.
  const FIXTURE = resolve(dirname(fileURLToPath(import.meta.url)), 'fixtures/swift-v2-vault.json');

  interface Vector {
    masterPassword: string;
    secretKey: string;
    recoveryCode: string;
    entryPassword: string;
    vault: VaultFile;
  }

  async function loadVector(): Promise<Vector> {
    return JSON.parse(await readFile(FIXTURE, 'utf8')) as Vector;
  }

  it('opens a format-2 vault written by Swift', async () => {
    const vector = await loadVector();
    expect(vector.vault.formatVersion).toBe(2);

    const session = await unlockVault(vector.vault, vector.masterPassword, vector.secretKey);
    expect(session.data.entries[0]?.password).toBe(vector.entryPassword);
    expect(session.data.entries[0]?.username).toBe('vector@example.com');
  });

  it('recovers a format-2 vault written by Swift', async () => {
    // Exercises the recovery wrap, its separate KDF params and its AAD template —
    // none of which the unlock path touches.
    const vector = await loadVector();
    const session = await unlockWithRecoveryCode(vector.vault, vector.recoveryCode);
    expect(session.data.entries[0]?.password).toBe(vector.entryPassword);
  });

  it('rejects the Swift vault without its Secret Key', async () => {
    const vector = await loadVector();
    await expect(unlockVault(vector.vault, vector.masterPassword)).rejects.toThrow(/needs its Secret Key/);
  });
});

describe('sync credentials', () => {
  it('are bound to the Secret Key, so a stolen password alone cannot write to the server', async () => {
    const kdf = { ...defaultKdfParams('interactive'), memoryKiB: 16 * 1024, iterations: 2 };
    const secretKey = parseSecret('secret-key', (await makeV2()).kit.secretKey);

    const unbound = await deriveSyncAuthSecret(PASSWORD, kdf);
    const bound = await deriveSyncAuthSecret(PASSWORD, kdf, secretKey);
    expect(bound).not.toBe(unbound);

    // Still deterministic — a device must reproduce it on every unlock.
    expect(await deriveSyncAuthSecret(PASSWORD, kdf, secretKey)).toBe(bound);
  });
});
