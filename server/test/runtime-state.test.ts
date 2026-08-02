import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  effectiveAllowRegistration,
  readRuntimeState,
  runtimeStatePath,
  writeRuntimeState,
} from '../src/runtime-state.ts';

let dir: string;
let dbPath: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'keyhole-runtime-state-'));
  dbPath = join(dir, 'keyhole.sqlite');
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

// The security rule, tested directly rather than inferred from process
// behaviour. Both symmetric alternatives fail open in one direction.
describe('effectiveAllowRegistration', () => {
  it('leaves the env value alone when nothing is persisted', () => {
    expect(effectiveAllowRegistration(true, undefined)).toBe(true);
    expect(effectiveAllowRegistration(false, undefined)).toBe(false);
  });

  it('lets a persisted close survive a restart', () => {
    expect(effectiveAllowRegistration(true, false)).toBe(false);
  });

  it('never lets a persisted file reopen what the environment shut', () => {
    expect(effectiveAllowRegistration(false, true)).toBe(false);
  });

  it('stays open when both agree', () => {
    expect(effectiveAllowRegistration(true, true)).toBe(true);
  });
});

describe('runtimeStatePath', () => {
  it('has nowhere to write for an in-memory database', () => {
    expect(runtimeStatePath(':memory:')).toBeUndefined();
  });

  it('sits beside the database', () => {
    expect(runtimeStatePath(dbPath)).toBe(join(dir, 'runtime.json'));
  });
});

describe('read/write', () => {
  it('round-trips', () => {
    expect(writeRuntimeState(dbPath, false)).toBe(true);
    expect(readRuntimeState(dbPath)?.allowRegistration).toBe(false);

    expect(writeRuntimeState(dbPath, true)).toBe(true);
    expect(readRuntimeState(dbPath)?.allowRegistration).toBe(true);
  });

  it('writes 0644 — it holds no secret, unlike the control token', () => {
    writeRuntimeState(dbPath, false);
    expect(statSync(join(dir, 'runtime.json')).mode & 0o777).toBe(0o644);
  });

  it('leaves no temp file behind', () => {
    writeRuntimeState(dbPath, false);
    expect(() => statSync(join(dir, 'runtime.json.tmp'))).toThrow();
  });

  it('is absent, not an error, before anything is written', () => {
    expect(readRuntimeState(dbPath)).toBeUndefined();
  });

  it('does nothing at all for an in-memory database', () => {
    expect(writeRuntimeState(':memory:', false)).toBe(false);
    expect(readRuntimeState(':memory:')).toBeUndefined();
  });

  // A corrupt file must fall back to the environment, not to "closed". With the
  // control plane off, failing closed would leave no in-band way to reopen.
  it('ignores a corrupt file instead of failing closed', () => {
    writeFileSync(join(dir, 'runtime.json'), '{ not json');
    expect(readRuntimeState(dbPath)).toBeUndefined();
    expect(effectiveAllowRegistration(true, readRuntimeState(dbPath)?.allowRegistration)).toBe(true);
  });

  it('ignores a file with a non-boolean allowRegistration', () => {
    writeFileSync(join(dir, 'runtime.json'), JSON.stringify({ allowRegistration: 'false' }));
    expect(readRuntimeState(dbPath)).toBeUndefined();
  });

  it('records when the change was made', () => {
    writeRuntimeState(dbPath, false);
    const raw = JSON.parse(readFileSync(join(dir, 'runtime.json'), 'utf8')) as Record<string, unknown>;
    expect(typeof raw['updatedAt']).toBe('string');
    expect(Date.parse(raw['updatedAt'] as string)).not.toBeNaN();
  });
});
