/**
 * HTTP client for the Keyhole sync server.
 */

import { assertKdfParamsAcceptable, type KdfParams, type VaultFile } from '@keyhole/core';

export interface SyncConfig {
  baseUrl: string;
  accountId: string;
}

function authHeader(accountId: string, syncAuthSecretB64: string): string {
  // Prefer TextEncoder over string-concat + btoa: secrets are ASCII base64, but
  // this path stays correct if an account id ever contains non-Latin1 bytes.
  const raw = new TextEncoder().encode(`${accountId}:${syncAuthSecretB64}`);
  let binary = '';
  for (const byte of raw) binary += String.fromCharCode(byte);
  return `Basic ${btoa(binary)}`;
}

async function parseJson(res: Response): Promise<unknown> {
  const text = await res.text();
  if (text.length === 0) return null;
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw new SyncClientError('Server returned invalid JSON.', res.status);
  }
}

export class SyncClientError extends Error {
  readonly status: number;
  readonly code: string | undefined;

  constructor(message: string, status: number, code?: string) {
    super(message);
    this.name = 'SyncClientError';
    this.status = status;
    this.code = code;
  }
}

export async function healthCheck(baseUrl: string): Promise<boolean> {
  try {
    const res = await fetch(`${baseUrl.replace(/\/+$/, '')}/api/v1/health`);
    if (!res.ok) return false;
    const body = (await parseJson(res)) as { ok?: boolean } | null;
    return body?.ok === true;
  } catch {
    return false;
  }
}

export async function fetchPrelogin(baseUrl: string, accountId: string): Promise<{ kdf: KdfParams }> {
  const url = new URL('/api/v1/prelogin', baseUrl.replace(/\/+$/, ''));
  url.searchParams.set('account', accountId);
  const res = await fetch(url);
  const body = (await parseJson(res)) as { kdf?: KdfParams; error?: string } | null;
  if (!res.ok) {
    throw new SyncClientError(body?.error ?? 'Prelogin failed.', res.status);
  }
  if (!body?.kdf) {
    throw new SyncClientError('Prelogin response missing KDF parameters.', res.status);
  }
  assertKdfParamsAcceptable(body.kdf);
  return { kdf: body.kdf };
}

export interface RegisterResult {
  accountId: string;
  version: number;
  updatedAt: string;
}

export async function registerAccount(
  baseUrl: string,
  accountId: string,
  authSecretB64: string,
  envelope: VaultFile,
): Promise<RegisterResult> {
  const res = await fetch(`${baseUrl.replace(/\/+$/, '')}/api/v1/account`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ accountId, authSecret: authSecretB64, envelope }),
  });
  const body = (await parseJson(res)) as RegisterResult & { error?: string };
  if (res.status === 409) {
    throw new SyncClientError(body.error ?? 'That account already exists.', res.status);
  }
  if (!res.ok) {
    throw new SyncClientError(body.error ?? 'Registration failed.', res.status);
  }
  return body;
}

export interface VaultRemote {
  envelope: VaultFile;
  version: number;
  updatedAt: string;
}

export async function getVault(
  baseUrl: string,
  accountId: string,
  syncAuthSecretB64: string,
): Promise<VaultRemote> {
  const res = await fetch(`${baseUrl.replace(/\/+$/, '')}/api/v1/vault`, {
    headers: { Authorization: authHeader(accountId, syncAuthSecretB64) },
  });
  const body = (await parseJson(res)) as VaultRemote & { error?: string };
  if (res.status === 429) {
    throw new SyncClientError(body?.error ?? 'Too many attempts. Try again shortly.', res.status);
  }
  if (res.status === 401) {
    throw new SyncClientError(
      'Unauthorized — wrong master password for this account, or the account was registered from a different vault. Use Register & upload on first enroll, or import that vault into this device.',
      res.status,
    );
  }
  if (!res.ok) {
    throw new SyncClientError(body?.error ?? 'Could not fetch vault.', res.status);
  }
  if (!body.envelope || typeof body.version !== 'number') {
    throw new SyncClientError('Vault response missing envelope or version.', res.status);
  }
  return { envelope: body.envelope, version: body.version, updatedAt: body.updatedAt };
}

export interface PutVaultResult {
  version: number;
  updatedAt: string;
}

export interface PutVaultConflict {
  conflict: true;
  version: number;
  envelope: VaultFile;
  updatedAt: string;
}

export type PutVaultResponse = { conflict: false; result: PutVaultResult } | PutVaultConflict;

export async function putVault(
  baseUrl: string,
  accountId: string,
  syncAuthSecretB64: string,
  envelope: VaultFile,
  expectedVersion: number,
  /** When replacing with a different vault, rotate the account verifier to this secret. */
  nextAuthSecretB64?: string,
): Promise<PutVaultResponse> {
  const res = await fetch(`${baseUrl.replace(/\/+$/, '')}/api/v1/vault`, {
    method: 'PUT',
    headers: {
      Authorization: authHeader(accountId, syncAuthSecretB64),
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      envelope,
      expectedVersion,
      ...(nextAuthSecretB64 ? { authSecret: nextAuthSecretB64 } : {}),
    }),
  });
  const body = (await parseJson(res)) as PutVaultResult &
    PutVaultConflict & { error?: string; envelope?: VaultFile; version?: number; updatedAt?: string };

  if (res.status === 409 && body.envelope && typeof body.version === 'number') {
    return {
      conflict: true,
      version: body.version,
      envelope: body.envelope,
      updatedAt: body.updatedAt ?? '',
    };
  }
  if (res.status === 429) {
    throw new SyncClientError(body.error ?? 'Too many attempts. Try again shortly.', res.status);
  }
  if (res.status === 401) {
    throw new SyncClientError(
      'Unauthorized — wrong master password for this account, or the account was registered from a different vault.',
      res.status,
    );
  }
  if (!res.ok) {
    throw new SyncClientError(body.error ?? 'Upload failed.', res.status);
  }
  return { conflict: false, result: { version: body.version, updatedAt: body.updatedAt } };
}
