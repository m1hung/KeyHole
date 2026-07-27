/**
 * Import helpers for migrating from other password managers into an unlocked vault.
 *
 * These parsers produce EntryInput / folder names only — they never touch keys or
 * the encrypted envelope. The caller folds results through createFolder/createEntry.
 */

import type { EntryInput } from './vault.ts';
import { ValidationError } from './errors.ts';

export interface MigratedFolder {
  /** Stable id from the source format when available (Bitwarden). */
  sourceId?: string;
  name: string;
}

export interface MigratedEntry extends EntryInput {
  /** Source folder id (Bitwarden) or folder name (CSV) when present. */
  sourceFolderId?: string | null;
  sourceFolderName?: string | null;
}

export interface MigrationResult {
  folders: MigratedFolder[];
  entries: MigratedEntry[];
  format: 'bitwarden-json' | 'csv';
  warnings: string[];
}

/** Detect format and parse. Throws ValidationError on empty / unusable input. */
export function parseMigrationPayload(text: string, filenameHint = ''): MigrationResult {
  const trimmed = text.replace(/^\uFEFF/, '').trim();
  if (trimmed.length === 0) throw new ValidationError('Import file is empty.');

  const lower = filenameHint.toLowerCase();
  // Prefer explicit extension, then JSON shape — CSV heuristics can match
  // stringified Bitwarden JSON (commas + "name" on the first line).
  if (lower.endsWith('.csv')) return parseCsvMigration(trimmed);
  if (lower.endsWith('.json') || trimmed.startsWith('{') || trimmed.startsWith('[')) {
    return parseBitwardenJson(trimmed);
  }
  if (looksLikeCsv(trimmed)) return parseCsvMigration(trimmed);
  throw new ValidationError('Unrecognized import format. Use a .csv or .json export.');
}

function looksLikeCsv(text: string): boolean {
  const first = text.split(/\r?\n/, 1)[0]?.toLowerCase() ?? '';
  return (
    first.includes(',') &&
    (/name|title|url|username|password|login_/.test(first) || first.includes('"'))
  );
}

// ---------------------------------------------------------------------------
// Bitwarden unencrypted JSON
// ---------------------------------------------------------------------------

export function parseBitwardenJson(text: string): MigrationResult {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    throw new ValidationError('The .json file could not be parsed.');
  }

  if (!raw || typeof raw !== 'object') throw new ValidationError('The .json file must contain an object at its root.');
  const root = raw as Record<string, unknown>;
  if (root['encrypted'] === true) {
    throw new ValidationError('Encrypted exports are not supported. Export again without a password.');
  }

  const warnings: string[] = [];
  const folders: MigratedFolder[] = [];
  const folderRows = Array.isArray(root['folders']) ? root['folders'] : [];
  for (const row of folderRows) {
    if (!row || typeof row !== 'object') continue;
    const f = row as Record<string, unknown>;
    const name = typeof f['name'] === 'string' ? f['name'].trim() : '';
    if (!name) continue;
    folders.push({
      name,
      ...(typeof f['id'] === 'string' ? { sourceId: f['id'] } : {}),
    });
  }

  const entries: MigratedEntry[] = [];
  const items = Array.isArray(root['items']) ? root['items'] : Array.isArray(root) ? root : [];
  if (!Array.isArray(root['items']) && !Array.isArray(root)) {
    warnings.push('No items array found; nothing was imported.');
  }

  for (const item of items) {
    if (!item || typeof item !== 'object') continue;
    const row = item as Record<string, unknown>;
    const type = typeof row['type'] === 'number' ? row['type'] : 1;
    const name = typeof row['name'] === 'string' ? row['name'].trim() : '';
    if (!name) continue;

    // Bitwarden: 1=login, 2=secure note, 3=card, 4=identity — we take login + note.
    if (type === 3 || type === 4) {
      warnings.push(`Skipped unsupported item “${name}” (card/identity).`);
      continue;
    }

    const notes = typeof row['notes'] === 'string' ? row['notes'] : '';
    const folderId = typeof row['folderId'] === 'string' ? row['folderId'] : null;

    if (type === 2 || !row['login']) {
      entries.push({
        title: name,
        kind: 'note',
        notes,
        sourceFolderId: folderId,
      });
      continue;
    }

    const login = row['login'] as Record<string, unknown>;
    const urls: string[] = [];
    const uris = Array.isArray(login['uris']) ? login['uris'] : [];
    for (const u of uris) {
      if (u && typeof u === 'object' && typeof (u as Record<string, unknown>)['uri'] === 'string') {
        urls.push((u as Record<string, unknown>)['uri'] as string);
      }
    }

    let totpSecret: string | null = null;
    if (typeof login['totp'] === 'string' && login['totp'].length > 0) {
      totpSecret = login['totp'];
    }

    entries.push({
      title: name,
      kind: 'login',
      username: typeof login['username'] === 'string' ? login['username'] : '',
      password: typeof login['password'] === 'string' ? login['password'] : '',
      urls,
      notes,
      totpSecret,
      sourceFolderId: folderId,
    });
  }

  return { folders, entries, format: 'bitwarden-json', warnings };
}

// ---------------------------------------------------------------------------
// CSV (Bitwarden / Chrome / generic)
// ---------------------------------------------------------------------------

export function parseCsvMigration(text: string): MigrationResult {
  const rows = parseCsv(text);
  if (rows.length < 2) throw new ValidationError('CSV must include a header row and at least one entry.');

  const header = rows[0]!.map((h) => h.trim().toLowerCase());
  const col = (...names: string[]) => {
    for (const name of names) {
      const i = header.indexOf(name);
      if (i >= 0) return i;
    }
    return -1;
  };

  const iName = col('name', 'title', 'login_name');
  const iUrl = col('url', 'login_uri', 'login url', 'website');
  const iUser = col('username', 'login_username', 'login username', 'user');
  const iPass = col('password', 'login_password', 'login password');
  const iNotes = col('notes', 'note');
  const iTotp = col('totp', 'login_totp', 'otpauth');
  const iFolder = col('folder', 'folders');
  const iType = col('type');

  if (iName < 0 && iUrl < 0 && iUser < 0) {
    throw new ValidationError('CSV header must include name/title, url, or username.');
  }

  const folderNames = new Set<string>();
  const entries: MigratedEntry[] = [];
  const warnings: string[] = [];

  for (let r = 1; r < rows.length; r++) {
    const row = rows[r]!;
    if (row.every((c) => c.trim().length === 0)) continue;

    const typeRaw = iType >= 0 ? (row[iType] ?? '').trim().toLowerCase() : 'login';
    const name = (iName >= 0 ? row[iName] : '')?.trim() || (iUrl >= 0 ? row[iUrl]?.trim() : '') || 'Imported entry';
    const folderName = iFolder >= 0 ? (row[iFolder] ?? '').trim() : '';
    if (folderName) folderNames.add(folderName);

    if (typeRaw === 'note' || typeRaw === 'secure note') {
      entries.push({
        title: name,
        kind: 'note',
        notes: iNotes >= 0 ? (row[iNotes] ?? '') : '',
        sourceFolderName: folderName || null,
      });
      continue;
    }

    if (typeRaw && typeRaw !== 'login' && typeRaw !== 'password') {
      warnings.push(`Skipped CSV row “${name}” (type ${typeRaw}).`);
      continue;
    }

    const url = iUrl >= 0 ? (row[iUrl] ?? '').trim() : '';
    const totp = iTotp >= 0 ? (row[iTotp] ?? '').trim() : '';
    entries.push({
      title: name,
      kind: 'login',
      username: iUser >= 0 ? (row[iUser] ?? '') : '',
      password: iPass >= 0 ? (row[iPass] ?? '') : '',
      urls: url ? [url] : [],
      notes: iNotes >= 0 ? (row[iNotes] ?? '') : '',
      totpSecret: totp.length > 0 ? totp : null,
      sourceFolderName: folderName || null,
    });
  }

  return {
    folders: [...folderNames].map((name) => ({ name })),
    entries,
    format: 'csv',
    warnings,
  };
}

/** Minimal RFC4180-ish CSV parser (quoted fields, commas, newlines). */
export function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let cell = '';
  let i = 0;
  let inQuotes = false;

  while (i < text.length) {
    const ch = text[i]!;
    if (inQuotes) {
      if (ch === '"') {
        if (text[i + 1] === '"') {
          cell += '"';
          i += 2;
          continue;
        }
        inQuotes = false;
        i += 1;
        continue;
      }
      cell += ch;
      i += 1;
      continue;
    }
    if (ch === '"') {
      inQuotes = true;
      i += 1;
      continue;
    }
    if (ch === ',') {
      row.push(cell);
      cell = '';
      i += 1;
      continue;
    }
    if (ch === '\n' || ch === '\r') {
      if (ch === '\r' && text[i + 1] === '\n') i += 1;
      row.push(cell);
      cell = '';
      if (row.some((c) => c.length > 0) || rows.length === 0) rows.push(row);
      row = [];
      i += 1;
      continue;
    }
    cell += ch;
    i += 1;
  }
  row.push(cell);
  if (row.some((c) => c.length > 0) || rows.length === 0) rows.push(row);
  return rows;
}

/**
 * Apply a migration into vault data via the provided mutators.
 * Returns how many folders/entries were created.
 */
export function applyMigration(
  data: import('./types.ts').VaultData,
  migration: MigrationResult,
  deps: {
    createFolder: (
      data: import('./types.ts').VaultData,
      name: string,
    ) => { data: import('./types.ts').VaultData; folder: import('./types.ts').Folder };
    createEntry: (
      data: import('./types.ts').VaultData,
      input: EntryInput,
    ) => { data: import('./types.ts').VaultData; entry: import('./types.ts').Entry };
  },
): { data: import('./types.ts').VaultData; folderCount: number; entryCount: number } {
  let next = data;
  const folderIdBySource = new Map<string, string>();
  const folderIdByName = new Map<string, string>();
  let folderCount = 0;
  let entryCount = 0;

  for (const existing of next.folders) {
    folderIdByName.set(existing.name.toLowerCase(), existing.id);
  }

  for (const folder of migration.folders) {
    const key = folder.name.toLowerCase();
    let id = folderIdByName.get(key);
    if (!id) {
      const created = deps.createFolder(next, folder.name);
      next = created.data;
      id = created.folder.id;
      folderIdByName.set(key, id);
      folderCount += 1;
    }
    if (folder.sourceId) folderIdBySource.set(folder.sourceId, id);
  }

  for (const entry of migration.entries) {
    let folderId: string | null = null;
    if (entry.sourceFolderId && folderIdBySource.has(entry.sourceFolderId)) {
      folderId = folderIdBySource.get(entry.sourceFolderId)!;
    } else if (entry.sourceFolderName) {
      folderId = folderIdByName.get(entry.sourceFolderName.toLowerCase()) ?? null;
    }

    const { sourceFolderId: _a, sourceFolderName: _b, ...input } = entry;
    const created = deps.createEntry(next, { ...input, folderId });
    next = created.data;
    entryCount += 1;
  }

  return { data: next, folderCount, entryCount };
}
