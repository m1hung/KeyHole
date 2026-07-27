/**
 * Keyhole desktop — Electron main process.
 *
 * This process is the only part of Keyhole with filesystem access, and the
 * renderer is treated as untrusted in the same spirit as the extension's content
 * script: it can ask for exactly seven things (see `preload.cjs`), each of them
 * validated here, and it can reach nothing else.
 *
 * Three decisions worth stating up front, because they are what keep the desktop
 * build honest against the threat model in README.md:
 *
 *  1. **The renderer is served over a custom `app://` scheme, not `file://`.**
 *     `file://` gives every document an opaque origin, which breaks
 *     localStorage/IndexedDB partitioning and makes CORS against the sync server
 *     unpredictable. `app://` is registered as a standard *secure* origin, so
 *     WebCrypto, IndexedDB and the sync fetches all behave exactly as they do on
 *     `https://` — the audited behaviour.
 *
 *  2. **The vault is a real file, written atomically.** `%APPDATA%\Keyhole\
 *     keyhole-vault.keyhole.json` is the single source of truth. A password
 *     manager that half-writes its vault on a power cut is worse than useless,
 *     so every write goes to a temp file and is renamed over the target, with the
 *     previous copy kept as `.bak`.
 *
 *  3. **No plaintext ever reaches this process.** The renderer hands over the
 *     already-encrypted envelope as a JSON string. The master password, derived
 *     keys and decrypted entries never cross the IPC boundary — main could not
 *     leak them if it tried, because it never has them.
 */

import { constants as fsConstants } from 'node:fs';
import { access, copyFile, mkdir, readFile, rename, rm, stat, writeFile } from 'node:fs/promises';
import { dirname, join, normalize, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { app, BrowserWindow, dialog, ipcMain, protocol, shell } from 'electron';

const here = dirname(fileURLToPath(import.meta.url));

/**
 * Must precede any getPath('userData') call — Electron resolves the user-data
 * directory from the app name exactly once, and we want %APPDATA%\Keyhole
 * rather than %APPDATA%\@keyhole-desktop.
 */
app.setName('Keyhole');

/** Where the renderer bundle lives; staged from app/dist by scripts/stage.mjs. */
const RENDERER_DIR = resolve(here, '..', 'renderer');
const APP_ORIGIN = 'app://keyhole';

const VAULT_FILENAME = 'keyhole-vault.keyhole.json';
/**
 * 16 MiB. The extension refuses writes above 9 MB against a 10 MB quota; there
 * is no quota here, but an unbounded write from a compromised renderer should
 * still not be able to fill the disk.
 */
const MAX_VAULT_BYTES = 16 * 1024 * 1024;

function vaultPath() {
  return join(app.getPath('userData'), VAULT_FILENAME);
}

// ---------------------------------------------------------------------------
// Serving the renderer
// ---------------------------------------------------------------------------

/**
 * `secure: true` is the load-bearing flag: without it `app://` is not a secure
 * context, and `crypto.subtle` — every last byte of Keyhole's cryptography — is
 * simply undefined. `corsEnabled` lets the sync client issue cross-origin
 * requests to the self-hosted server; `allowServiceWorkers` is deliberately
 * absent, since the offline shell exists to make a *browser* tab work offline
 * and a packaged binary is already offline by construction.
 */
protocol.registerSchemesAsPrivileged([
  {
    scheme: 'app',
    privileges: { standard: true, secure: true, supportFetchAPI: true, corsEnabled: true, stream: true },
  },
]);

/** @type {Record<string, string>} */
const MIME_TYPES = {
  '.css': 'text/css',
  '.html': 'text/html',
  '.js': 'text/javascript',
  '.json': 'application/json',
  '.map': 'application/json',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
  '.webmanifest': 'application/manifest+json',
  '.woff2': 'font/woff2',
};

/** @param {string} pathname */
function contentTypeFor(pathname) {
  const dot = pathname.lastIndexOf('.');
  const ext = dot === -1 ? '' : pathname.slice(dot).toLowerCase();
  return MIME_TYPES[ext] ?? 'application/octet-stream';
}

/**
 * Resolve a request path inside RENDERER_DIR, or null if it escapes.
 *
 * The renderer is our own build, so this is defence in depth rather than a live
 * threat — but a path-traversal bug in a process that can read the whole disk is
 * exactly the kind of thing that turns a renderer compromise into a total one.
 *
 * @param {string} pathname
 * @returns {string | null}
 */
function resolveRendererFile(pathname) {
  const decoded = decodeURIComponent(pathname);
  const candidate = resolve(RENDERER_DIR, `.${normalize(decoded)}`);
  const rel = relative(RENDERER_DIR, candidate);
  if (rel.startsWith('..') || rel.startsWith(sep) || resolve(rel) === rel) return null;
  return candidate;
}

function registerAppProtocol() {
  protocol.handle('app', async (request) => {
    const url = new URL(request.url);

    // One window, one app: anything not addressed to our host is not ours.
    if (url.host !== 'keyhole') return new Response('Not found', { status: 404 });

    const wanted = url.pathname === '/' ? '/index.html' : url.pathname;
    let file = resolveRendererFile(wanted);
    if (!file) return new Response('Forbidden', { status: 403 });

    try {
      await access(file, fsConstants.R_OK);
    } catch {
      // Single-page app: unknown paths fall back to the shell rather than 404,
      // which keeps the manifest's ?view= shortcuts working.
      file = join(RENDERER_DIR, 'index.html');
    }

    try {
      const body = await readFile(file);
      return new Response(body, {
        status: 200,
        headers: {
          'Content-Type': contentTypeFor(file),
          // The bundle is immutable per build and served from disk; nothing here
          // should ever be revalidated over a network that does not exist.
          'Cache-Control': 'no-cache',
        },
      });
    } catch {
      return new Response('Not found', { status: 404 });
    }
  });
}

// ---------------------------------------------------------------------------
// Vault file IPC
// ---------------------------------------------------------------------------

/**
 * Reject anything that is not a plausible envelope before it touches the disk.
 *
 * Main deliberately does *not* validate the vault schema — `parseVaultFile` in
 * the core owns that, and duplicating it here would create two definitions of
 * "valid" that could drift. This checks only what main is responsible for: type,
 * size, and that the bytes are parseable JSON, so a corrupt write cannot brick
 * the next launch.
 *
 * @param {unknown} json
 * @returns {asserts json is string}
 */
function assertWritableEnvelope(json) {
  if (typeof json !== 'string') throw new Error('Vault payload must be a string.');
  if (json.length === 0) throw new Error('Refusing to write an empty vault.');
  if (Buffer.byteLength(json, 'utf8') > MAX_VAULT_BYTES) {
    throw new Error('Vault exceeds the 16 MB write limit.');
  }
  try {
    JSON.parse(json);
  } catch {
    throw new Error('Vault payload is not valid JSON.');
  }
}

/**
 * Write, then swap. `rename` within a directory is atomic on NTFS, so a reader
 * sees either the whole old file or the whole new one — never a truncated vault.
 * The previous copy survives as `.bak` for one generation.
 *
 * @param {string} json
 */
async function writeVaultAtomically(json) {
  const target = vaultPath();
  const temp = `${target}.tmp`;
  const backup = `${target}.bak`;

  await mkdir(dirname(target), { recursive: true });
  await writeFile(temp, json, { encoding: 'utf8', mode: 0o600 });

  try {
    await copyFile(target, backup);
  } catch {
    // First write — there is nothing to back up yet.
  }

  await rename(temp, target);
}

function registerVaultIpc() {
  ipcMain.handle('vault:read', async () => {
    try {
      return await readFile(vaultPath(), 'utf8');
    } catch (err) {
      if (err instanceof Error && /** @type {NodeJS.ErrnoException} */ (err).code === 'ENOENT') return null;
      throw err;
    }
  });

  ipcMain.handle('vault:write', async (_event, json) => {
    assertWritableEnvelope(json);
    await writeVaultAtomically(json);
    return true;
  });

  ipcMain.handle('vault:clear', async () => {
    // Deleting the vault is the user's explicit, confirmed choice in the UI, but
    // it is still irreversible — so the last copy is kept as `.bak` rather than
    // shredded, matching what every other write here does.
    try {
      await copyFile(vaultPath(), `${vaultPath()}.bak`);
    } catch {
      /* nothing to preserve */
    }
    await rm(vaultPath(), { force: true });
    return true;
  });

  ipcMain.handle('vault:path', () => vaultPath());

  ipcMain.handle('vault:reveal', async () => {
    try {
      await access(vaultPath(), fsConstants.R_OK);
      shell.showItemInFolder(vaultPath());
    } catch {
      // No vault yet — open the folder it will be created in.
      await shell.openPath(app.getPath('userData'));
    }
    return true;
  });

  /** Native open dialog → file contents, for first-run migration and imports. */
  ipcMain.handle('vault:import', async (event) => {
    const window = BrowserWindow.fromWebContents(event.sender);
    /** Modal to the window that asked, so the dialog cannot be lost behind it. */
    const options = {
      title: 'Import Keyhole vault',
      properties: /** @type {const} */ (['openFile']),
      filters: [
        { name: 'Keyhole vault', extensions: ['json'] },
        { name: 'All files', extensions: ['*'] },
      ],
    };
    const result = window
      ? await dialog.showOpenDialog(window, { ...options, properties: [...options.properties] })
      : await dialog.showOpenDialog({ ...options, properties: [...options.properties] });
    if (result.canceled || result.filePaths.length === 0) return null;

    const chosen = result.filePaths[0];
    if (chosen === undefined) return null;
    const info = await stat(chosen);
    if (info.size > MAX_VAULT_BYTES) throw new Error('That file is too large to be a Keyhole vault.');
    return await readFile(chosen, 'utf8');
  });

  /** Native save dialog → write an export where the user asks. */
  ipcMain.handle('vault:export', async (event, json) => {
    assertWritableEnvelope(json);
    const window = BrowserWindow.fromWebContents(event.sender);
    const options = {
      title: 'Export Keyhole vault',
      defaultPath: VAULT_FILENAME,
      filters: [{ name: 'Keyhole vault', extensions: ['json'] }],
    };
    const result = window ? await dialog.showSaveDialog(window, options) : await dialog.showSaveDialog(options);
    if (result.canceled || !result.filePath) return null;
    await writeFile(result.filePath, json, { encoding: 'utf8', mode: 0o600 });
    return result.filePath;
  });
}

// ---------------------------------------------------------------------------
// Window
// ---------------------------------------------------------------------------

function createWindow() {
  const window = new BrowserWindow({
    width: 1100,
    height: 780,
    minWidth: 880,
    minHeight: 600,
    // Matches --bg (dark) in the renderer's stylesheet, so the frame does not
    // flash white before the first paint.
    backgroundColor: '#0d1117',
    autoHideMenuBar: true,
    show: false,
    webPreferences: {
      preload: join(here, 'preload.cjs'),
      // The three flags that keep a renderer compromise from becoming a machine
      // compromise. None of them is optional for a password manager.
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      // Nothing in Keyhole is typed into a dictionary-backed field, and
      // spellcheck ships text to a platform service on some configurations.
      spellcheck: false,
      // Nothing in Keyhole is a <webview>, and leaving it enabled is free
      // attack surface.
      webviewTag: false,
    },
  });

  window.once('ready-to-show', () => window.show());

  /**
   * Navigation lockdown. The renderer should never leave its own origin: any
   * attempt to is either a bug or an attack, and in both cases the right answer
   * is to refuse and hand the URL to the user's real browser instead.
   */
  window.webContents.on('will-navigate', (event, url) => {
    if (!url.startsWith(`${APP_ORIGIN}/`)) {
      event.preventDefault();
      if (url.startsWith('https://')) void shell.openExternal(url);
    }
  });

  window.webContents.setWindowOpenHandler(({ url }) => {
    if (url.startsWith('https://')) void shell.openExternal(url);
    return { action: 'deny' };
  });

  /**
   * Keyhole asks for no OS permissions — no camera, microphone, geolocation or
   * notifications. Denying the lot means a prompt can never be used to phish a
   * user inside an app they trust.
   */
  window.webContents.session.setPermissionRequestHandler((_wc, _permission, callback) => callback(false));

  void window.loadURL(`${APP_ORIGIN}/index.html`);
  return window;
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

/**
 * Two instances would both hold the vault file and race each other's writes,
 * silently discarding one window's edits. Take the lock or hand focus to the
 * copy that already has it.
 */
const gotTheLock = app.requestSingleInstanceLock();

if (!gotTheLock) {
  app.quit();
} else {
  /** @type {BrowserWindow | null} */
  let mainWindow = null;

  app.on('second-instance', () => {
    if (!mainWindow) return;
    if (mainWindow.isMinimized()) mainWindow.restore();
    mainWindow.focus();
  });

  app.whenReady().then(() => {
    registerAppProtocol();
    registerVaultIpc();
    mainWindow = createWindow();

    app.on('activate', () => {
      if (BrowserWindow.getAllWindows().length === 0) mainWindow = createWindow();
    });
  });

  // Windows/Linux: closing the window closes the app — and with it the process
  // holding the unlocked key in memory.
  app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') app.quit();
  });
}
