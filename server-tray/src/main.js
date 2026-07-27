/**
 * Keyhole sync server, as a one-click Windows tray app.
 *
 * Double-click the .exe → the server starts and a tray icon appears. No console
 * window, no command line, no Node installation required (the child runs on the
 * Node that Electron already bundles).
 *
 * Three decisions that are load-bearing:
 *
 *  1. **The server runs as a child process, not in this one.** `server/src/index.ts`
 *     calls `process.exit(1)` when it cannot bind a port, and Fastify's error
 *     paths assume they own the process. In-process, a failed start would take
 *     the tray down with it — leaving a user with an .exe that vanishes on
 *     double-click and no way to see why. Out-of-process, a crash is a status
 *     line and a Restart button.
 *
 *  2. **The bind address is forced to 127.0.0.1 here**, overriding whatever is in
 *     the environment. The server's own default is `0.0.0.0` (sensible for a
 *     deliberate deployment behind a firewall), but a thing you launch by
 *     double-clicking must not quietly publish a password-sync service to every
 *     network you join. Exposing it on a LAN should be an explicit act, not the
 *     consequence of a default.
 *
 *  3. **The database path is pinned to userData**, never the working directory.
 *     `KEYHOLE_DB` defaults to `./data/keyhole.sqlite`, relative to cwd — and the
 *     cwd of a double-clicked executable is wherever Explorer happened to be.
 *     Left alone, launching from two different folders silently produces two
 *     different, empty databases and looks exactly like losing every account.
 */

import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { mkdir } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { app, clipboard, dialog, Menu, nativeImage, shell, Tray } from 'electron';

const here = dirname(fileURLToPath(import.meta.url));

app.setName('Keyhole Sync Server');

/** Loopback only. See the header — this is deliberately not configurable here. */
const HOST = '127.0.0.1';
const PORT = Number(process.env['KEYHOLE_PORT']) || 8787;
const BASE_URL = `http://${HOST}:${PORT}`;

/**
 * The bundled server, emitted by scripts/bundle.mjs and kept OUTSIDE the asar
 * (see electron-builder.yml) so the child launches an ordinary file on disk with
 * no archive semantics in play.
 */
function serverEntrypoint() {
  const packaged = join(process.resourcesPath ?? '', 'server-dist', 'keyhole-server.mjs');
  if (app.isPackaged && existsSync(packaged)) return packaged;
  return resolve(here, '..', 'server-dist', 'keyhole-server.mjs');
}

function databasePath() {
  return join(app.getPath('userData'), 'data', 'keyhole.sqlite');
}

// ---------------------------------------------------------------------------
// Server lifecycle
// ---------------------------------------------------------------------------

/** @type {import('node:child_process').ChildProcess | null} */
let child = null;
/** @type {'stopped' | 'starting' | 'running' | 'crashed'} */
let status = 'stopped';
/** @type {string | null} */
let lastError = null;
/** @type {Tray | null} */
let tray = null;

async function startServer() {
  if (child) return;

  const entry = serverEntrypoint();
  if (!existsSync(entry)) {
    status = 'crashed';
    lastError = 'Server bundle missing. Run: npm run bundle -w @keyhole/server-tray';
    refreshTray();
    return;
  }

  status = 'starting';
  lastError = null;
  refreshTray();

  const db = databasePath();
  await mkdir(dirname(db), { recursive: true });

  child = spawn(
    process.execPath,
    [entry],
    {
      env: {
        ...process.env,
        // Run Electron's binary as a plain Node process.
        ELECTRON_RUN_AS_NODE: '1',
        KEYHOLE_HOST: HOST,
        KEYHOLE_PORT: String(PORT),
        KEYHOLE_DB: db,
      },
      // No console window on Windows; output is piped to us instead.
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    },
  );

  child.stdout?.on('data', (chunk) => {
    const text = String(chunk);
    // Fastify's own ready log is the only reliable "actually listening" signal.
    if (text.includes('Server listening at') || text.includes('Keyhole sync listening')) {
      status = 'running';
      refreshTray();
    }
  });

  child.stderr?.on('data', (chunk) => {
    lastError = String(chunk).trim().split('\n').slice(-1)[0] ?? null;
  });

  child.on('exit', (code, signal) => {
    child = null;
    // A signal means we asked it to stop; a non-zero code means it fell over.
    status = signal !== null || code === 0 ? 'stopped' : 'crashed';
    if (status === 'crashed' && !lastError) lastError = `Server exited with code ${code}.`;
    refreshTray();
  });

  child.on('error', (err) => {
    child = null;
    status = 'crashed';
    lastError = err.message;
    refreshTray();
  });
}

function stopServer() {
  if (!child) return;
  status = 'stopped';
  const doomed = child;
  child = null;
  // The server installs SIGTERM/SIGINT handlers that close Fastify cleanly, but
  // Windows does not deliver POSIX signals — kill() terminates it outright, which
  // is safe here because every write is committed synchronously by SQLite.
  doomed.kill();
  refreshTray();
}

async function restartServer() {
  stopServer();
  // Give the listener a moment to release the port before rebinding.
  await new Promise((r) => setTimeout(r, 400));
  await startServer();
}

// ---------------------------------------------------------------------------
// Tray
// ---------------------------------------------------------------------------

function statusLabel() {
  switch (status) {
    case 'running':
      return `Running — ${BASE_URL}`;
    case 'starting':
      return 'Starting…';
    case 'crashed':
      return `Stopped (error)${lastError ? `: ${lastError.slice(0, 60)}` : ''}`;
    default:
      return 'Stopped';
  }
}

function refreshTray() {
  if (!tray) return;

  const running = status === 'running' || status === 'starting';

  tray.setToolTip(`Keyhole Sync Server — ${status === 'running' ? BASE_URL : status}`);
  tray.setContextMenu(
    Menu.buildFromTemplate([
      { label: statusLabel(), enabled: false },
      { type: 'separator' },
      {
        label: 'Open status page',
        enabled: status === 'running',
        click: () => void shell.openExternal(BASE_URL),
      },
      {
        label: 'Copy server URL',
        enabled: status === 'running',
        click: () => clipboard.writeText(BASE_URL),
      },
      { type: 'separator' },
      { label: 'Start', enabled: !running, click: () => void startServer() },
      { label: 'Stop', enabled: running, click: () => stopServer() },
      { label: 'Restart', enabled: running, click: () => void restartServer() },
      { type: 'separator' },
      {
        label: 'Show data folder',
        click: () => void shell.openPath(join(app.getPath('userData'), 'data')),
      },
      {
        label: 'About',
        click: () => {
          void dialog.showMessageBox({
            type: 'info',
            title: 'Keyhole Sync Server',
            message: 'Keyhole Sync Server',
            detail: [
              `Address:  ${BASE_URL}`,
              'Binding:  127.0.0.1 only — not reachable from other machines.',
              '',
              `Database: ${databasePath()}`,
              '',
              'The server stores only encrypted vault envelopes. It cannot read',
              'your passwords: decryption happens in the Keyhole app, never here.',
            ].join('\n'),
          });
        },
      },
      { type: 'separator' },
      { label: 'Quit', click: () => app.quit() },
    ]),
  );
}

function createTray() {
  const iconPath = join(here, '..', 'build', 'tray.png');
  let image = nativeImage.createFromPath(iconPath);
  if (image.isEmpty()) {
    // A tray app with no icon is an invisible app. Fall back to something
    // clickable rather than starting a process the user cannot see or stop.
    image = nativeImage.createEmpty();
  }
  tray = new Tray(image.resize({ width: 16, height: 16 }));
  // Left-click opens the same menu as right-click; on Windows a tray icon with
  // no primary action reads as broken.
  tray.on('click', () => tray?.popUpContextMenu());
  refreshTray();
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

/** Two instances would fight over port 8787 and the same SQLite file. */
if (!app.requestSingleInstanceLock()) {
  app.quit();
} else {
  app.whenReady().then(async () => {
    createTray();
    // One click means it is running when the icon appears — no second step.
    await startServer();
  });

  // This app has no windows at all; the default "quit when none are open" rule
  // would terminate it the instant it started.
  app.on('window-all-closed', () => {});

  app.on('before-quit', () => stopServer());
}
