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
 *  2. **The bind address is decided here, not by the environment.** It is
 *     127.0.0.1 unless you tick "Allow access from other devices" in the tray
 *     menu, which is off until you turn it on and confirm a warning. The server's
 *     own default is `0.0.0.0` (sensible for a deliberate deployment behind a
 *     firewall), but a thing you launch by double-clicking must not quietly
 *     publish a password-sync service to every network you join. `KEYHOLE_HOST`
 *     is still ignored: exposure is a menu tick you can see, not an environment
 *     variable you can forget.
 *
 *  3. **The database path is pinned to userData**, never the working directory.
 *     `KEYHOLE_DB` defaults to `./data/keyhole.sqlite`, relative to cwd — and the
 *     cwd of a double-clicked executable is wherever Explorer happened to be.
 *     Left alone, launching from two different folders silently produces two
 *     different, empty databases and looks exactly like losing every account.
 */

import { spawn } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { mkdir } from 'node:fs/promises';
import { networkInterfaces } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { app, clipboard, dialog, Menu, nativeImage, shell, Tray } from 'electron';

const here = dirname(fileURLToPath(import.meta.url));

app.setName('Keyhole Sync Server');

const LOOPBACK = '127.0.0.1';
const ANY_INTERFACE = '0.0.0.0';
const PORT = Number(process.env['KEYHOLE_PORT']) || 8787;
/** Always reachable from this machine, whichever interface the server is on. */
const LOCAL_URL = `http://${LOOPBACK}:${PORT}`;

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

/**
 * One tick, persisted next to the database. Off means loopback; on means every
 * interface. Deliberately not read from `KEYHOLE_HOST` — see the header.
 */
let allowLan = false;

function settingsPath() {
  return join(app.getPath('userData'), 'settings.json');
}

function loadSettings() {
  try {
    // Strip a BOM: we never write one, but Notepad and PowerShell's
    // `Set-Content -Encoding utf8` do, and JSON.parse rejects it. Without this,
    // hand-editing the file makes the setting silently revert to off.
    const text = readFileSync(settingsPath(), 'utf8').replace(/^\uFEFF/, '');
    const raw = JSON.parse(text);
    allowLan = raw?.allowLan === true;
  } catch {
    // Missing or corrupt settings must not expose the server: the safe value is
    // also the default value, so falling through with allowLan = false is right.
    allowLan = false;
  }
}

function saveSettings() {
  try {
    writeFileSync(settingsPath(), `${JSON.stringify({ allowLan }, null, 2)}\n`, 'utf8');
  } catch (err) {
    lastError = `Could not save settings: ${err instanceof Error ? err.message : String(err)}`;
  }
}

function bindHost() {
  return allowLan ? ANY_INTERFACE : LOOPBACK;
}

/**
 * First non-internal IPv4 address, for display and for "Copy server URL".
 * Null when there is no such interface (offline, or LAN access is off).
 */
function lanAddress() {
  if (!allowLan) return null;
  for (const addrs of Object.values(networkInterfaces())) {
    for (const addr of addrs ?? []) {
      if (addr.family === 'IPv4' && !addr.internal) return addr.address;
    }
  }
  return null;
}

/** What to hand another device: the LAN URL when there is one, else loopback. */
function shareUrl() {
  const lan = lanAddress();
  return lan ? `http://${lan}:${PORT}` : LOCAL_URL;
}

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
        KEYHOLE_HOST: bindHost(),
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

/**
 * Turning LAN access on is a security decision, so it costs a confirmation.
 * Turning it back off does not — the safe direction should never be obstructed.
 */
async function toggleLan() {
  if (!allowLan) {
    const { response } = await dialog.showMessageBox({
      type: 'warning',
      title: 'Allow access from other devices?',
      message: 'Allow access from other devices?',
      detail: [
        'The sync server will listen on every network interface, not just this',
        'machine. Anyone who can reach this computer on any network you join —',
        'including public Wi-Fi — will be able to reach it.',
        '',
        'The server holds only encrypted vaults and cannot read them. But it',
        'serves plain HTTP: the sync credential travels in a header, so put a',
        'reverse proxy with TLS in front of it before using it over a network',
        'you do not trust. Browsers also refuse plain http:// to anything but',
        'this machine, so the app and extension need that HTTPS proxy to',
        'connect at all.',
        '',
        'Close registration once your devices are enrolled.',
      ].join('\n'),
      buttons: ['Cancel', 'Allow LAN access'],
      defaultId: 0,
      cancelId: 0,
      noLink: true,
    });
    if (response !== 1) {
      // Rebuild the menu so the checkbox snaps back — Electron has already
      // flipped it visually by the time the click handler runs.
      refreshTray();
      return;
    }
  }

  allowLan = !allowLan;
  saveSettings();
  refreshTray();
  // The bind address is fixed at listen(); only a restart can change it.
  await restartServer();
}

function statusLabel() {
  switch (status) {
    case 'running':
      return allowLan ? `Running — ${shareUrl()} (LAN)` : `Running — ${LOCAL_URL}`;
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

  tray.setToolTip(
    `Keyhole Sync Server — ${status === 'running' ? statusLabel().replace('Running — ', '') : status}`,
  );
  tray.setContextMenu(
    Menu.buildFromTemplate([
      { label: statusLabel(), enabled: false },
      { type: 'separator' },
      {
        // Always loopback: this menu runs on the machine hosting the server.
        label: 'Open status page',
        enabled: status === 'running',
        click: () => void shell.openExternal(LOCAL_URL),
      },
      {
        label: 'Copy server URL',
        enabled: status === 'running',
        click: () => clipboard.writeText(shareUrl()),
      },
      { type: 'separator' },
      { label: 'Start', enabled: !running, click: () => void startServer() },
      { label: 'Stop', enabled: running, click: () => stopServer() },
      { label: 'Restart', enabled: running, click: () => void restartServer() },
      { type: 'separator' },
      {
        label: 'Allow access from other devices',
        type: 'checkbox',
        checked: allowLan,
        click: () => void toggleLan(),
      },
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
              `Address:  ${shareUrl()}`,
              allowLan
                ? 'Binding:  0.0.0.0 — reachable from other machines on your networks.'
                : 'Binding:  127.0.0.1 only — not reachable from other machines.',
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
    // Before the tray is built and before the server binds: both need to know
    // whether LAN access was left on last time.
    loadSettings();
    createTray();
    // One click means it is running when the icon appears — no second step.
    await startServer();
  });

  // This app has no windows at all; the default "quit when none are open" rule
  // would terminate it the instant it started.
  app.on('window-all-closed', () => {});

  app.on('before-quit', () => stopServer());
}
