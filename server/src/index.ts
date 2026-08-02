/** Entrypoint. Boots the API and shuts down cleanly on a signal. */

import { buildApp } from './app.ts';
import { loadConfig } from './config.ts';
import { ConsoleLog } from './console-log.ts';
import { RESTART_EXIT_CODE, buildControlApp, createControlToken } from './control.ts';
import { Store } from './db.ts';
import {
  effectiveAllowRegistration,
  readRuntimeState,
  writeRuntimeState,
} from './runtime-state.ts';

const config = loadConfig();

// Boot-time precedence: the restrictive value wins, so a dashboard close
// survives a restart but a stale file can never reopen a server that the
// environment shut. See runtime-state.ts for the full truth table.
config.allowRegistration = effectiveAllowRegistration(
  config.allowRegistration,
  readRuntimeState(config.databasePath)?.allowRegistration,
);

// Generated even when the control plane is off, so the API can decide whether
// to hand it to a local dashboard without a second code path. Nothing can be
// done with it unless a control listener is actually bound.
const control = createControlToken(config.databasePath);

// The entrypoint owns both of these rather than letting buildApp create them,
// because the control plane needs the same instances the API is using — a
// second Store would be a second connection to the same file, and a second
// ConsoleLog would log to a buffer nobody is watching.
const store = new Store(config.databasePath);
const consoleLog = new ConsoleLog();

const app = buildApp({
  config,
  store,
  consoleLog,
  logger: true,
  controlToken: config.control ? control.token : undefined,
});

let controlApp: ReturnType<typeof buildControlApp> | undefined;

/** Close both listeners before leaving, so the port is free for whatever starts next. */
async function shutdown(code: number, reason: string): Promise<never> {
  app.log.info(`${reason}, closing`);
  try {
    if (controlApp) await controlApp.close();
    await app.close();
    // buildApp only closes a Store it created itself, and it no longer creates
    // this one — without this the WAL is left uncheckpointed on every restart.
    store.close();
  } catch (err) {
    app.log.error(err);
  }
  process.exit(code);
}

for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.on(signal, () => {
    void shutdown(0, `${signal} received`);
  });
}

try {
  await app.listen({ host: config.host, port: config.port });
  app.log.info(
    `Keyhole sync listening on ${config.host}:${config.port} — registration ${
      config.allowRegistration ? 'OPEN' : 'closed'
    }`,
  );

  if (config.control) {
    controlApp = buildControlApp({
      config,
      token: control.token,
      store,
      // 0 leaves the service down under systemd; RESTART_EXIT_CODE is mapped in
      // the unit file to bring it straight back.
      onStop: () => void shutdown(0, 'stop requested'),
      onRestart: () => void shutdown(RESTART_EXIT_CODE, 'restart requested'),
      setRegistration: (allow) => {
        // Mutating in place is the mechanism, not a shortcut: buildApp closed
        // over this same object and the POST /api/v1/account gate reads the
        // field on every request, so the change is live immediately.
        config.allowRegistration = allow;
        const persisted = writeRuntimeState(config.databasePath, allow);
        const note = `Registration ${allow ? 'opened' : 'closed'}${
          persisted ? '' : ' (not persisted)'
        }`;
        app.log.warn(note);
        // Into the dashboard console too, so the change is visible in the same
        // place the requests are — including to a remote viewer, who can
        // already read the Registration tile on that page.
        consoleLog.push({
          level: allow ? 'warn' : 'info',
          method: '—',
          path: '/control/v1/registration',
          statusCode: 200,
          ms: 0,
          ip: 'local',
          message: note,
        });
        return { allowRegistration: allow, persisted };
      },
    });
    // Hard-coded loopback. See ServerConfig.controlPort for why this is not an
    // option: a control plane on a network interface is a remote kill switch.
    await controlApp.listen({ host: '127.0.0.1', port: config.controlPort });
    app.log.info(
      `Control plane on 127.0.0.1:${config.controlPort}${
        control.path ? ` — token at ${control.path}` : ''
      }`,
    );
  }
} catch (err) {
  app.log.error(err);
  process.exit(1);
}
