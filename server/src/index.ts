/** Entrypoint. Boots the API and shuts down cleanly on a signal. */

import { buildApp } from './app.ts';
import { loadConfig } from './config.ts';
import { RESTART_EXIT_CODE, buildControlApp, createControlToken } from './control.ts';

const config = loadConfig();

// Generated even when the control plane is off, so the API can decide whether
// to hand it to a local dashboard without a second code path. Nothing can be
// done with it unless a control listener is actually bound.
const control = createControlToken(config.databasePath);

const app = buildApp({ config, logger: true, controlToken: config.control ? control.token : undefined });

let controlApp: ReturnType<typeof buildControlApp> | undefined;

/** Close both listeners before leaving, so the port is free for whatever starts next. */
async function shutdown(code: number, reason: string): Promise<never> {
  app.log.info(`${reason}, closing`);
  try {
    if (controlApp) await controlApp.close();
    await app.close();
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
      // 0 leaves the service down under systemd; RESTART_EXIT_CODE is mapped in
      // the unit file to bring it straight back.
      onStop: () => void shutdown(0, 'stop requested'),
      onRestart: () => void shutdown(RESTART_EXIT_CODE, 'restart requested'),
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
