/** Entrypoint. Boots the API and shuts down cleanly on a signal. */

import { buildApp } from './app.ts';
import { loadConfig } from './config.ts';

const config = loadConfig();
const app = buildApp({ config, logger: true });

for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.on(signal, () => {
    app.log.info(`${signal} received, closing`);
    void app.close().then(() => process.exit(0));
  });
}

try {
  await app.listen({ host: config.host, port: config.port });
  app.log.info(
    `Keyhole sync listening on ${config.host}:${config.port} — registration ${
      config.allowRegistration ? 'OPEN' : 'closed'
    }`,
  );
} catch (err) {
  app.log.error(err);
  process.exit(1);
}
