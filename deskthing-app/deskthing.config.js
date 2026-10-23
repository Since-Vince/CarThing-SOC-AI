import { defineConfig } from '@deskthing/cli';

export default defineConfig({
  development: {
    logging: { level: 'info', prefix: '[CarThing SOC]' },
    client: {
      logging: { level: 'info', prefix: '[CarThing SOC Client]', enableRemoteLogging: true },
      clientPort: 3000, viteLocation: 'http://localhost', vitePort: 5173, linkPort: 8080
    },
    server: { editCooldownMs: 1000 }
  }
});
