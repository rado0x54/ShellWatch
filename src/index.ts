import { loadConfig } from "./config/index.js";
import { buildApp } from "./server/app.js";

const PORT = parseInt(process.env.PORT ?? "3000", 10);
const HOST = process.env.HOST ?? "0.0.0.0";

try {
  const config = loadConfig();
  console.log(`Loaded ${config.servers.length} endpoint(s) from config`);

  const app = buildApp(config);

  await app.listen({ port: PORT, host: HOST });
  console.log(`ShellWatch server listening on http://${HOST}:${PORT}`);
} catch (err) {
  console.error("Failed to start ShellWatch:", (err as Error).message);
  process.exit(1);
}
