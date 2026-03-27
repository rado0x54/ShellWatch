import { loadConfig } from "./config/index.js";
import { buildApp } from "./server/app.js";
import { TerminalManager } from "./terminal/index.js";
import { createSshTransportFactory } from "./transport/index.js";

const PORT = parseInt(process.env.PORT ?? "3000", 10);
const HOST = process.env.HOST ?? "0.0.0.0";

try {
  const config = loadConfig();
  console.log(`Loaded ${config.servers.length} endpoint(s) from config`);

  const transportFactory = createSshTransportFactory(config);
  const terminalManager = new TerminalManager(config, transportFactory);

  const app = await buildApp(config, terminalManager);

  const shutdown = async () => {
    terminalManager.destroy();
    await app.close();
    process.exit(0);
  };

  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);

  await app.listen({ port: PORT, host: HOST });
  console.log(`ShellWatch server listening on http://${HOST}:${PORT}`);
  console.log(`MCP endpoint available at http://${HOST}:${PORT}/mcp`);
} catch (err) {
  console.error("Failed to start ShellWatch:", (err as Error).message);
  process.exit(1);
}
