import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { loadConfig } from "./config/index.js";
import { createMcpServer } from "./mcp/index.js";
import { buildApp } from "./server/app.js";
import { TerminalManager } from "./terminal/index.js";
import { createSshTransportFactory } from "./transport/index.js";

const PORT = parseInt(process.env.PORT ?? "3000", 10);
const HOST = process.env.HOST ?? "0.0.0.0";

try {
  const config = loadConfig();
  // Use stderr for all logging — stdout is reserved for MCP stdio
  console.error(`Loaded ${config.servers.length} endpoint(s) from config`);

  const transportFactory = createSshTransportFactory(config);
  const terminalManager = new TerminalManager(config, transportFactory);

  // Start HTTP + WebSocket server (logs to stderr via pino)
  const app = buildApp(config, terminalManager, { logToStderr: true });

  // Start MCP stdio server (shares the same TerminalManager)
  const mcpServer = createMcpServer(config, terminalManager);
  const mcpTransport = new StdioServerTransport();
  await mcpServer.connect(mcpTransport);

  const shutdown = async () => {
    await mcpServer.close();
    terminalManager.destroy();
    await app.close();
    process.exit(0);
  };

  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);

  await app.listen({ port: PORT, host: HOST });
  console.error(`ShellWatch server listening on http://${HOST}:${PORT}`);
  console.error("MCP stdio server ready");
} catch (err) {
  console.error("Failed to start ShellWatch:", (err as Error).message);
  process.exit(1);
}
