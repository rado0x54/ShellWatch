import { resolve } from "node:path";
import fastifyCors from "@fastify/cors";
import middie from "@fastify/middie";
import fastifyWebsocket from "@fastify/websocket";
import Fastify from "fastify";
import { createServer as createViteServer } from "vite";
import type { Config } from "../config/index.js";
import { registerMcpHttpTransport } from "../mcp/http-transport.js";
import { createMcpServer } from "../mcp/index.js";
import type { TerminalManager } from "../terminal/index.js";
import { registerWebSocket } from "./ws-handler.js";

export async function buildApp(config: Config, terminalManager: TerminalManager) {
  const app = Fastify({ logger: true });

  await app.register(fastifyCors, { origin: true });
  await app.register(fastifyWebsocket);
  await app.register(middie);

  // Vite dev server for client UI (middleware mode, same port)
  const clientRoot = resolve(import.meta.dirname, "../../client");
  const vite = await createViteServer({
    root: clientRoot,
    server: { middlewareMode: true, hmr: { server: app.server } },
    appType: "spa",
  });
  app.use(vite.middlewares);

  // Health check
  app.get("/health", async () => ({ status: "ok" }));

  // Endpoint listing API
  app.get("/api/endpoints", async () => ({
    endpoints: config.servers.map(({ id, label, host, port, username }) => ({
      id,
      label,
      host,
      port,
      username,
    })),
  }));

  // Session management API
  app.post<{ Body: { endpointId: string } }>("/api/sessions", async (request, reply) => {
    try {
      const { endpointId } = request.body;
      const session = await terminalManager.create(endpointId, "ui");
      return session;
    } catch (err) {
      reply.status(400);
      return { error: (err as Error).message };
    }
  });

  app.get("/api/sessions", async () => ({
    sessions: terminalManager.listSessions(),
  }));

  app.delete<{ Params: { sessionId: string } }>(
    "/api/sessions/:sessionId",
    async (request, reply) => {
      try {
        terminalManager.close(request.params.sessionId);
        return { status: "closed" };
      } catch (err) {
        reply.status(404);
        return { error: (err as Error).message };
      }
    },
  );

  // WebSocket for terminal I/O
  registerWebSocket(app, terminalManager);

  // MCP server over streamable HTTP at /mcp
  const mcpServer = createMcpServer(config, terminalManager);
  await registerMcpHttpTransport(app, mcpServer);

  return app;
}
