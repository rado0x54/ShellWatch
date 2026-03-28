import { resolve } from "node:path";
import fastifyCors from "@fastify/cors";
import fastifyWebsocket from "@fastify/websocket";
import Fastify from "fastify";
import { createServer as createViteServer } from "vite";
import type { Config } from "../config/index.js";
import { registerMcpHttpTransport } from "../mcp/http-transport.js";
import type { TerminalManager } from "../terminal/index.js";
import { registerIpAllowlist } from "./ip-allowlist.js";
import { registerWebSocket } from "./ws-handler.js";

export interface AppOptions {
  logger?: boolean;
  /** Skip Vite dev server setup (for tests) */
  skipVite?: boolean;
}

export async function buildApp(
  config: Config,
  terminalManager: TerminalManager,
  options: AppOptions = {},
) {
  const app = Fastify({ logger: options.logger ?? true });

  await app.register(fastifyCors, { origin: true });
  await app.register(fastifyWebsocket);

  // IP allowlist — protect MCP endpoint (default: localhost only)
  registerIpAllowlist(app, config.security.allowedNetworks, ["/mcp"]);

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
      uiCreatedSessions.add(session.sessionId);
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
  const { uiCreatedSessions } = registerWebSocket(app, terminalManager);

  // MCP server over streamable HTTP at /mcp
  await registerMcpHttpTransport(app, config, terminalManager);

  // Vite dev server — catches all routes not handled by Fastify
  if (!options.skipVite) {
    const clientRoot = resolve(import.meta.dirname, "../../client");
    const vite = await createViteServer({
      root: clientRoot,
      server: {
        middlewareMode: true,
        hmr: { port: 24679 },
      },
      appType: "spa",
    });

    app.setNotFoundHandler((request, reply) => {
      vite.middlewares.handle(request.raw, reply.raw, () => {
        reply.status(404).send({ error: "Not found" });
      });
    });
  }

  return app;
}
