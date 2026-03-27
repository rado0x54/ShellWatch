import fastifyCors from "@fastify/cors";
import fastifyWebsocket from "@fastify/websocket";
import Fastify from "fastify";
import type { Config } from "../config/index.js";
import type { TerminalManager } from "../terminal/index.js";
import { registerWebSocket } from "./ws-handler.js";

export interface AppOptions {
  logToStderr?: boolean;
}

export function buildApp(
  config: Config,
  terminalManager: TerminalManager,
  options: AppOptions = {},
) {
  const app = Fastify({
    logger: options.logToStderr
      ? { transport: { target: "pino/file", options: { destination: 2 } } }
      : true,
  });

  app.register(fastifyCors, { origin: true });
  app.register(fastifyWebsocket);

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
  app.after(() => {
    registerWebSocket(app, terminalManager);
  });

  return app;
}
