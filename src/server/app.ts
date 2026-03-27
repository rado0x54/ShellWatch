import fastifyCors from "@fastify/cors";
import fastifyWebsocket from "@fastify/websocket";
import Fastify from "fastify";
import type { Config } from "../config/index.js";
import type { TerminalManager } from "../terminal/index.js";
import { registerWebSocket } from "./ws-handler.js";

export function buildApp(config: Config, terminalManager: TerminalManager) {
  const app = Fastify({ logger: true });

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
  app.post<{ Body: { endpointId: string } }>("/api/sessions", async (request) => {
    const { endpointId } = request.body;
    const session = await terminalManager.create(endpointId, "ui");
    return session;
  });

  app.get("/api/sessions", async () => ({
    sessions: terminalManager.listSessions(),
  }));

  app.delete<{ Params: { sessionId: string } }>("/api/sessions/:sessionId", async (request) => {
    terminalManager.close(request.params.sessionId);
    return { status: "closed" };
  });

  // WebSocket for terminal I/O
  app.after(() => {
    registerWebSocket(app, terminalManager);
  });

  return app;
}
