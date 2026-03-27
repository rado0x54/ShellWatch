import fastifyCors from "@fastify/cors";
import Fastify from "fastify";
import type { Config } from "../config/index.js";

export function buildApp(config: Config) {
  const app = Fastify({ logger: true });

  app.register(fastifyCors, { origin: true });

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

  return app;
}
