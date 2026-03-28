import { randomUUID } from "node:crypto";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import type { FastifyInstance } from "fastify";
import type { Config } from "../config/index.js";
import type { TerminalManager } from "../terminal/index.js";
import { attachMcpNotifications } from "./notifications.js";
import { createMcpServer } from "./server.js";

export async function registerMcpHttpTransport(
  app: FastifyInstance,
  config: Config,
  terminalManager: TerminalManager,
) {
  const transports = new Map<string, StreamableHTTPServerTransport>();

  app.addHook("onRequest", async (request, reply) => {
    if (request.url !== "/mcp") return;

    const sessionId = request.headers["mcp-session-id"] as string | undefined;
    let transport = sessionId ? transports.get(sessionId) : undefined;

    if (!transport) {
      const newTransport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
      });

      const { server: mcpServer, ownership } = createMcpServer(config, terminalManager);

      await mcpServer.connect(newTransport);

      const notifications = attachMcpNotifications(mcpServer, terminalManager, ownership, {
        debounceMs: config.notifications.mcp.debounceMs,
      });

      newTransport.onclose = () => {
        if (newTransport.sessionId) {
          transports.delete(newTransport.sessionId);
        }
        // Close all terminal sessions owned by this MCP client
        ownership.closeAllSessions();
        notifications.destroy();
      };

      newTransport.onerror = (err) => {
        app.log.error(err, "MCP transport error");
      };

      transport = newTransport;
    }

    try {
      await transport.handleRequest(request.raw, reply.raw);
    } catch (err) {
      app.log.error(err, "MCP handleRequest error");
      if (!reply.raw.headersSent) {
        reply.raw.writeHead(500, { "Content-Type": "application/json" });
        reply.raw.end(
          JSON.stringify({
            jsonrpc: "2.0",
            error: { code: -32603, message: (err as Error).message },
            id: null,
          }),
        );
      }
    }

    if (transport.sessionId && !transports.has(transport.sessionId)) {
      transports.set(transport.sessionId, transport);
    }

    reply.hijack();
  });
}
