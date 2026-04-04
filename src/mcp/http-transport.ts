import { randomUUID } from "node:crypto";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import type { FastifyInstance } from "fastify";
import { AgentSession } from "../agent/index.js";
import type { Config } from "../config/index.js";
import type { AccountRepository } from "../db/repositories/account-repo.js";
import type { EndpointRepository } from "../db/repositories/endpoint-repo.js";
import type { SshKeyRepository } from "../db/repositories/key-repo.js";
import type { TerminalManager } from "../terminal/index.js";
import { attachMcpNotifications } from "./notifications.js";
import { createMcpServer } from "./server.js";

export async function registerMcpHttpTransport(
  app: FastifyInstance,
  config: Config,
  terminalManager: TerminalManager,
  endpointRepo: EndpointRepository,
  keyRepo: SshKeyRepository,
  accountRepo: AccountRepository,
) {
  interface ManagedTransport {
    transport: StreamableHTTPServerTransport;
    agentSession: AgentSession;
    notifications: { destroy(): void };
  }

  const sessions = new Map<string, ManagedTransport>();

  function destroyManaged(managed: ManagedTransport) {
    const id = managed.transport.sessionId;
    if (id) sessions.delete(id);
    managed.agentSession.destroy();
    managed.notifications.destroy();
  }

  const mcpPath = `${config.server.basePath}/mcp`;

  app.addHook("onRequest", async (request, reply) => {
    if (request.url !== mcpPath) return;

    const sessionId = request.headers["mcp-session-id"] as string | undefined;
    let managed = sessionId ? sessions.get(sessionId) : undefined;

    if (!managed) {
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
      });

      // Look up account's session limit
      let maxSessions = 5;
      if (request.accountId) {
        const account = await accountRepo.findById(request.accountId);
        if (account) maxSessions = account.maxSessions;
      }

      const agentSession = new AgentSession(endpointRepo, terminalManager, "mcp", maxSessions);
      const mcpServer = await createMcpServer(
        agentSession,
        endpointRepo,
        keyRepo,
        request.accountId,
        accountRepo,
      );

      await mcpServer.connect(transport);

      const notifications = attachMcpNotifications(mcpServer, terminalManager, agentSession, {
        debounceMs: config.notifications.mcp.debounceMs,
      });

      managed = { transport, agentSession, notifications };

      transport.onclose = () => destroyManaged(managed!);

      transport.onerror = (err) => {
        app.log.error(err, "MCP transport error");
      };
    }

    const isNew = !sessionId;

    try {
      await managed.transport.handleRequest(request.raw, reply.raw);
    } catch (err) {
      app.log.error(err, "MCP handleRequest error");
      if (isNew) destroyManaged(managed);
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

    const tid = managed.transport.sessionId;
    if (tid && !sessions.has(tid)) {
      sessions.set(tid, managed);
    } else if (isNew && !tid) {
      // Transport never got a session ID (e.g. non-initialize request) — clean up
      destroyManaged(managed);
    }

    reply.hijack();
  });
}
