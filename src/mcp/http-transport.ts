import { randomUUID } from "node:crypto";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import type { FastifyInstance } from "fastify";
import { AgentSession } from "../agent/index.js";
import type { Config } from "../config/index.js";
import type { AccountRepository, EndpointRepository, SshKeyRepository } from "../db/index.js";
import type { TerminalManager } from "../terminal/index.js";
import { attachMcpNotifications } from "./notifications.js";
import { createMcpServer } from "./server.js";

export interface McpHttpTransportOptions {
  app: FastifyInstance;
  config: Config;
  terminalManager: TerminalManager;
  endpointRepo: EndpointRepository;
  keyRepo: SshKeyRepository;
  accountRepo: AccountRepository;
}

export async function registerMcpHttpTransport(opts: McpHttpTransportOptions) {
  const { app, config, terminalManager, endpointRepo, keyRepo, accountRepo } = opts;
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

  const mcpPath = "/mcp";

  app.addHook("onRequest", async (request, reply) => {
    if (request.url !== mcpPath) return;

    const sessionId = request.headers["mcp-session-id"] as string | undefined;
    let managed = sessionId ? sessions.get(sessionId) : undefined;

    if (sessionId && !managed) {
      // Stale session ID (e.g. client holding a session from a prior server
      // instance). Return 404 so the client drops it and reinitializes.
      reply.code(404).send({
        jsonrpc: "2.0",
        error: { code: -32001, message: "Session not found" },
        id: null,
      });
      return;
    }

    if (!managed) {
      // Defense-in-depth: api-key-auth normally rejects unauthenticated /mcp
      // before we get here, but it's only registered when apiKeyRepo is wired
      // (see app.ts — the dev path without apiKeyRepo skips it). Catch that
      // case fast instead of letting tool calls fail downstream.
      if (!request.accountId) {
        reply.status(401).send({ error: "Authentication required" });
        return;
      }
      const accountId = request.accountId;

      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
      });

      // Look up account's session limit
      let maxSessions = 5;
      const account = await accountRepo.findById(accountId);
      if (account) maxSessions = account.maxSessions;

      const agentSession = new AgentSession(
        endpointRepo,
        terminalManager,
        "mcp",
        maxSessions,
        request.ip,
      );
      const mcpServer = await createMcpServer(agentSession, endpointRepo, keyRepo, accountId);

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
