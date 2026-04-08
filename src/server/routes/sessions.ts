import type { FastifyInstance } from "fastify";
import type { AccountRepository, EndpointRepository } from "../../db/index.js";
import type { TerminalManager } from "../../terminal/index.js";

export interface SessionRoutesParams {
  app: FastifyInstance;
  endpointRepo: EndpointRepository;
  accountRepo: AccountRepository;
  terminalManager: TerminalManager;
  uiCreatedSessions: Set<string>;
}

export function registerSessionRoutes(params: SessionRoutesParams) {
  const { app, endpointRepo, accountRepo, terminalManager, uiCreatedSessions } = params;

  app.post<{ Body: { endpointId: string } }>("/api/sessions", async (request, reply) => {
    if (!request.accountId) {
      reply.status(401);
      return { error: "Not authenticated" };
    }
    try {
      // Enforce per-account session limit (scoped to this account's endpoints)
      const account = await accountRepo.findById(request.accountId);
      if (account) {
        const accountEndpoints = await endpointRepo.findAllForAccount(request.accountId);
        const accountEndpointIds = new Set(accountEndpoints.map((e) => e.id));
        const activeSessions = terminalManager.listSessions();
        const accountSessions = activeSessions.filter(
          (s) => accountEndpointIds.has(s.endpointId) && s.status === "open",
        );
        if (accountSessions.length >= account.maxSessions) {
          reply.status(429);
          return {
            error: `Maximum concurrent sessions (${account.maxSessions}) reached`,
          };
        }
      }

      const { endpointId } = request.body;
      const endpoint = await endpointRepo.findByIdForAccount(endpointId, request.accountId);
      if (!endpoint) {
        reply.status(404);
        return { error: "Endpoint not found" };
      }
      const session = await terminalManager.create(endpointId, "ui");
      uiCreatedSessions.add(session.sessionId);

      return session;
    } catch (err) {
      app.log.error(err, "request failed");
      reply.status(400);
      return { error: (err as Error).message };
    }
  });

  app.get("/api/sessions", async (request) => {
    if (!request.accountId) return { sessions: [] };
    // Only show sessions on endpoints owned by this account
    const accountEndpoints = await endpointRepo.findAllForAccount(request.accountId);
    const endpointIds = new Set(accountEndpoints.map((e) => e.id));
    const sessions = terminalManager.listSessions().filter((s) => endpointIds.has(s.endpointId));
    return { sessions };
  });

  app.delete<{ Params: { sessionId: string } }>(
    "/api/sessions/:sessionId",
    async (request, reply) => {
      if (!request.accountId) {
        reply.status(401);
        return { error: "Not authenticated" };
      }
      const session = terminalManager.getSession(request.params.sessionId);
      if (!session) {
        reply.status(404);
        return { error: "Session not found" };
      }
      // Verify the session's endpoint belongs to this account
      const endpoint = await endpointRepo.findByIdForAccount(session.endpointId, request.accountId);
      if (!endpoint) {
        reply.status(403);
        return { error: "Access denied" };
      }
      terminalManager.close(request.params.sessionId);
      return { status: "closed" };
    },
  );
}
