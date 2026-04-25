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
      // Enforce per-account session limit
      const account = await accountRepo.findById(request.accountId);
      if (account) {
        const accountSessions = terminalManager
          .listSessions()
          .filter((s) => s.accountId === request.accountId && s.status === "open");
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
      const session = await terminalManager.create(endpointId, {
        kind: "ui",
        sourceIp: request.ip,
      });
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
    const sessions = terminalManager
      .listSessions()
      .filter((s) => s.accountId === request.accountId);
    return { sessions };
  });

  app.get<{
    Params: { sessionId: string };
    Querystring: { limit?: string };
  }>("/api/sessions/:sessionId/tail", async (request, reply) => {
    if (!request.accountId) {
      reply.status(401);
      return { error: "Not authenticated" };
    }
    const session = terminalManager.getSession(request.params.sessionId);
    if (!session || session.accountId !== request.accountId) {
      // Don't disclose existence of sessions on other accounts.
      reply.status(404);
      return { error: "Session not found" };
    }
    // Clamp to a sane range so a malformed query string can't bloat the response.
    const requested = Number(request.query.limit);
    const limit =
      Number.isFinite(requested) && requested > 0 ? Math.min(Math.floor(requested), 8000) : 2000;
    const data = terminalManager.readOutputTail(request.params.sessionId, limit);
    return { data };
  });

  app.delete<{ Params: { sessionId: string } }>(
    "/api/sessions/:sessionId",
    async (request, reply) => {
      if (!request.accountId) {
        reply.status(401);
        return { error: "Not authenticated" };
      }
      const session = terminalManager.getSession(request.params.sessionId);
      if (!session || session.accountId !== request.accountId) {
        reply.status(404);
        return { error: "Session not found" };
      }
      terminalManager.close(request.params.sessionId);
      return { status: "closed" };
    },
  );
}
