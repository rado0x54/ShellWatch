// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import type { FastifyInstance } from "fastify";
import type { AccountRepository, EndpointRepository } from "../../db/index.js";
import type { DemoEndpointsService } from "../../demo-endpoints/index.js";
import { isDemoEndpointId } from "../../demo-endpoints/index.js";
import type { TerminalManager } from "../../terminal/index.js";

export interface SessionRoutesParams {
  app: FastifyInstance;
  endpointRepo: EndpointRepository;
  accountRepo: AccountRepository;
  demoEndpoints: DemoEndpointsService;
  terminalManager: TerminalManager;
}

export function registerSessionRoutes(params: SessionRoutesParams) {
  const { app, endpointRepo, accountRepo, demoEndpoints, terminalManager } = params;

  app.post<{ Body: { endpointId: string } }>("/api/sessions", async (request, reply) => {
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
      // Demo endpoints are virtual (config-only). Connect deliberately
      // bypasses the per-account `showDemoEndpoints` toggle — the toggle is a
      // *visibility* preference, not an authorization gate. Demo entries are
      // global, operator-curated, and not sensitive; the demo container's
      // ForceCommand pinning is the real control. Hiding them from the list
      // shouldn't break a session a caller has already chosen to open (e.g.
      // when re-using a bookmarked URL with the demo id).
      const endpoint = isDemoEndpointId(endpointId)
        ? demoEndpoints.findById(endpointId, request.accountId)
        : await endpointRepo.findByIdForAccount(endpointId, request.accountId);
      if (!endpoint) {
        reply.status(404);
        return { error: "Endpoint not found" };
      }
      const session = await terminalManager.create(endpoint, request.accountId, {
        kind: "ui",
        sourceIp: request.ip,
      });

      return session;
    } catch (err) {
      app.log.error(err, "request failed");
      reply.status(400);
      return { error: (err as Error).message };
    }
  });

  app.get("/api/sessions", async (request) => {
    const sessions = terminalManager
      .listSessions()
      .filter((s) => s.accountId === request.accountId);
    return { sessions };
  });

  app.get<{
    Params: { sessionId: string };
    Querystring: { limit?: string };
  }>("/api/sessions/:sessionId/tail", async (request, reply) => {
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
      const session = terminalManager.getSession(request.params.sessionId);
      if (!session || session.accountId !== request.accountId) {
        // Don't disclose existence of sessions on other accounts.
        reply.status(404);
        return { error: "Session not found" };
      }
      terminalManager.close(request.params.sessionId, "client.ui");
      return { status: "closed" };
    },
  );
}
