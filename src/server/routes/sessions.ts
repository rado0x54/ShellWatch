import { eq } from "drizzle-orm";
import type { FastifyInstance } from "fastify";
import type { ShellWatchDB } from "../../db/connection.js";
import type { AccountRepository, EndpointRepository } from "../../db/index.js";
import { sshKeys as sshKeysTable, webauthnCredentials } from "../../db/schema.js";
import type { TerminalManager } from "../../terminal/index.js";

export interface SessionRoutesParams {
  app: FastifyInstance;
  basePath: string;
  endpointRepo: EndpointRepository;
  accountRepo: AccountRepository;
  terminalManager: TerminalManager;
  uiCreatedSessions: Set<string>;
  db?: ShellWatchDB | null;
}

export function registerSessionRoutes(params: SessionRoutesParams) {
  const {
    app,
    basePath: base,
    endpointRepo,
    accountRepo,
    terminalManager,
    uiCreatedSessions,
    db = null,
  } = params;

  app.post<{ Body: { endpointId: string } }>(`${base}/api/sessions`, async (request, reply) => {
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

      // Update lastUsedAt on the assigned key
      const now = new Date().toISOString();
      if (endpoint.passkeyId && db) {
        db.update(webauthnCredentials)
          .set({ lastUsedAt: now })
          .where(eq(webauthnCredentials.id, endpoint.passkeyId))
          .run();
      } else if (endpoint.keyId && db) {
        db.update(sshKeysTable)
          .set({ lastUsedAt: now })
          .where(eq(sshKeysTable.id, endpoint.keyId))
          .run();
      }

      return session;
    } catch (err) {
      app.log.error(err, "request failed");
      reply.status(400);
      return { error: (err as Error).message };
    }
  });

  app.get(`${base}/api/sessions`, async (request) => {
    if (!request.accountId) return { sessions: [] };
    // Only show sessions on endpoints owned by this account
    const accountEndpoints = await endpointRepo.findAllForAccount(request.accountId);
    const endpointIds = new Set(accountEndpoints.map((e) => e.id));
    const sessions = terminalManager.listSessions().filter((s) => endpointIds.has(s.endpointId));
    return { sessions };
  });

  app.delete<{ Params: { sessionId: string } }>(
    `${base}/api/sessions/:sessionId`,
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
