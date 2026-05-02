import type { FastifyInstance } from "fastify";
import type { SessionLifecycleFilters, SessionLifecycleRepository } from "../../audit/index.js";

export interface AuditRoutesParams {
  app: FastifyInstance;
  sessionLifecycleRepo: SessionLifecycleRepository;
}

export function registerAuditRoutes(params: AuditRoutesParams) {
  const { app, sessionLifecycleRepo } = params;

  app.get<{
    Querystring: {
      endpointId?: string;
      cursor?: string;
      limit?: string;
    };
  }>("/api/audit/sessions", async (request) => {
    const filters: SessionLifecycleFilters = {
      endpointId: request.query.endpointId,
    };
    const limit = parseLimit(request.query.limit);
    const page = sessionLifecycleRepo.list(request.accountId, filters, {
      cursor: request.query.cursor,
      limit,
    });
    return page;
  });

  app.get<{ Params: { sessionId: string } }>(
    "/api/audit/sessions/:sessionId",
    async (request, reply) => {
      const row = sessionLifecycleRepo.findOne(request.params.sessionId, request.accountId);
      if (!row) {
        // Don't disclose existence of audit rows owned by other accounts.
        reply.status(404);
        return { error: "Audit row not found" };
      }
      return row;
    },
  );
}

function parseLimit(raw: string | undefined): number | undefined {
  if (!raw) return undefined;
  const n = Number(raw);
  if (!Number.isFinite(n)) return undefined;
  return n;
}
