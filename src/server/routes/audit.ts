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
}

function parseLimit(raw: string | undefined): number | undefined {
  if (!raw) return undefined;
  const n = Number(raw);
  if (!Number.isFinite(n)) return undefined;
  return n;
}
