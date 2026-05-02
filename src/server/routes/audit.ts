import type { FastifyInstance } from "fastify";
import type {
  SessionLifecycleFilters,
  SessionLifecycleRepository,
  SigningRequestFilters,
  SigningRequestsRepository,
} from "../../audit/index.js";

export interface AuditRoutesParams {
  app: FastifyInstance;
  sessionLifecycleRepo?: SessionLifecycleRepository;
  signingRequestsRepo?: SigningRequestsRepository;
}

const SOURCE_VALUES = ["endpoint-auth", "agent-forwarding", "agent-proxy"] as const;
const TYPE_VALUES = ["webauthn-sign", "key-approve"] as const;
const OUTCOME_VALUES = ["approved", "denied", "expired", "cancelled"] as const;

export function registerAuditRoutes(params: AuditRoutesParams) {
  const { app, sessionLifecycleRepo, signingRequestsRepo } = params;

  if (sessionLifecycleRepo) {
    app.get<{
      Querystring: {
        endpointId?: string;
        from?: string;
        to?: string;
        cursor?: string;
        limit?: string;
      };
    }>("/api/audit/sessions", async (request) => {
      const filters: SessionLifecycleFilters = {
        endpointId: request.query.endpointId,
        from: request.query.from,
        to: request.query.to,
      };
      const limit = parseLimit(request.query.limit);
      const page = sessionLifecycleRepo.list(request.accountId, filters, {
        cursor: request.query.cursor,
        limit,
      });
      return page;
    });
  }

  if (signingRequestsRepo) {
    app.get<{
      Querystring: {
        source?: string | string[];
        type?: string | string[];
        outcome?: string | string[];
        credentialId?: string;
        sessionId?: string;
        from?: string;
        to?: string;
        cursor?: string;
        limit?: string;
      };
    }>("/api/audit/signings", async (request, reply) => {
      const source = parseEnum(request.query.source, SOURCE_VALUES);
      if (source === "invalid") return reply.code(400).send({ error: "invalid source filter" });
      const type = parseEnum(request.query.type, TYPE_VALUES);
      if (type === "invalid") return reply.code(400).send({ error: "invalid type filter" });
      const outcome = parseEnum(request.query.outcome, OUTCOME_VALUES);
      if (outcome === "invalid") return reply.code(400).send({ error: "invalid outcome filter" });

      const filters: SigningRequestFilters = {
        source,
        type,
        outcome,
        credentialId: request.query.credentialId,
        sessionId: request.query.sessionId,
        from: request.query.from,
        to: request.query.to,
      };
      const limit = parseLimit(request.query.limit);
      const page = signingRequestsRepo.list(request.accountId, filters, {
        cursor: request.query.cursor,
        limit,
      });
      return page;
    });

    app.get<{ Params: { id: string } }>("/api/audit/signings/:id", async (request, reply) => {
      const row = signingRequestsRepo.getById(request.accountId, request.params.id);
      if (!row) return reply.code(404).send({ error: "not found" });
      return row;
    });
  }
}

function parseLimit(raw: string | undefined): number | undefined {
  if (!raw) return undefined;
  const n = Number(raw);
  if (!Number.isFinite(n)) return undefined;
  return n;
}

/**
 * Parse a query-string enum filter that may be repeated (`?source=a&source=b`).
 * Returns:
 *   - `undefined` when the filter wasn't provided
 *   - a single string when one value was provided
 *   - an array when multiple were provided
 *   - the literal `"invalid"` when any value is outside the allowed set
 */
function parseEnum<T extends string>(
  raw: string | string[] | undefined,
  allowed: readonly T[],
): T | T[] | undefined | "invalid" {
  if (raw === undefined) return undefined;
  const list = (Array.isArray(raw) ? raw : [raw]).filter((v) => v.length > 0);
  if (list.length === 0) return undefined;
  for (const v of list) {
    if (!allowed.includes(v as T)) return "invalid";
  }
  return list.length === 1 ? (list[0] as T) : (list as T[]);
}
