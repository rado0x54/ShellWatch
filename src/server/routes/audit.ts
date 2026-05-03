// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
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
        source?: string;
        outcome?: string;
        from?: string;
        to?: string;
        cursor?: string;
        limit?: string;
      };
    }>("/api/audit/signings", async (request, reply) => {
      const source = parseEnum(request.query.source, SOURCE_VALUES);
      if (source === "invalid") return reply.code(400).send({ error: "invalid source filter" });
      const outcome = parseEnum(request.query.outcome, OUTCOME_VALUES);
      if (outcome === "invalid") return reply.code(400).send({ error: "invalid outcome filter" });

      const filters: SigningRequestFilters = {
        source,
        outcome,
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
 * Parse and validate a single-value query-string enum filter. Returns:
 *   - `undefined` when the filter wasn't provided
 *   - the value when it's in the allowed set
 *   - the literal `"invalid"` when it isn't (caller emits 400)
 */
function parseEnum<T extends string>(
  raw: string | undefined,
  allowed: readonly T[],
): T | undefined | "invalid" {
  if (raw === undefined || raw === "") return undefined;
  if (!allowed.includes(raw as T)) return "invalid";
  return raw as T;
}
