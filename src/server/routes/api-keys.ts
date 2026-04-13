import { randomBytes, randomUUID } from "node:crypto";
import type { FastifyInstance } from "fastify";
import type { ApiKeyRepository } from "../../db/index.js";
import { hashApiKey } from "../auth/api-key-auth.js";

export interface ApiKeyRoutesParams {
  app: FastifyInstance;
  apiKeyRepo: ApiKeyRepository;
}

export function registerApiKeyRoutes(params: ApiKeyRoutesParams) {
  const { app, apiKeyRepo } = params;

  app.get("/api/keys/api", async (request) => {
    if (!request.accountId) return { keys: [] };
    const keys = await apiKeyRepo.findAll();
    return {
      keys: keys
        .filter((k) => k.accountId === request.accountId)
        .map((k) => ({
          id: k.id,
          label: k.label,
          keyPrefix: k.keyPrefix,
          scopes: k.scopes,
          enabled: k.enabled,
          createdAt: k.createdAt,
        })),
    };
  });

  const VALID_SCOPES = ["mcp", "agent"] as const;
  type Scope = (typeof VALID_SCOPES)[number];

  app.post<{ Body: { label: string; scopes?: string[] } }>(
    "/api/keys/api",
    async (request, reply) => {
      if (!request.accountId) {
        reply.status(401);
        return { error: "Not authenticated" };
      }
      const { label, scopes: requestedScopes } = request.body;
      if (!label) {
        reply.status(400);
        return { error: "Label is required" };
      }
      let scopes: Scope[] = ["mcp"];
      if (requestedScopes !== undefined) {
        if (
          !Array.isArray(requestedScopes) ||
          requestedScopes.length === 0 ||
          !requestedScopes.every((s): s is Scope => (VALID_SCOPES as readonly string[]).includes(s))
        ) {
          reply.status(400);
          return { error: `Scopes must be a non-empty subset of: ${VALID_SCOPES.join(", ")}` };
        }
        scopes = Array.from(new Set(requestedScopes));
      }
      const raw = `sw_${randomBytes(24).toString("hex")}`;
      const keyHash = hashApiKey(raw);
      const keyPrefix = raw.slice(0, 10);
      const id = randomUUID();
      await apiKeyRepo.create({
        id,
        accountId: request.accountId,
        label,
        keyHash,
        keyPrefix,
        scopes,
      });
      return { id, label, keyPrefix, scopes, key: raw };
    },
  );

  app.delete<{ Params: { id: string } }>("/api/keys/api/:id", async (request, reply) => {
    if (!request.accountId) {
      reply.status(401);
      return { error: "Not authenticated" };
    }
    // Verify ownership before revoking
    const keys = await apiKeyRepo.findAll();
    const key = keys.find((k) => k.id === request.params.id && k.accountId === request.accountId);
    if (!key) {
      reply.status(404);
      return { error: "API key not found" };
    }
    await apiKeyRepo.revoke(request.params.id);
    return { status: "revoked" };
  });
}
