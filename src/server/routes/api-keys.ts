import { randomBytes, randomUUID } from "node:crypto";
import type { FastifyInstance } from "fastify";
import type { AccountRepository, ApiKeyRepository } from "../../db/index.js";
import { hashApiKey } from "../auth/api-key-auth.js";

export interface ApiKeyRoutesParams {
  app: FastifyInstance;
  basePath: string;
  apiKeyRepo: ApiKeyRepository;
  accountRepo: AccountRepository;
}

export function registerApiKeyRoutes(params: ApiKeyRoutesParams) {
  const { app, basePath: base, apiKeyRepo } = params;

  app.get(`${base}/api/keys/api`, async (request) => {
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

  app.post<{ Body: { label: string } }>(`${base}/api/keys/api`, async (request, reply) => {
    if (!request.accountId) {
      reply.status(401);
      return { error: "Not authenticated" };
    }
    const { label } = request.body;
    if (!label) {
      reply.status(400);
      return { error: "Label is required" };
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
      scopes: ["mcp"],
    });
    return { id, label, keyPrefix, key: raw };
  });

  app.delete<{ Params: { id: string } }>(`${base}/api/keys/api/:id`, async (request, reply) => {
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
