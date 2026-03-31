import { createHash } from "node:crypto";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import type { ApiKeyRepository } from "../../db/repositories/api-key-repo.js";

export function hashApiKey(raw: string): string {
  return createHash("sha256").update(raw).digest("hex");
}

export function registerApiKeyAuth(
  app: FastifyInstance,
  apiKeyRepo: ApiKeyRepository,
  mcpPath: string,
): void {
  app.addHook("onRequest", async (request: FastifyRequest, reply: FastifyReply) => {
    if (!request.url.startsWith(mcpPath)) return;

    const auth = request.headers.authorization;
    if (!auth?.startsWith("Bearer ")) {
      reply.status(401).send({ error: "API key required. Use Authorization: Bearer sw_..." });
      return;
    }

    const token = auth.slice(7);
    const hash = hashApiKey(token);
    const key = await apiKeyRepo.findByHash(hash);

    if (!key) {
      reply.status(401).send({ error: "Invalid API key" });
      return;
    }
  });
}
