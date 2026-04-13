import { randomUUID } from "node:crypto";
import type { FastifyInstance } from "fastify";
import type { AccountRepository, EndpointRepository } from "../../db/index.js";
import {
  isUserVerification,
  USER_VERIFICATION_VALUES,
  type UserVerification,
} from "../../db/repositories/endpoint-repo.js";
import type { TerminalManager } from "../../terminal/index.js";

export interface EndpointRoutesParams {
  app: FastifyInstance;
  endpointRepo: EndpointRepository;
  accountRepo: AccountRepository;
  terminalManager: TerminalManager;
}

export function registerEndpointRoutes(params: EndpointRoutesParams) {
  const { app, endpointRepo, terminalManager } = params;

  app.get("/api/endpoints", async (request, reply) => {
    if (!request.accountId) {
      reply.status(401);
      return { error: "Not authenticated" };
    }
    const all = await endpointRepo.findAllForAccount(request.accountId);
    return {
      endpoints: all.map(({ id, label, host, port, username, userVerification }) => ({
        id,
        label,
        host,
        port,
        username,
        userVerification,
      })),
    };
  });

  app.post<{
    Body: {
      label: string;
      host: string;
      port?: number;
      username?: string;
      userVerification?: string;
    };
  }>("/api/endpoints", async (request, reply) => {
    if (!request.accountId) {
      reply.status(401);
      return { error: "Not authenticated" };
    }
    try {
      const uv = request.body.userVerification;
      if (uv !== undefined && !isUserVerification(uv)) {
        reply.status(400);
        return {
          error: `userVerification must be one of: ${USER_VERIFICATION_VALUES.join(", ")}`,
        };
      }
      const id = randomUUID();
      await endpointRepo.create({
        id,
        accountId: request.accountId,
        label: request.body.label,
        host: request.body.host,
        port: request.body.port ?? 22,
        username: request.body.username ?? "shellwatch",
        userVerification: uv as UserVerification | undefined,
      });
      return { status: "created", id };
    } catch (err) {
      app.log.error(err, "request failed");
      reply.status(400);
      return { error: (err as Error).message };
    }
  });

  app.put<{ Params: { id: string }; Body: Record<string, unknown> }>(
    "/api/endpoints/:id",
    async (request, reply) => {
      if (!request.accountId) {
        reply.status(401);
        return { error: "Not authenticated" };
      }
      try {
        const body = request.body;
        if ("userVerification" in body && !isUserVerification(body.userVerification)) {
          reply.status(400);
          return {
            error: `userVerification must be one of: ${USER_VERIFICATION_VALUES.join(", ")}`,
          };
        }
        await endpointRepo.update(
          request.params.id,
          request.accountId,
          body as Parameters<EndpointRepository["update"]>[2],
        );
        return { status: "updated" };
      } catch (err) {
        app.log.error(err, "request failed");
        reply.status(400);
        return { error: (err as Error).message };
      }
    },
  );

  app.delete<{ Params: { id: string } }>("/api/endpoints/:id", async (request, reply) => {
    if (!request.accountId) {
      reply.status(401);
      return { error: "Not authenticated" };
    }
    try {
      const activeSessions = terminalManager
        .listSessions()
        .filter((s) => s.endpointId === request.params.id);
      if (activeSessions.length > 0) {
        reply.status(409);
        return { error: "Cannot delete endpoint with active sessions" };
      }
      await endpointRepo.delete(request.params.id, request.accountId);
      return { status: "deleted" };
    } catch (err) {
      app.log.error(err, "request failed");
      reply.status(400);
      return { error: (err as Error).message };
    }
  });
}
