// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { randomUUID } from "node:crypto";
import type { FastifyInstance } from "fastify";
import type { AccountRepository, EndpointRepository } from "../../db/index.js";
import {
  ENDPOINT_DESCRIPTION_MAX_LENGTH,
  isUserVerification,
  USER_VERIFICATION_VALUES,
  type UserVerification,
} from "../../db/repositories/endpoint-repo.js";
import type { DemoEndpointsService } from "../../demo-endpoints/index.js";
import { isDemoEndpointId } from "../../demo-endpoints/index.js";
import type { TerminalManager } from "../../terminal/index.js";

function normalizeDescription(value: unknown): { ok: true; value: string | null } | { ok: false } {
  if (value === undefined || value === null) return { ok: true, value: null };
  if (typeof value !== "string") return { ok: false };
  if (value.length > ENDPOINT_DESCRIPTION_MAX_LENGTH) return { ok: false };
  const trimmed = value.trim();
  return { ok: true, value: trimmed === "" ? null : trimmed };
}

export interface EndpointRoutesParams {
  app: FastifyInstance;
  endpointRepo: EndpointRepository;
  accountRepo: AccountRepository;
  demoEndpoints: DemoEndpointsService;
  terminalManager: TerminalManager;
}

export function registerEndpointRoutes(params: EndpointRoutesParams) {
  const { app, endpointRepo, accountRepo, demoEndpoints, terminalManager } = params;

  app.get("/api/endpoints", async (request) => {
    const own = await endpointRepo.findAllForAccount(request.accountId);
    const account = await accountRepo.findById(request.accountId);
    const merged = [
      ...own.map((e) => ({ ...e, isDemo: false as const })),
      ...(account?.showDemoEndpoints
        ? demoEndpoints.list(request.accountId).map((e) => ({ ...e, isDemo: true as const }))
        : []),
    ];
    return {
      endpoints: merged.map(
        ({
          id,
          label,
          host,
          port,
          username,
          userVerification,
          agentForward,
          description,
          isDemo,
        }) => ({
          id,
          label,
          host,
          port,
          username,
          userVerification,
          agentForward,
          description,
          isDemo,
        }),
      ),
    };
  });

  app.post<{
    Body: {
      label: string;
      host: string;
      port?: number;
      username?: string;
      userVerification?: string;
      agentForward?: boolean;
      description?: string | null;
    };
  }>("/api/endpoints", async (request, reply) => {
    try {
      // label + host are the two required fields (openapi.yaml marks them so, and
      // the MCP create path already enforces it). Reject empty/whitespace-only
      // rather than persisting a blank endpoint.
      const label = typeof request.body.label === "string" ? request.body.label.trim() : "";
      const host = typeof request.body.host === "string" ? request.body.host.trim() : "";
      if (!label || !host) {
        reply.status(400);
        return { error: "label and host are required" };
      }
      const uv = request.body.userVerification;
      if (uv !== undefined && !isUserVerification(uv)) {
        reply.status(400);
        return {
          error: `userVerification must be one of: ${USER_VERIFICATION_VALUES.join(", ")}`,
        };
      }
      if (
        request.body.agentForward !== undefined &&
        typeof request.body.agentForward !== "boolean"
      ) {
        reply.status(400);
        return { error: "agentForward must be a boolean" };
      }
      const desc = normalizeDescription(request.body.description);
      if (!desc.ok) {
        reply.status(400);
        return {
          error: `description must be a string up to ${ENDPOINT_DESCRIPTION_MAX_LENGTH} characters`,
        };
      }
      const id = randomUUID();
      await endpointRepo.create({
        id,
        accountId: request.accountId,
        label,
        host,
        port: request.body.port ?? 22,
        username: request.body.username ?? "shellwatch",
        userVerification: uv as UserVerification | undefined,
        agentForward: request.body.agentForward,
        description: desc.value,
      });
      return { status: "created", id };
    } catch (err) {
      app.log.error(err, "request failed");
      reply.status(400);
      return { error: (err as Error).message };
    }
  });

  app.put<{
    Params: { id: string };
    Body: {
      label?: string;
      host?: string;
      port?: number;
      username?: string;
      userVerification?: string;
      agentForward?: boolean;
      description?: string | null;
    };
  }>("/api/endpoints/:id", async (request, reply) => {
    try {
      if (isDemoEndpointId(request.params.id)) {
        reply.status(400);
        return { error: "Demo endpoints are read-only — toggle visibility instead" };
      }
      const body = request.body;
      if (body.userVerification !== undefined && !isUserVerification(body.userVerification)) {
        reply.status(400);
        return {
          error: `userVerification must be one of: ${USER_VERIFICATION_VALUES.join(", ")}`,
        };
      }
      if (body.agentForward !== undefined && typeof body.agentForward !== "boolean") {
        reply.status(400);
        return { error: "agentForward must be a boolean" };
      }
      const descriptionPatch: Partial<{ description: string | null }> = {};
      if (body.description !== undefined) {
        const desc = normalizeDescription(body.description);
        if (!desc.ok) {
          reply.status(400);
          return {
            error: `description must be a string up to ${ENDPOINT_DESCRIPTION_MAX_LENGTH} characters`,
          };
        }
        descriptionPatch.description = desc.value;
      }
      await endpointRepo.update(request.params.id, request.accountId, {
        ...body,
        userVerification: body.userVerification as UserVerification | undefined,
        ...descriptionPatch,
      });
      return { status: "updated" };
    } catch (err) {
      app.log.error(err, "request failed");
      reply.status(400);
      return { error: (err as Error).message };
    }
  });

  app.delete<{ Params: { id: string } }>("/api/endpoints/:id", async (request, reply) => {
    try {
      if (isDemoEndpointId(request.params.id)) {
        reply.status(400);
        return { error: "Demo endpoints are read-only — toggle visibility instead" };
      }
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
