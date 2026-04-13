import type { FastifyInstance } from "fastify";
import type { PendingActionStore } from "../../pending-action/index.js";
import type { WebSocketChannel } from "../../pending-action/ws-channel.js";
import { toActionView } from "../../pending-action/index.js";
import { isUserVerified } from "../../webauthn/signature-format.js";

export interface ActionRoutesParams {
  app: FastifyInstance;
  actionStore: PendingActionStore;
  wsChannel: WebSocketChannel;
}

export function registerActionRoutes(params: ActionRoutesParams) {
  const { app, actionStore, wsChannel } = params;

  app.get<{ Params: { actionId: string } }>("/api/actions/:actionId", async (request, reply) => {
    if (!request.accountId) {
      reply.status(401);
      return { error: "Not authenticated" };
    }

    const action = actionStore.get(request.params.actionId);
    if (!action) {
      reply.status(404);
      return { error: "Action not found" };
    }
    if (action.accountId !== request.accountId) {
      reply.status(403);
      return { error: "Access denied" };
    }

    return toActionView(action);
  });

  app.post<{
    Params: { actionId: string };
    Body: { authenticatorData: string; signature: string; clientDataJSON: string };
  }>("/api/actions/:actionId/resolve", async (request, reply) => {
    if (!request.accountId) {
      reply.status(401);
      return { error: "Not authenticated" };
    }

    const action = actionStore.get(request.params.actionId);
    if (!action) {
      reply.status(404);
      return { error: "Action not found" };
    }
    if (action.accountId !== request.accountId) {
      reply.status(403);
      return { error: "Access denied" };
    }
    if (action.status !== "pending") {
      reply.status(409);
      return { error: `Action is already ${action.status}` };
    }

    let resolved: boolean;

    if (action.type === "webauthn-sign") {
      const { authenticatorData, signature, clientDataJSON } = request.body ?? {};
      if (
        typeof authenticatorData !== "string" ||
        typeof signature !== "string" ||
        typeof clientDataJSON !== "string"
      ) {
        reply.status(400);
        return { error: "Missing required fields: authenticatorData, signature, clientDataJSON" };
      }
      const authDataBuf = Buffer.from(authenticatorData, "base64url");
      // Defense-in-depth: when the action (typically the originating endpoint)
      // requires UV, reject responses without the UV bit set so we fail fast
      // with a clear error. Cryptographic enforcement still happens downstream
      // when the SSH server verifies the signature against the sk-* pubkey and
      // its `verify-required` option; this check alone is not a primary gate.
      // For "preferred"/"discouraged" endpoints we accept either UV state.
      if (action.userVerification === "required" && !isUserVerified(authDataBuf)) {
        reply.status(400);
        return { error: "User verification required" };
      }
      resolved = actionStore.resolve(action.id, {
        requestId: action.id,
        authenticatorData: authDataBuf,
        signature: Buffer.from(signature, "base64url"),
        clientDataJSON,
      });
    } else {
      // key-approve: no payload needed
      resolved = actionStore.resolve(action.id);
    }

    if (!resolved) {
      reply.status(409);
      return { error: "Action could not be resolved" };
    }

    wsChannel.broadcastResolved(action.id, action.accountId);
    return { redirectTo: action.redirectTo };
  });

  app.post<{ Params: { actionId: string } }>(
    "/api/actions/:actionId/deny",
    async (request, reply) => {
      if (!request.accountId) {
        reply.status(401);
        return { error: "Not authenticated" };
      }

      const action = actionStore.get(request.params.actionId);
      if (!action) {
        reply.status(404);
        return { error: "Action not found" };
      }
      if (action.accountId !== request.accountId) {
        reply.status(403);
        return { error: "Access denied" };
      }
      if (action.status !== "pending") {
        reply.status(409);
        return { error: `Action is already ${action.status}` };
      }

      actionStore.deny(action.id);
      wsChannel.broadcastResolved(action.id, action.accountId);
      return { status: "denied" };
    },
  );
}
