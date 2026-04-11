import type { FastifyInstance } from "fastify";
import type { PushSubscriptionRepository } from "../../db/repositories/push-subscription-repo.js";

export interface PushRoutesParams {
  app: FastifyInstance;
  pushSubRepo: PushSubscriptionRepository;
  vapidPublicKey: string;
}

export function registerPushRoutes(params: PushRoutesParams) {
  const { app, pushSubRepo, vapidPublicKey } = params;

  // Return VAPID public key so the client can subscribe
  app.get("/api/push/vapid-key", async () => {
    return { publicKey: vapidPublicKey };
  });

  // Save push subscription
  app.post<{
    Body: { endpoint: string; keys: { p256dh: string; auth: string } };
  }>("/api/push/subscribe", async (request, reply) => {
    if (!request.accountId) {
      reply.status(401);
      return { error: "Not authenticated" };
    }
    const { endpoint, keys } = request.body;
    if (!endpoint || !keys?.p256dh || !keys?.auth) {
      reply.status(400);
      return { error: "Invalid subscription: endpoint, keys.p256dh, and keys.auth are required" };
    }
    const sub = pushSubRepo.upsert({
      accountId: request.accountId,
      endpoint,
      p256dh: keys.p256dh,
      auth: keys.auth,
    });
    return { id: sub.id };
  });

  // Remove push subscription
  app.delete<{ Body: { endpoint: string } }>("/api/push/subscribe", async (request, reply) => {
    if (!request.accountId) {
      reply.status(401);
      return { error: "Not authenticated" };
    }
    const { endpoint } = request.body;
    if (!endpoint) {
      reply.status(400);
      return { error: "endpoint is required" };
    }
    pushSubRepo.deleteByEndpoint(endpoint);
    return { ok: true };
  });
}
