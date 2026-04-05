import { eq } from "drizzle-orm";
import type { FastifyInstance } from "fastify";
import type { ShellWatchDB } from "../../db/connection.js";
import type { AccountRepository } from "../../db/index.js";
import {
  accounts as accountsTable,
  apiKeys as apiKeysTable,
  endpointKeys,
  endpoints as endpointsTable,
  sessionHistory,
  webauthnCredentials,
} from "../../db/schema.js";

export interface AccountRoutesParams {
  app: FastifyInstance;
  basePath: string;
  accountRepo: AccountRepository;
  db?: ShellWatchDB | null;
}

export function registerAccountRoutes(params: AccountRoutesParams) {
  const { app, basePath: base, accountRepo, db = null } = params;

  // --- Auth: current account ---
  app.get(`${base}/api/auth/me`, async (request, reply) => {
    const accountId = request.accountId;
    if (!accountId) {
      reply.status(401);
      return { error: "Not authenticated" };
    }
    const account = await accountRepo.findById(accountId);
    if (!account) {
      reply.status(401);
      return { error: "Account not found" };
    }
    return {
      id: account.id,
      name: account.name,
      type: account.type,
      isAdmin: account.isAdmin,
    };
  });

  app.put<{ Body: { name?: string } }>(`${base}/api/auth/me`, async (request, reply) => {
    const accountId = request.accountId;
    if (!accountId) {
      reply.status(401);
      return { error: "Not authenticated" };
    }
    const { name } = request.body;
    if (name !== undefined) {
      const trimmed = name.trim();
      if (!trimmed) {
        reply.status(400);
        return { error: "Name cannot be empty" };
      }
      await accountRepo.update(accountId, { name: trimmed });
    }
    return { status: "updated" };
  });

  // --- Account Management (admin only) ---

  app.get(`${base}/api/accounts`, async (request, reply) => {
    if (!request.accountId || !accountRepo.isAdmin(request.accountId)) {
      reply.status(403);
      return { error: "Admin access required" };
    }
    const all = await accountRepo.findAll();
    return {
      accounts: all.map((a) => ({
        id: a.id,
        name: a.name,
        type: a.type,
        isAdmin: a.isAdmin,
        enabled: a.enabled,
        maxSessions: a.maxSessions,
        lastUsedAt: a.lastUsedAt,
        createdAt: a.createdAt,
      })),
    };
  });

  app.delete<{ Params: { id: string } }>(`${base}/api/accounts/:id`, async (request, reply) => {
    if (!request.accountId || !accountRepo.isAdmin(request.accountId)) {
      reply.status(403);
      return { error: "Admin access required" };
    }
    const targetId = request.params.id;

    // Cannot delete yourself
    if (targetId === request.accountId) {
      reply.status(400);
      return { error: "Cannot delete your own account" };
    }

    // Cannot delete the admin account
    if (accountRepo.isAdmin(targetId)) {
      reply.status(400);
      return { error: "Cannot delete the admin account" };
    }

    // Hard-delete: cascade all owned data (order matters for FK constraints)
    if (db) {
      // Get the account's endpoint IDs for junction table cleanup
      const accountEndpoints = db
        .select({ id: endpointsTable.id })
        .from(endpointsTable)
        .where(eq(endpointsTable.accountId, targetId))
        .all();
      for (const ep of accountEndpoints) {
        db.delete(endpointKeys).where(eq(endpointKeys.endpointId, ep.id)).run();
      }
      db.delete(sessionHistory).where(eq(sessionHistory.accountId, targetId)).run();
      db.delete(webauthnCredentials).where(eq(webauthnCredentials.accountId, targetId)).run();
      db.delete(apiKeysTable).where(eq(apiKeysTable.accountId, targetId)).run();
      db.delete(endpointsTable).where(eq(endpointsTable.accountId, targetId)).run();
      db.delete(accountsTable).where(eq(accountsTable.id, targetId)).run();
    }

    return { status: "deleted" };
  });
}
