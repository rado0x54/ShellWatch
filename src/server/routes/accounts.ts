import { and, eq } from "drizzle-orm";
import type { FastifyInstance } from "fastify";
import type { ShellWatchDB } from "../../db/connection.js";
import type { AccountRepository } from "../../db/index.js";
import { CREDENTIAL_STATE } from "../../db/repositories/credential-queries.js";
import {
  accounts as accountsTable,
  apiKeys as apiKeysTable,
  endpoints as endpointsTable,
  sessionHistory,
  webauthnCredentials,
} from "../../db/schema.js";
import { formatEndpointAddress } from "../../utils/endpoint-address.js";
import type { AccountLifecycle } from "../account-lifecycle.js";

export interface AccountRoutesParams {
  app: FastifyInstance;
  accountRepo: AccountRepository;
  db?: ShellWatchDB | null;
  accountLifecycle: AccountLifecycle;
}

export function registerAccountRoutes(params: AccountRoutesParams) {
  const { app, accountRepo, db = null, accountLifecycle } = params;

  // --- Auth: current account ---
  app.get("/api/auth/me", async (request, reply) => {
    const account = await accountRepo.findById(request.accountId);
    if (!account) {
      reply.status(401);
      return { error: "Account not found" };
    }
    return {
      id: account.id,
      name: account.name,
      isAdmin: account.isAdmin,
      agentForward: account.agentForward,
    };
  });

  app.put<{ Body: { name?: string; agentForward?: boolean } }>(
    "/api/auth/me",
    async (request, reply) => {
      const accountId = request.accountId;
      const { name, agentForward } = request.body;
      const updates: Partial<{ name: string; agentForward: boolean }> = {};
      if (name !== undefined) {
        const trimmed = name.trim();
        if (!trimmed) {
          reply.status(400);
          return { error: "Name cannot be empty" };
        }
        updates.name = trimmed;
      }
      if (agentForward !== undefined) {
        updates.agentForward = agentForward;
      }
      if (Object.keys(updates).length > 0) {
        await accountRepo.update(accountId, updates);
      }
      return { status: "updated" };
    },
  );

  // --- Account Management (admin only) ---

  app.get("/api/accounts", async (request, reply) => {
    if (!accountRepo.isAdmin(request.accountId)) {
      reply.status(403);
      return { error: "Admin access required" };
    }
    const all = await accountRepo.findAll();
    return {
      accounts: all.map((a) => ({
        id: a.id,
        name: a.name,
        isAdmin: a.isAdmin,
        enabled: a.enabled,
        maxSessions: a.maxSessions,
        agentForward: a.agentForward,
        lastUsedAt: a.lastUsedAt,
        createdAt: a.createdAt,
      })),
    };
  });

  app.delete<{ Params: { id: string } }>("/api/accounts/:id", async (request, reply) => {
    if (!accountRepo.isAdmin(request.accountId)) {
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
      db.delete(sessionHistory).where(eq(sessionHistory.accountId, targetId)).run();
      db.delete(webauthnCredentials).where(eq(webauthnCredentials.accountId, targetId)).run();
      db.delete(apiKeysTable).where(eq(apiKeysTable.accountId, targetId)).run();
      db.delete(endpointsTable).where(eq(endpointsTable.accountId, targetId)).run();
      db.delete(accountsTable).where(eq(accountsTable.id, targetId)).run();
    }

    // Subscribers (TerminalManager teardown — #122, MCP transport map — #134,
    // future per-account caches) react synchronously via the lifecycle bus.
    // Emitted unconditionally — even if `db` is null (test path), in-memory
    // cleanup still needs to run; the event represents intent, not the DB write.
    accountLifecycle.emitDeleted(targetId);

    return { status: "deleted" };
  });

  // --- Export seed config (admin only) ---

  app.get("/api/accounts/export-seed", async (request, reply) => {
    if (!accountRepo.isAdmin(request.accountId)) {
      reply.status(403);
      return { error: "Admin access required" };
    }
    if (!db) {
      reply.status(500);
      return { error: "Database not available" };
    }

    const adminId = request.accountId;

    // Fetch non-revoked passkeys (include internal id for endpoint cross-reference)
    const passkeys = db
      .select({
        id: webauthnCredentials.id,
        credentialId: webauthnCredentials.credentialId,
        publicKey: webauthnCredentials.publicKey,
        counter: webauthnCredentials.counter,
        transports: webauthnCredentials.transports,
        label: webauthnCredentials.label,
      })
      .from(webauthnCredentials)
      .where(
        and(
          eq(webauthnCredentials.accountId, adminId),
          eq(webauthnCredentials.revoked, false),
          eq(webauthnCredentials.state, CREDENTIAL_STATE.active),
        ),
      )
      .all();

    // Fetch endpoints
    const eps = db
      .select({
        label: endpointsTable.label,
        host: endpointsTable.host,
        port: endpointsTable.port,
        username: endpointsTable.username,
      })
      .from(endpointsTable)
      .where(eq(endpointsTable.accountId, adminId))
      .all();

    const seedPasskeys = passkeys.map((pk) => {
      let transports: string[] = [];
      if (pk.transports) {
        try {
          transports = JSON.parse(pk.transports);
        } catch {
          // Malformed JSON — skip transports
        }
      }
      return {
        credentialId: pk.credentialId,
        publicKeyHex: pk.publicKey.toString("hex"),
        counter: pk.counter,
        transports,
        label: pk.label,
      };
    });

    const seedEndpoints = eps.map((ep) => ({
      label: ep.label,
      address: formatEndpointAddress({
        username: ep.username,
        host: ep.host,
        port: ep.port,
      }),
    }));

    return { passkeys: seedPasskeys, endpoints: seedEndpoints };
  });
}
