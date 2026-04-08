import { and, eq } from "drizzle-orm";
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
import { formatEndpointAddress } from "../../utils/endpoint-address.js";

export interface AccountRoutesParams {
  app: FastifyInstance;
  accountRepo: AccountRepository;
  db?: ShellWatchDB | null;
}

export function registerAccountRoutes(params: AccountRoutesParams) {
  const { app, accountRepo, db = null } = params;

  // --- Auth: current account ---
  app.get("/api/auth/me", async (request, reply) => {
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
      isAdmin: account.isAdmin,
      agentForward: account.agentForward,
    };
  });

  app.put<{ Body: { name?: string; agentForward?: boolean } }>(
    "/api/auth/me",
    async (request, reply) => {
      const accountId = request.accountId;
      if (!accountId) {
        reply.status(401);
        return { error: "Not authenticated" };
      }
      const { name, agentForward } = request.body;
      if (name !== undefined) {
        const trimmed = name.trim();
        if (!trimmed) {
          reply.status(400);
          return { error: "Name cannot be empty" };
        }
        await accountRepo.update(accountId, { name: trimmed });
      }
      if (agentForward !== undefined) {
        await accountRepo.update(accountId, { agentForward });
      }
      return { status: "updated" };
    },
  );

  // --- Account Management (admin only) ---

  app.get("/api/accounts", async (request, reply) => {
    if (!request.accountId || !accountRepo.isAdmin(request.accountId)) {
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

  // --- Export seed config (admin only) ---

  app.get("/api/accounts/export-seed", async (request, reply) => {
    if (!request.accountId || !accountRepo.isAdmin(request.accountId)) {
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
        and(eq(webauthnCredentials.accountId, adminId), eq(webauthnCredentials.revoked, false)),
      )
      .all();

    // Fetch endpoints
    const eps = db
      .select({
        label: endpointsTable.label,
        host: endpointsTable.host,
        port: endpointsTable.port,
        username: endpointsTable.username,
        passkeyId: endpointsTable.passkeyId,
      })
      .from(endpointsTable)
      .where(eq(endpointsTable.accountId, adminId))
      .all();

    // Build passkey internal ID → credentialId lookup for endpoint references
    const passkeyIdToCredentialId = new Map<string, string>();
    for (const pk of passkeys) {
      passkeyIdToCredentialId.set(pk.id, pk.credentialId);
    }

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

    const seedEndpoints = eps.map((ep) => {
      const address = formatEndpointAddress({
        username: ep.username,
        host: ep.host,
        port: ep.port,
      });
      const result: { label: string; address: string; passkeyCredentialRef?: string } = {
        label: ep.label,
        address,
      };
      if (ep.passkeyId) {
        const credId = passkeyIdToCredentialId.get(ep.passkeyId);
        if (credId) result.passkeyCredentialRef = credId;
      }
      return result;
    });

    return { passkeys: seedPasskeys, endpoints: seedEndpoints };
  });
}
