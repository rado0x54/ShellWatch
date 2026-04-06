import { and, eq, ne } from "drizzle-orm";
import type { FastifyInstance } from "fastify";
import type { ShellWatchDB } from "../db/connection.js";
import { webauthnCredentials } from "../db/schema.js";
import { detectAlgorithm, computeFingerprint } from "./credential-utils.js";
import { getSshdConfigLine } from "./ssh-key-format.js";

export interface CredentialRoutesParams {
  app: FastifyInstance;
  db: ShellWatchDB;
  basePath: string;
}

export function registerCredentialRoutes(params: CredentialRoutesParams) {
  const { app, db, basePath } = params;

  // --- List Registered Credentials (scoped to account) ---
  app.get(`${basePath}/api/webauthn/credentials`, async (request, reply) => {
    if (!request.accountId) {
      reply.status(401);
      return { error: "Not authenticated" };
    }
    const creds = db
      .select({
        id: webauthnCredentials.id,
        credentialId: webauthnCredentials.credentialId,
        publicKey: webauthnCredentials.publicKey,
        publicKeyOpenSsh: webauthnCredentials.publicKeyOpenSsh,
        label: webauthnCredentials.label,
        revoked: webauthnCredentials.revoked,
        createdAt: webauthnCredentials.createdAt,
        lastUsedAt: webauthnCredentials.lastUsedAt,
      })
      .from(webauthnCredentials)
      .where(eq(webauthnCredentials.accountId, request.accountId))
      .all();

    return {
      credentials: creds.map((c) => ({
        id: c.id,
        credentialId: c.credentialId,
        label: c.label,
        algorithm: detectAlgorithm(c.publicKey),
        fingerprint: computeFingerprint(c.publicKey),
        authorizedKeysEntry: c.publicKeyOpenSsh ?? null,
        revoked: c.revoked,
        createdAt: c.createdAt,
        lastUsedAt: c.lastUsedAt,
      })),
      sshdConfig: getSshdConfigLine(),
    };
  });

  // --- Rename Credential ---
  app.patch<{ Params: { id: string }; Body: { label: string } }>(
    `${basePath}/api/webauthn/credentials/:id/label`,
    async (request, reply) => {
      if (!request.accountId) {
        reply.status(401);
        return { error: "Not authenticated" };
      }
      const { id } = request.params;
      const { label } = request.body;
      if (!label?.trim()) {
        reply.status(400);
        return { error: "Label is required" };
      }

      const cred = db
        .select({ id: webauthnCredentials.id })
        .from(webauthnCredentials)
        .where(
          and(eq(webauthnCredentials.id, id), eq(webauthnCredentials.accountId, request.accountId)),
        )
        .get();
      if (!cred) {
        reply.status(404);
        return { error: "Credential not found" };
      }

      const trimmed = label.trim();

      // Enforce unique label within account
      const conflict = db
        .select({ id: webauthnCredentials.id })
        .from(webauthnCredentials)
        .where(
          and(
            eq(webauthnCredentials.accountId, request.accountId),
            eq(webauthnCredentials.label, trimmed),
            ne(webauthnCredentials.id, id),
          ),
        )
        .get();
      if (conflict) {
        reply.status(409);
        return { error: "A passkey with this label already exists" };
      }

      db.update(webauthnCredentials)
        .set({ label: trimmed })
        .where(
          and(eq(webauthnCredentials.id, id), eq(webauthnCredentials.accountId, request.accountId)),
        )
        .run();

      return { status: "updated" };
    },
  );

  // --- Revoke Credential (permanent, scoped to account) ---
  app.post<{ Params: { id: string } }>(
    `${basePath}/api/webauthn/credentials/:id/revoke`,
    async (request, reply) => {
      if (!request.accountId) {
        reply.status(401);
        return { error: "Not authenticated" };
      }
      const { id } = request.params;

      // Verify ownership
      const cred = db
        .select({ id: webauthnCredentials.id, revoked: webauthnCredentials.revoked })
        .from(webauthnCredentials)
        .where(
          and(eq(webauthnCredentials.id, id), eq(webauthnCredentials.accountId, request.accountId)),
        )
        .get();
      if (!cred) {
        reply.status(404);
        return { error: "Credential not found" };
      }
      if (cred.revoked) {
        reply.status(400);
        return { error: "Credential is already revoked" };
      }

      // Prevent revoking the last active passkey
      const activeCount = db
        .select({ id: webauthnCredentials.id })
        .from(webauthnCredentials)
        .where(
          and(
            eq(webauthnCredentials.accountId, request.accountId),
            eq(webauthnCredentials.revoked, false),
          ),
        )
        .all().length;
      if (activeCount <= 1) {
        reply.status(400);
        return { error: "Cannot revoke the last active passkey" };
      }

      // Revoke the credential
      db.update(webauthnCredentials)
        .set({ revoked: true })
        .where(eq(webauthnCredentials.id, id))
        .run();

      return { status: "revoked" };
    },
  );
}
