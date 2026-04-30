import { and, eq, ne } from "drizzle-orm";
import type { FastifyInstance } from "fastify";
import type { ShellWatchDB } from "../db/connection.js";
import { CREDENTIAL_STATE } from "../db/repositories/credential-queries.js";
import { webauthnCredentials } from "../db/schema.js";
import { detectAlgorithm } from "./credential-utils.js";
import { fingerprintFromAuthorizedKeys } from "./fingerprint.js";
import { getSshdConfigLine } from "./ssh-key-format.js";
import { requireStepUp } from "./stepup-gate.js";
import { STEPUP_ACTION } from "./stepup-store.js";

export interface CredentialRoutesParams {
  app: FastifyInstance;
  db: ShellWatchDB;
}

export function registerCredentialRoutes(params: CredentialRoutesParams) {
  const { app, db } = params;

  // --- List Registered Credentials (scoped to account) ---
  app.get("/api/webauthn/credentials", async (request) => {
    const creds = db
      .select({
        id: webauthnCredentials.id,
        credentialId: webauthnCredentials.credentialId,
        publicKey: webauthnCredentials.publicKey,
        publicKeyOpenSsh: webauthnCredentials.publicKeyOpenSsh,
        label: webauthnCredentials.label,
        revoked: webauthnCredentials.revoked,
        state: webauthnCredentials.state,
        createdAt: webauthnCredentials.createdAt,
        lastUsedAt: webauthnCredentials.lastUsedAt,
      })
      .from(webauthnCredentials)
      .where(eq(webauthnCredentials.accountId, request.accountId))
      .all();

    return {
      credentials: creds.map((c) => {
        const isActive = c.state === CREDENTIAL_STATE.active;
        // The fingerprint is surfaced for pending creds too — it's a public
        // hash the user reads aloud / eyeballs across two devices to confirm
        // the right passkey is being activated (see /passkey-invite confirm
        // flow). The SSH `authorizedKeysEntry` stays withheld until confirmed:
        // copying it into authorized_keys would let the new passkey reach
        // servers before the user has approved it.
        return {
          id: c.id,
          credentialId: c.credentialId,
          label: c.label,
          algorithm: detectAlgorithm(c.publicKey),
          fingerprint: fingerprintFromAuthorizedKeys(c.publicKeyOpenSsh),
          authorizedKeysEntry: isActive ? (c.publicKeyOpenSsh ?? null) : null,
          revoked: c.revoked,
          state: c.state,
          createdAt: c.createdAt,
          lastUsedAt: c.lastUsedAt,
        };
      }),
      sshdConfig: getSshdConfigLine(),
    };
  });

  // --- Rename Credential ---
  app.patch<{ Params: { id: string }; Body: { label: string } }>(
    "/api/webauthn/credentials/:id/label",
    async (request, reply) => {
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
    "/api/webauthn/credentials/:id/revoke",
    async (request, reply) => {
      // Step-up gate: single endpoint, single token. Label edits (PATCH
      // /label) intentionally don't require step-up — labels are cosmetic,
      // not a factor change.
      if (
        !requireStepUp({
          request,
          reply,
          action: STEPUP_ACTION.revokePasskey,
        })
      ) {
        return reply;
      }

      const { id } = request.params;

      // Verify ownership
      const cred = db
        .select({
          id: webauthnCredentials.id,
          revoked: webauthnCredentials.revoked,
          state: webauthnCredentials.state,
        })
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

      // Pending credentials don't count as the user's last login factor —
      // they can't log in. Only enforce the "last active passkey" guard for
      // active credentials.
      if (cred.state === CREDENTIAL_STATE.active) {
        const activeCount = db
          .select({ id: webauthnCredentials.id })
          .from(webauthnCredentials)
          .where(
            and(
              eq(webauthnCredentials.accountId, request.accountId),
              eq(webauthnCredentials.revoked, false),
              eq(webauthnCredentials.state, CREDENTIAL_STATE.active),
            ),
          )
          .all().length;
        if (activeCount <= 1) {
          reply.status(400);
          return { error: "Cannot revoke the last active passkey" };
        }
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
