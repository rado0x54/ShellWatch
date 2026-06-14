// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { and, eq, ne } from "drizzle-orm";
import type { FastifyInstance } from "fastify";
import type { ShellWatchDB } from "../db/connection.js";
import { CREDENTIAL_STATE } from "../db/repositories/credential-queries.js";
import { webauthnCredentials } from "../db/schema.js";
import type { HydraAdminClient } from "../hydra/admin-client.js";
import { detectAlgorithm } from "./credential-utils.js";
import { fingerprintFromAuthorizedKeys } from "./fingerprint.js";
import { getSshdConfigLine } from "./ssh-key-format.js";
import { requireStepUp } from "./stepup-gate.js";
import { STEPUP_ACTION } from "./stepup-store.js";

export interface CredentialRoutesParams {
  app: FastifyInstance;
  db: ShellWatchDB;
  /** Hydra admin — used to optionally invalidate all sessions on revoke (#219). */
  admin: HydraAdminClient;
}

export function registerCredentialRoutes(params: CredentialRoutesParams) {
  const { app, db, admin } = params;

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
  // Step-up gated via preHandler. Label edits (PATCH /label) intentionally
  // don't require step-up — labels are cosmetic, not a factor change.
  app.post<{ Params: { id: string }; Body: { invalidateSessions?: boolean } }>(
    "/api/webauthn/credentials/:id/revoke",
    { preHandler: requireStepUp(STEPUP_ACTION.revokePasskey) },
    async (request, reply) => {
      const { id } = request.params;
      const invalidateSessions = request.body?.invalidateSessions === true;

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

      request.log.info(
        {
          event: "passkey.revoked",
          accountId: request.accountId,
          credentialRowId: id,
        },
        "passkey revoked",
      );

      // Optionally terminate every active session for the account (#219).
      // Hydra keys sessions by subject, not credential, so this is necessarily
      // account-wide: it kills all consent grants + login (SSO) sessions, so the
      // revoked-passkey holder — and every other device/client — must log in
      // again. Covered by the same revoke_passkey step-up above (one passkey).
      // The credential is already revoked; a Hydra hiccup here shouldn't fail
      // the whole request, so report it back instead of 500-ing.
      let sessionsInvalidated = false;
      if (invalidateSessions) {
        try {
          await admin.revokeConsentSessions(request.accountId);
          await admin.revokeLoginSessions(request.accountId);
          sessionsInvalidated = true;
          request.log.info(
            { event: "passkey.revoked.sessions_invalidated", accountId: request.accountId },
            "all sessions invalidated after passkey revoke",
          );
        } catch (err) {
          request.log.error(
            {
              err,
              event: "passkey.revoked.sessions_invalidate_failed",
              accountId: request.accountId,
            },
            "failed to invalidate sessions after passkey revoke",
          );
        }
      }

      return { status: "revoked", sessionsInvalidated };
    },
  );
}
