import { generateRegistrationOptions } from "@simplewebauthn/server";
import { and, eq } from "drizzle-orm";
import type { FastifyInstance } from "fastify";
import type { ShellWatchDB } from "../db/connection.js";
import { CREDENTIAL_STATE } from "../db/repositories/index.js";
import { webauthnCredentials } from "../db/schema.js";
import { storeChallenge } from "./challenge-store.js";
import { insertCredentialRow, verifyAndDecodeRegistration } from "./credential-store.js";
import { sha256Fingerprint } from "./fingerprint.js";
import {
  consumeInviteSlot,
  createInviteSlot,
  findInviteByToken,
  findInviteForAccount,
  type InviteSlot,
} from "./invite-store.js";
import type { RateLimitConfig } from "./routes.js";
import { buildPublicKeyBlob, toSkPublicKeyBlob } from "./ssh-key-format.js";

export interface PasskeyInviteRoutesParams {
  app: FastifyInstance;
  db: ShellWatchDB;
  rpId: string;
  trustedOrigins: string[];
  rateLimitConfig: RateLimitConfig;
}

/**
 * Returns the SHA256 fingerprint string the credentials list also displays,
 * computed the same way (see credentials.ts). Returned to device B after
 * registration so the user can eyeball-compare it against the fingerprint
 * that shows up on device A's confirm screen — defends against an intercepted
 * invite link silently enrolling an attacker's authenticator.
 */
function fingerprintFromOpenSsh(authorizedKeysEntry: string | null): string | null {
  if (!authorizedKeysEntry) return null;
  return sha256Fingerprint(
    toSkPublicKeyBlob(buildPublicKeyBlob({ publicKey: authorizedKeysEntry })),
  );
}

/** Shape returned to UI / invite-link consumer. */
function publicInviteShape(slot: InviteSlot) {
  return {
    label: slot.label,
    expiresAt: new Date(slot.expiresAt).toISOString(),
    createdAt: new Date(slot.createdAt).toISOString(),
    token: slot.token,
  };
}

export function registerPasskeyInviteRoutes(params: PasskeyInviteRoutesParams) {
  const { app, db, rpId, trustedOrigins, rateLimitConfig } = params;

  // --- Authenticated: create or supersede the invite slot for the account ---
  app.post<{ Body: { label?: string } }>(
    "/api/webauthn/invite",
    {
      config: {
        rateLimit: {
          max: rateLimitConfig.passkeyRegister.max,
          timeWindow: `${rateLimitConfig.passkeyRegister.windowMinutes} minutes`,
        },
      },
    },
    async (request, reply) => {
      const label = request.body?.label?.trim() || "Invited passkey";
      if (label.length > 64) {
        reply.status(400);
        return { error: "Label must be 64 characters or less" };
      }
      const slot = createInviteSlot({ accountId: request.accountId, label });
      request.log.info(
        { event: "passkey_invite.created", accountId: request.accountId },
        "passkey invite created",
      );
      return { invite: publicInviteShape(slot) };
    },
  );

  // --- Authenticated: read the active invite slot, if any ---
  app.get("/api/webauthn/invite", async (request, reply) => {
    const slot = findInviteForAccount(request.accountId);
    if (!slot) {
      reply.status(404);
      return { error: "No active invite" };
    }
    return { invite: publicInviteShape(slot) };
  });

  // --- Authenticated: confirm a pending credential ---
  app.post<{ Params: { id: string } }>(
    "/api/webauthn/credentials/:id/confirm",
    async (request, reply) => {
      const { id } = request.params;
      const cred = db
        .select({
          id: webauthnCredentials.id,
          state: webauthnCredentials.state,
          revoked: webauthnCredentials.revoked,
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
        return { error: "Credential is revoked" };
      }
      if (cred.state === CREDENTIAL_STATE.active) {
        reply.status(400);
        return { error: "Credential is already active" };
      }

      db.update(webauthnCredentials)
        .set({ state: CREDENTIAL_STATE.active })
        .where(eq(webauthnCredentials.id, id))
        .run();

      request.log.info(
        { event: "passkey_invite.confirmed", credentialId: id, accountId: request.accountId },
        "passkey invite confirmed",
      );
      return { status: "active" };
    },
  );

  // --- Public: fetch invite metadata by token (for the registration page) ---
  app.get<{ Params: { token: string } }>(
    "/api/passkey-invite/:token",
    {
      config: {
        rateLimit: {
          max: rateLimitConfig.passkeyRegister.max,
          timeWindow: `${rateLimitConfig.passkeyRegister.windowMinutes} minutes`,
        },
      },
    },
    async (request, reply) => {
      const slot = findInviteByToken(request.params.token);
      if (!slot) {
        reply.status(404);
        return { error: "Invite not found or expired" };
      }
      return {
        label: slot.label,
        expiresAt: new Date(slot.expiresAt).toISOString(),
      };
    },
  );

  // --- Public: registration options for an invite ---
  app.post<{ Body: { token: string } }>(
    "/api/passkey-invite/register/options",
    {
      config: {
        rateLimit: {
          max: rateLimitConfig.passkeyRegister.max,
          timeWindow: `${rateLimitConfig.passkeyRegister.windowMinutes} minutes`,
        },
      },
    },
    async (request, reply) => {
      const { token } = request.body ?? {};
      if (!token || typeof token !== "string") {
        reply.status(400);
        return { error: "Token is required" };
      }
      const slot = findInviteByToken(token);
      if (!slot) {
        reply.status(404);
        return { error: "Invite not found or expired" };
      }

      // ExcludeCredentials scoped to the inviting account, same as the
      // authenticated registration flow — prevents duplicate enrollment of an
      // authenticator that's already on the account.
      const existing = db
        .select({ credentialId: webauthnCredentials.credentialId })
        .from(webauthnCredentials)
        .where(eq(webauthnCredentials.accountId, slot.accountId))
        .all();

      const userName = slot.label.slice(0, 64);
      const options = await generateRegistrationOptions({
        rpName: "ShellWatch",
        rpID: rpId,
        userName,
        userDisplayName: slot.label,
        attestationType: "none",
        authenticatorSelection: {
          residentKey: "preferred",
          userVerification: "required",
        },
        supportedAlgorithmIDs: [-7],
        excludeCredentials: existing.map((c) => ({ id: c.credentialId })),
      });

      const challengeId = storeChallenge(options.challenge);
      return { ...options, challengeId };
    },
  );

  // --- Public: complete invite registration ---
  app.post<{
    Body: { token: string; challengeId: string; credential: unknown; label?: string };
  }>(
    "/api/passkey-invite/register",
    {
      config: {
        rateLimit: {
          max: rateLimitConfig.passkeyRegister.max,
          timeWindow: `${rateLimitConfig.passkeyRegister.windowMinutes} minutes`,
        },
      },
    },
    async (request, reply) => {
      const { token, challengeId, credential, label } = request.body ?? ({} as never);
      if (!token || typeof token !== "string") {
        reply.status(400);
        return { error: "Token is required" };
      }
      const trimmedLabel = typeof label === "string" ? label.trim() : "";
      if (trimmedLabel.length > 64) {
        reply.status(400);
        return { error: "Label must be 64 characters or less" };
      }
      const slot = findInviteByToken(token);
      if (!slot) {
        reply.status(404);
        return { error: "Invite not found or expired" };
      }

      const result = await verifyAndDecodeRegistration({
        challengeId,
        credential,
        rpId,
        trustedOrigins,
      });
      if (!result.ok) {
        reply.status(400);
        return { error: result.error };
      }

      // Atomically: drop the invite slot, then insert the credential row in
      // `pending_confirmation`. If a parallel attempt already consumed the
      // slot we abort before any DB mutation, keeping single-use semantics.
      const consumed = consumeInviteSlot(slot.accountId);
      if (!consumed || consumed.token !== token) {
        reply.status(409);
        return { error: "Invite was already used" };
      }

      const decoded = {
        ...result.decoded,
        baseLabel: trimmedLabel || slot.label,
      };
      const inserted = db.transaction((tx) => {
        const { id, label: insertedLabel } = insertCredentialRow(tx, slot.accountId, decoded);
        tx.update(webauthnCredentials)
          .set({ state: CREDENTIAL_STATE.pendingConfirmation })
          .where(eq(webauthnCredentials.id, id))
          .run();
        return { id, label: insertedLabel };
      });

      request.log.info(
        {
          event: "passkey_invite.registered",
          credentialId: inserted.id,
          accountId: slot.accountId,
        },
        "passkey invite registered (pending confirmation)",
      );

      return {
        status: "registered",
        label: inserted.label,
        fingerprint: fingerprintFromOpenSsh(result.decoded.authorizedKeysEntry),
      };
    },
  );
}
