import { generateRegistrationOptions } from "@simplewebauthn/server";
import { and, eq } from "drizzle-orm";
import type { FastifyInstance } from "fastify";
import type { ShellWatchDB } from "../db/connection.js";
import {
  CREDENTIAL_STATE,
  inviteStatus,
  type PasskeyInviteInfo,
  type PasskeyInviteRepository,
} from "../db/repositories/index.js";
import { webauthnCredentials } from "../db/schema.js";
import { storeChallenge } from "./challenge-store.js";
import { insertCredentialRow, verifyAndDecodeRegistration } from "./credential-store.js";
import type { RateLimitConfig } from "./routes.js";

export interface PasskeyInviteRoutesParams {
  app: FastifyInstance;
  db: ShellWatchDB;
  inviteRepo: PasskeyInviteRepository;
  rpId: string;
  trustedOrigins: string[];
  rateLimitConfig: RateLimitConfig;
}

/**
 * Shape returned to UI / invite link consumer. Hides the raw token from list
 * endpoints (the token is only visible at create-time so the inviter can copy
 * it once); reveals it only on the create response.
 */
function publicInviteShape(invite: PasskeyInviteInfo, includeToken: boolean) {
  return {
    id: invite.id,
    label: invite.label,
    expiresAt: invite.expiresAt,
    createdAt: invite.createdAt,
    consumedAt: invite.consumedAt,
    revokedAt: invite.revokedAt,
    credentialId: invite.credentialId,
    status: inviteStatus(invite),
    ...(includeToken ? { token: invite.token } : {}),
  };
}

export function registerPasskeyInviteRoutes(params: PasskeyInviteRoutesParams) {
  const { app, db, inviteRepo, rpId, trustedOrigins, rateLimitConfig } = params;

  // --- Authenticated: create invite ---
  app.post<{ Body: { label?: string } }>(
    "/api/webauthn/invites",
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
      const invite = inviteRepo.create({ accountId: request.accountId, label });
      request.log.info(
        { event: "passkey_invite.created", inviteId: invite.id, accountId: request.accountId },
        "passkey invite created",
      );
      return { invite: publicInviteShape(invite, true) };
    },
  );

  // --- Authenticated: list invites for account ---
  app.get("/api/webauthn/invites", async (request) => {
    const invites = inviteRepo.listForAccount(request.accountId);
    return {
      invites: invites.map((i) => publicInviteShape(i, false)),
    };
  });

  // --- Authenticated: revoke an invite ---
  app.post<{ Params: { id: string } }>(
    "/api/webauthn/invites/:id/revoke",
    async (request, reply) => {
      const { id } = request.params;
      const invite = inviteRepo.findByIdForAccount(id, request.accountId);
      if (!invite) {
        reply.status(404);
        return { error: "Invite not found" };
      }
      const status = inviteStatus(invite);
      if (status === "revoked") {
        reply.status(400);
        return { error: "Invite already revoked" };
      }

      inviteRepo.revoke(id, request.accountId);

      // If the invite already produced a (still-pending) credential, revoke it
      // too. This makes "revoke invite" a single, complete cleanup action even
      // after the device-B registration step has succeeded but before the
      // device-A confirm step.
      if (invite.credentialId) {
        db.update(webauthnCredentials)
          .set({ revoked: true })
          .where(
            and(
              eq(webauthnCredentials.id, invite.credentialId),
              eq(webauthnCredentials.state, CREDENTIAL_STATE.pendingConfirmation),
            ),
          )
          .run();
      }

      request.log.info(
        { event: "passkey_invite.revoked", inviteId: id, accountId: request.accountId },
        "passkey invite revoked",
      );
      return { status: "revoked" };
    },
  );

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
      const invite = inviteRepo.findByToken(request.params.token);
      if (!invite) {
        reply.status(404);
        return { error: "Invite not found" };
      }
      const status = inviteStatus(invite);
      // Don't echo the (now-known-invalid) token back; just status + label so
      // the UI can show the user why the link won't work.
      return {
        status,
        label: invite.label,
        expiresAt: invite.expiresAt,
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
      const invite = inviteRepo.findByToken(token);
      if (!invite) {
        reply.status(404);
        return { error: "Invite not found" };
      }
      const status = inviteStatus(invite);
      if (status !== "pending") {
        reply.status(410);
        return { error: `Invite is ${status}` };
      }

      // ExcludeCredentials scoped to the inviting account, same as the
      // authenticated registration flow — prevents duplicate enrollment of an
      // authenticator that's already on the account.
      const existing = db
        .select({ credentialId: webauthnCredentials.credentialId })
        .from(webauthnCredentials)
        .where(eq(webauthnCredentials.accountId, invite.accountId))
        .all();

      const userName = invite.label.slice(0, 64);
      const options = await generateRegistrationOptions({
        rpName: "ShellWatch",
        rpID: rpId,
        userName,
        userDisplayName: invite.label,
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
  app.post<{ Body: { token: string; challengeId: string; credential: unknown } }>(
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
      const { token, challengeId, credential } = request.body ?? ({} as never);
      if (!token || typeof token !== "string") {
        reply.status(400);
        return { error: "Token is required" };
      }
      const invite = inviteRepo.findByToken(token);
      if (!invite) {
        reply.status(404);
        return { error: "Invite not found" };
      }
      const status = inviteStatus(invite);
      if (status !== "pending") {
        reply.status(410);
        return { error: `Invite is ${status}` };
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

      // The credential is created in `pending_confirmation` state — it is not
      // usable for login or SSH signing until the inviting (already-authenticated)
      // device flips it to `active` via /api/webauthn/credentials/:id/confirm.
      const decoded = {
        ...result.decoded,
        baseLabel: invite.label,
      };
      const inserted = db.transaction((tx) => {
        const { id, label } = insertCredentialRow(tx, invite.accountId, decoded);
        tx.update(webauthnCredentials)
          .set({ state: CREDENTIAL_STATE.pendingConfirmation })
          .where(eq(webauthnCredentials.id, id))
          .run();
        return { id, label };
      });

      const consumed = inviteRepo.markConsumed(invite.id, inserted.id);
      if (!consumed) {
        // Lost the race against another concurrent register attempt on the
        // same token. Roll back our credential insert so the invite remains
        // truly single-use.
        db.delete(webauthnCredentials).where(eq(webauthnCredentials.id, inserted.id)).run();
        reply.status(409);
        return { error: "Invite was already used" };
      }

      request.log.info(
        {
          event: "passkey_invite.registered",
          inviteId: invite.id,
          credentialId: inserted.id,
          accountId: invite.accountId,
        },
        "passkey invite registered (pending confirmation)",
      );

      return {
        status: "registered",
        label: inserted.label,
      };
    },
  );
}
