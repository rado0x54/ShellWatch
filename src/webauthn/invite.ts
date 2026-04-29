import { generateRegistrationOptions } from "@simplewebauthn/server";
import { and, eq } from "drizzle-orm";
import type { FastifyInstance } from "fastify";
import type { ShellWatchDB } from "../db/connection.js";
import { CREDENTIAL_STATE } from "../db/repositories/index.js";
import { accounts, webauthnCredentials } from "../db/schema.js";
import { storeChallenge } from "./challenge-store.js";
import { insertCredentialRow, verifyAndDecodeRegistration } from "./credential-store.js";
import { sha256Fingerprint } from "./fingerprint.js";
import {
  consumeInviteSlot,
  createInviteSlot,
  findInviteByToken,
  findInviteForAccount,
  markInviteRegistered,
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

      // If a slot for this account still references the just-confirmed cred,
      // drop it. Stops a leaked token from re-renaming after activation.
      const slot = findInviteForAccount(request.accountId);
      if (slot && slot.credentialId === id) {
        consumeInviteSlot(request.accountId);
      }

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
      // The account name is fine to surface to the invite holder — the token
      // already grants register-a-passkey-on-this-account, and showing
      // "ShellWatch · for <name>" lets device B's user verify they're
      // enrolling on the right account.
      const acct = db
        .select({ name: accounts.name })
        .from(accounts)
        .where(eq(accounts.id, slot.accountId))
        .get();
      return {
        label: slot.label,
        accountName: acct?.name ?? null,
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
  // The slot is NOT consumed here — it stays alive so device B can use the
  // same token to confirm/rename via PATCH /api/passkey-invite/register/label.
  // The slot's natural 5-minute expiry (or device A's confirm action) is what
  // ultimately retires it. The credential is inserted with the AAGUID-derived
  // label; device B sees that suggestion and can edit it before confirming.
  app.post<{
    Body: { token: string; challengeId: string; credential: unknown };
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
      const { token, challengeId, credential } = request.body ?? ({} as never);
      if (!token || typeof token !== "string") {
        reply.status(400);
        return { error: "Token is required" };
      }
      const slot = findInviteByToken(token);
      if (!slot) {
        reply.status(404);
        return { error: "Invite not found or expired" };
      }
      if (slot.credentialId) {
        // Slot already produced a credential. Single-use: refuse a second
        // ceremony rather than allow the rename-window to be hijacked.
        reply.status(409);
        return { error: "Invite was already used" };
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

      const inserted = db.transaction((tx) => {
        const { id, label: insertedLabel } = insertCredentialRow(
          tx,
          slot.accountId,
          result.decoded,
        );
        tx.update(webauthnCredentials)
          .set({ state: CREDENTIAL_STATE.pendingConfirmation })
          .where(eq(webauthnCredentials.id, id))
          .run();
        return { id, label: insertedLabel };
      });

      // Mark the slot as registered. Race lost (slot expired/superseded
      // between findInviteByToken and now): undo the insert so we don't leave
      // an orphaned pending credential nobody can finish confirming.
      const ok = markInviteRegistered(slot.accountId, inserted.id);
      if (!ok) {
        db.delete(webauthnCredentials).where(eq(webauthnCredentials.id, inserted.id)).run();
        reply.status(409);
        return { error: "Invite expired during registration" };
      }

      request.log.info(
        {
          event: "passkey_invite.registered",
          credentialId: inserted.id,
          accountId: slot.accountId,
        },
        "passkey invite registered (pending confirmation, awaiting rename)",
      );

      return {
        status: "registered",
        credentialId: inserted.id,
        label: inserted.label,
        fingerprint: fingerprintFromOpenSsh(result.decoded.authorizedKeysEntry),
      };
    },
  );

  // --- Public: confirm/rename the just-registered credential ---
  // Device B has no session, so the invite token is the bearer of authority
  // for this one PATCH. Once accepted, the slot is consumed — device B can't
  // come back and rename again, and a leaked link can't either.
  app.patch<{ Body: { token: string; label: string } }>(
    "/api/passkey-invite/register/label",
    {
      config: {
        rateLimit: {
          max: rateLimitConfig.passkeyRegister.max,
          timeWindow: `${rateLimitConfig.passkeyRegister.windowMinutes} minutes`,
        },
      },
    },
    async (request, reply) => {
      const { token, label } = request.body ?? ({} as never);
      if (!token || typeof token !== "string") {
        reply.status(400);
        return { error: "Token is required" };
      }
      const trimmed = typeof label === "string" ? label.trim() : "";
      if (!trimmed) {
        reply.status(400);
        return { error: "Label is required" };
      }
      if (trimmed.length > 64) {
        reply.status(400);
        return { error: "Label must be 64 characters or less" };
      }
      const slot = findInviteByToken(token);
      if (!slot || !slot.credentialId) {
        reply.status(404);
        return { error: "Invite not found or registration not completed" };
      }

      // Refuse on label collision within the account, same as the
      // session-authenticated rename endpoint. An accidental match would
      // surface as a confusing duplicate name in the credentials list.
      const conflict = db
        .select({ id: webauthnCredentials.id })
        .from(webauthnCredentials)
        .where(
          and(
            eq(webauthnCredentials.accountId, slot.accountId),
            eq(webauthnCredentials.label, trimmed),
          ),
        )
        .get();
      if (conflict && conflict.id !== slot.credentialId) {
        reply.status(409);
        return { error: "A passkey with this label already exists on the account" };
      }

      db.update(webauthnCredentials)
        .set({ label: trimmed })
        .where(
          and(
            eq(webauthnCredentials.id, slot.credentialId),
            eq(webauthnCredentials.state, CREDENTIAL_STATE.pendingConfirmation),
          ),
        )
        .run();

      // Drop the slot — single-use rename window is over.
      consumeInviteSlot(slot.accountId);

      request.log.info(
        {
          event: "passkey_invite.label_confirmed",
          credentialId: slot.credentialId,
          accountId: slot.accountId,
        },
        "passkey invite label confirmed",
      );

      return { status: "confirmed", label: trimmed };
    },
  );
}
