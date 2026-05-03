// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { generateRegistrationOptions } from "@simplewebauthn/server";
import { and, eq } from "drizzle-orm";
import type { FastifyInstance } from "fastify";
import type { ShellWatchDB } from "../db/connection.js";
import { CREDENTIAL_STATE } from "../db/repositories/index.js";
import { accounts, webauthnCredentials } from "../db/schema.js";
import { CHALLENGE_PURPOSE, storeChallenge } from "./challenge-store.js";
import { insertCredentialRow, verifyAndDecodeRegistration } from "./credential-store.js";
import { fingerprintFromAuthorizedKeys } from "./fingerprint.js";
import {
  consumeInviteSlotIfTokenMatches,
  createInviteSlot,
  findInviteByToken,
  findInviteForAccount,
  type InviteSlot,
} from "./invite-store.js";
import type { RateLimitConfig } from "./routes.js";
import { requireStepUp } from "./stepup-gate.js";
import { STEPUP_ACTION } from "./stepup-store.js";

export interface PasskeyInviteRoutesParams {
  app: FastifyInstance;
  db: ShellWatchDB;
  rpId: string;
  trustedOrigins: string[];
  rateLimitConfig: RateLimitConfig;
}

/** Shape returned to UI / invite-link consumer. */
function publicInviteShape(slot: InviteSlot) {
  return {
    expiresAt: new Date(slot.expiresAt).toISOString(),
    createdAt: new Date(slot.createdAt).toISOString(),
    token: slot.token,
  };
}

export function registerPasskeyInviteRoutes(params: PasskeyInviteRoutesParams) {
  const { app, db, rpId, trustedOrigins, rateLimitConfig } = params;

  // --- Authenticated: create or supersede the invite slot for the account ---
  app.post(
    "/api/webauthn/invite",
    {
      config: {
        rateLimit: {
          max: rateLimitConfig.passkeyRegister.max,
          timeWindow: `${rateLimitConfig.passkeyRegister.windowMinutes} minutes`,
        },
      },
    },
    async (request) => {
      // No step-up here. Creating an invite by itself doesn't change a login
      // factor — the credential it produces lands as `pending_confirmation`
      // and is unusable for login until the in-account confirm step (which
      // IS step-up gated). Asking the user to assert twice (once to mint
      // the invite, once to confirm the resulting credential) is overkill;
      // the confirm gate is the load-bearing one in this chain.
      const slot = createInviteSlot({ accountId: request.accountId });
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
  // Step-up gated via preHandler. Confirm flips a pending credential to
  // active, which is the moment it becomes a usable login factor — the most
  // load-bearing gate in the invite flow. Without it, a stolen-cookie
  // attacker could create an invite, register a pending credential from
  // their own device, and confirm it back here.
  app.post<{ Params: { id: string } }>(
    "/api/webauthn/credentials/:id/confirm",
    { preHandler: requireStepUp(STEPUP_ACTION.confirmPasskey) },
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
      // authenticator that's already on the account. Revoked rows are NOT
      // excluded so the user can re-enroll an authenticator they previously
      // revoked.
      const existing = db
        .select({ credentialId: webauthnCredentials.credentialId })
        .from(webauthnCredentials)
        .where(
          and(
            eq(webauthnCredentials.accountId, slot.accountId),
            eq(webauthnCredentials.revoked, false),
          ),
        )
        .all();

      // Use the account name for both userName and userDisplayName so the
      // entry the authenticator stores matches what the in-account flow
      // produces — both are written into the user's authenticator (e.g.
      // iCloud Keychain) and become the human-readable identifier there.
      const acct = db
        .select({ name: accounts.name })
        .from(accounts)
        .where(eq(accounts.id, slot.accountId))
        .get();
      const accountName = acct?.name ?? "ShellWatch user";
      const userName = accountName.slice(0, 64);
      const options = await generateRegistrationOptions({
        rpName: "ShellWatch",
        rpID: rpId,
        userName,
        userDisplayName: accountName,
        attestationType: "none",
        authenticatorSelection: {
          residentKey: "preferred",
          userVerification: "required",
        },
        supportedAlgorithmIDs: [-7],
        excludeCredentials: existing.map((c) => ({ id: c.credentialId })),
      });

      const challengeId = storeChallenge(options.challenge, CHALLENGE_PURPOSE.registerInvite);
      return { ...options, challengeId };
    },
  );

  // --- Public: complete invite registration ---
  // Single-use: consume the slot atomically with the credential insert. The
  // credential lands in `pending_confirmation` and stays there until device A
  // confirms. Device B has no session and no further endpoints to call —
  // renaming is intentionally device A's job, so an intercepted token can't
  // weaponise device A's confirm screen by setting a misleading label.
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
        challengePurpose: CHALLENGE_PURPOSE.registerInvite,
      });
      if (!result.ok) {
        reply.status(400);
        return { error: result.error };
      }

      // Atomic supersede check: the in-flight `verifyAndDecodeRegistration`
      // above is async, so a concurrent /api/webauthn/invite supersede can
      // land between the findInviteByToken at the top of this handler and
      // here. consumeInviteSlotIfTokenMatches refuses to delete a freshly
      // superseded slot on the wrong token.
      const consumed = consumeInviteSlotIfTokenMatches(slot.accountId, token);
      if (!consumed) {
        reply.status(409);
        return { error: "Invite was already used" };
      }

      const inserted = insertCredentialRow(db, slot.accountId, result.decoded, {
        state: CREDENTIAL_STATE.pendingConfirmation,
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
        fingerprint: fingerprintFromAuthorizedKeys(result.decoded.authorizedKeysEntry),
      };
    },
  );
}
