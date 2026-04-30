import { generateRegistrationOptions } from "@simplewebauthn/server";
import { and, eq } from "drizzle-orm";
import type { FastifyInstance } from "fastify";
import type { ShellWatchDB } from "../db/connection.js";
import { webauthnCredentials } from "../db/schema.js";
import { storeChallenge } from "./challenge-store.js";
import { insertCredentialRow, verifyAndDecodeRegistration } from "./credential-store.js";
import { getSshdConfigLine } from "./ssh-key-format.js";
import type { RateLimitConfig } from "./routes.js";
import { requireStepUp } from "./stepup-gate.js";
import { STEPUP_ACTION } from "./stepup-store.js";

export interface RegistrationRoutesParams {
  app: FastifyInstance;
  db: ShellWatchDB;
  rpId: string;
  trustedOrigins: string[];

  rateLimitConfig: RateLimitConfig;
}

export function registerRegistrationRoutes(params: RegistrationRoutesParams) {
  const { app, db, rpId, trustedOrigins, rateLimitConfig } = params;

  // --- Registration: Generate Options ---
  app.post<{ Body: { label: string; name?: string } }>(
    "/api/webauthn/register/options",
    {
      config: {
        rateLimit: {
          max: rateLimitConfig.passkeyRegister.max,
          timeWindow: `${rateLimitConfig.passkeyRegister.windowMinutes} minutes`,
        },
      },
    },
    async (request, reply) => {
      // Step-up gate: peek the token without consuming. The same token has to
      // survive to the subsequent /api/webauthn/register call (the verify
      // step), which is where it actually gets burned. Both endpoints check
      // so an attacker with a session cookie can't even enumerate the
      // account's existing credentials via excludeCredentials below without
      // first proving fresh possession.
      if (
        !requireStepUp({
          request,
          reply,
          action: STEPUP_ACTION.registerPasskey,
          mode: "peek",
        })
      ) {
        return reply;
      }

      const { label, name } = request.body;
      // Auth-gated route: scope excludeCredentials to the calling account so
      // we don't leak the global credential-id list to authenticated callers.
      // The anonymous self-register flow uses /api/auth/register/options
      // (returns no excludeCredentials).
      //
      // Revoked credentials are intentionally NOT excluded — the user
      // explicitly destroyed the prior credential, and they should be able
      // to re-enroll the same authenticator. Otherwise the browser/authenticator
      // throws "The authenticator was previously registered" and the only
      // recovery is to delete the row out-of-band.
      const existing = db
        .select({ credentialId: webauthnCredentials.credentialId })
        .from(webauthnCredentials)
        .where(
          and(
            eq(webauthnCredentials.accountId, request.accountId),
            eq(webauthnCredentials.revoked, false),
          ),
        )
        .all();

      // userName: max 64 bytes per WebAuthn recommendation
      const userName = (name || label || "user").slice(0, 64);

      const options = await generateRegistrationOptions({
        rpName: "ShellWatch",
        rpID: rpId,
        userName,
        userDisplayName: name || label || "ShellWatch User",
        attestationType: "none",
        authenticatorSelection: {
          residentKey: "preferred",
          userVerification: "required",
        },
        supportedAlgorithmIDs: [-7], // ES256 (P-256) only — OpenSSH sk-* keys don't support Ed25519 webauthn
        excludeCredentials: existing.map((c) => ({
          id: c.credentialId,
        })),
      });

      const challengeId = storeChallenge(options.challenge);
      return { ...options, challengeId };
    },
  );

  // --- Registration: Verify Response ---
  app.post<{ Body: { challengeId: string; credential: unknown } }>(
    "/api/webauthn/register",
    {
      config: {
        rateLimit: {
          max: rateLimitConfig.passkeyRegister.max,
          timeWindow: `${rateLimitConfig.passkeyRegister.windowMinutes} minutes`,
        },
      },
    },
    async (request, reply) => {
      // Step-up gate (consume): this is the terminal endpoint of the
      // registration ceremony, so we burn the token here. A successful
      // ceremony => one consumed step-up token; cancellation/failure on the
      // client side just leaves the token to expire naturally.
      if (
        !requireStepUp({
          request,
          reply,
          action: STEPUP_ACTION.registerPasskey,
          mode: "consume",
        })
      ) {
        return reply;
      }

      const { challengeId, credential } = request.body;

      try {
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

        // Auth-gated route: request.accountId is set by the auth gate.
        // First-passkey/bootstrap and self-registration go through
        // /api/auth/register (self-register.ts), which creates the account
        // and credential atomically — there is no unauth path here.
        const { id, label } = insertCredentialRow(db, request.accountId, result.decoded);

        return {
          verified: true,
          credentialId: result.decoded.credentialId,
          id,
          label,
          authorizedKeysEntry: result.decoded.authorizedKeysEntry,
          sshdConfig: result.decoded.authorizedKeysEntry ? getSshdConfigLine() : null,
        };
      } catch (err) {
        reply.status(400);
        return { error: (err as Error).message };
      }
    },
  );
}
