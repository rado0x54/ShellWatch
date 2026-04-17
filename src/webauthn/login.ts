import { generateAuthenticationOptions } from "@simplewebauthn/server";
import { eq } from "drizzle-orm";
import type { FastifyInstance } from "fastify";
import type { AccountRepository } from "../db/repositories/account-repo.js";
import type { ShellWatchDB } from "../db/connection.js";
import { webauthnCredentials } from "../db/schema.js";
import { storeChallenge } from "./challenge-store.js";
import { type AuthenticationResponseLike, verifyPasskeyAssertion } from "./passkey-verify.js";
import type { OnLoginSuccess, RateLimitConfig } from "./routes.js";

export interface LoginRoutesParams {
  app: FastifyInstance;
  db: ShellWatchDB;
  accountRepo: AccountRepository;
  rpId: string;
  trustedOrigins: string[];

  onLoginSuccess?: OnLoginSuccess;
  rateLimitConfig: RateLimitConfig;
}

export function registerLoginRoutes(params: LoginRoutesParams) {
  const { app, db, accountRepo, rpId, trustedOrigins, onLoginSuccess, rateLimitConfig } = params;

  // --- Login (Assertion): Generate Options ---
  app.post(
    "/api/webauthn/login/options",
    {
      config: {
        rateLimit: {
          max: rateLimitConfig.loginOptions.max,
          timeWindow: `${rateLimitConfig.loginOptions.windowMinutes} minutes`,
        },
      },
    },
    async () => {
      const creds = db
        .select({ credentialId: webauthnCredentials.credentialId })
        .from(webauthnCredentials)
        .where(eq(webauthnCredentials.revoked, false))
        .all();

      if (creds.length === 0) {
        return { error: "no_passkeys" };
      }

      const options = await generateAuthenticationOptions({
        rpID: rpId,
        userVerification: "required",
        allowCredentials: creds.map((c) => ({ id: c.credentialId })),
      });

      const challengeId = storeChallenge(options.challenge);
      return { ...options, challengeId };
    },
  );

  // --- Login (Assertion): Verify ---
  app.post<{ Body: { challengeId: string; credential: unknown } }>(
    "/api/webauthn/login/verify",
    {
      config: {
        rateLimit: {
          max: rateLimitConfig.loginVerify.max,
          timeWindow: `${rateLimitConfig.loginVerify.windowMinutes} minutes`,
        },
      },
    },
    async (request, reply) => {
      if (!onLoginSuccess) {
        reply.status(500);
        return { error: "Login handler not configured" };
      }

      const result = await verifyPasskeyAssertion({
        db,
        accountRepo,
        rpId,
        trustedOrigins,
        challengeId: request.body.challengeId,
        credential: request.body.credential as AuthenticationResponseLike,
      });

      if (!result.ok) {
        reply.status(result.status);
        return { error: result.error };
      }

      // Session minting + cookie wiring happens outside passkey code:
      // the OAuth module's UiSessionService owns the token shape and
      // cookie attributes. Keeps this file OAuth-agnostic.
      await onLoginSuccess(request, reply, { accountId: result.accountId });

      return { verified: true };
    },
  );
}
