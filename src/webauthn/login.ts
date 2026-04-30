import {
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server";
import { and, eq } from "drizzle-orm";
import type { FastifyInstance } from "fastify";
import type { AccountRepository } from "../db/repositories/account-repo.js";
import type { ShellWatchDB } from "../db/connection.js";
import { CREDENTIAL_STATE } from "../db/repositories/credential-queries.js";
import { webauthnCredentials } from "../db/schema.js";
import { CHALLENGE_PURPOSE, consumeChallenge, storeChallenge } from "./challenge-store.js";
import type { RateLimitConfig, SessionConfig } from "./routes.js";

export interface LoginRoutesParams {
  app: FastifyInstance;
  db: ShellWatchDB;
  accountRepo: AccountRepository;
  rpId: string;
  trustedOrigins: string[];

  sessionConfig?: SessionConfig;
  rateLimitConfig: RateLimitConfig;
}

export function registerLoginRoutes(params: LoginRoutesParams) {
  const { app, db, accountRepo, rpId, trustedOrigins, sessionConfig, rateLimitConfig } = params;

  // --- Login (Assertion): Generate Options ---
  app.post(
    "/api/auth/login/options",
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
        .where(
          and(
            eq(webauthnCredentials.revoked, false),
            eq(webauthnCredentials.state, CREDENTIAL_STATE.active),
          ),
        )
        .all();

      if (creds.length === 0) {
        return { error: "no_passkeys" };
      }

      const options = await generateAuthenticationOptions({
        rpID: rpId,
        userVerification: "required",
        allowCredentials: creds.map((c) => ({ id: c.credentialId })),
      });

      const challengeId = storeChallenge(options.challenge, CHALLENGE_PURPOSE.login);
      return { ...options, challengeId };
    },
  );

  // --- Login (Assertion): Verify ---
  app.post<{ Body: { challengeId: string; credential: unknown } }>(
    "/api/auth/login",
    {
      config: {
        rateLimit: {
          max: rateLimitConfig.loginVerify.max,
          timeWindow: `${rateLimitConfig.loginVerify.windowMinutes} minutes`,
        },
      },
    },
    async (request, reply) => {
      if (!sessionConfig) {
        reply.status(500);
        return { error: "Session config not available" };
      }

      const { challengeId, credential } = request.body;

      const challenge = consumeChallenge(challengeId, CHALLENGE_PURPOSE.login);
      if (!challenge) {
        reply.status(400);
        return { error: "Challenge expired or not found" };
      }

      // Find the credential in DB
      const assertionResponse = credential as {
        id: string;
        rawId: string;
        response: unknown;
        type: string;
        authenticatorAttachment?: string;
        clientExtensionResults?: unknown;
      };
      const storedCred = db
        .select({
          id: webauthnCredentials.id,
          accountId: webauthnCredentials.accountId,
          credentialId: webauthnCredentials.credentialId,
          publicKey: webauthnCredentials.publicKey,
          counter: webauthnCredentials.counter,
          transports: webauthnCredentials.transports,
          revoked: webauthnCredentials.revoked,
          state: webauthnCredentials.state,
        })
        .from(webauthnCredentials)
        .where(eq(webauthnCredentials.credentialId, assertionResponse.id))
        .get();

      if (!storedCred) {
        reply.status(400);
        return { error: "Unknown credential" };
      }

      if (storedCred.revoked) {
        reply.status(403);
        return { error: "This passkey has been revoked" };
      }

      if (storedCred.state !== CREDENTIAL_STATE.active) {
        // Pending-confirmation credentials can't log in until the inviting
        // device confirms them. We still get here in theory because login
        // options omit them, but a hand-crafted client could pass a known
        // credential id.
        reply.status(403);
        return { error: "This passkey is awaiting confirmation on the original device" };
      }

      try {
        const verification = await verifyAuthenticationResponse({
          response: credential as Parameters<typeof verifyAuthenticationResponse>[0]["response"],
          expectedChallenge: challenge,
          expectedOrigin: trustedOrigins,
          expectedRPID: rpId,
          requireUserVerification: true,
          credential: {
            id: storedCred.credentialId,
            publicKey: new Uint8Array(storedCred.publicKey),
            counter: storedCred.counter,
            transports: storedCred.transports ? JSON.parse(storedCred.transports) : undefined,
          },
        });

        if (!verification.verified) {
          reply.status(400);
          return { error: "Verification failed" };
        }

        // Update counter and last used
        db.update(webauthnCredentials)
          .set({
            counter: verification.authenticationInfo.newCounter,
            lastUsedAt: new Date().toISOString(),
          })
          .where(eq(webauthnCredentials.id, storedCred.id))
          .run();

        // Update account lastUsedAt
        accountRepo.touchLastUsed(storedCred.accountId);

        // Set session cookie with account ID
        const { createSessionCookie } = await import("../server/auth/session-cookie.js");
        const cookieValue = createSessionCookie(
          sessionConfig.secret,
          sessionConfig.ttlSeconds,
          storedCred.accountId,
        );
        const secure = request.protocol === "https" || !!request.headers["x-forwarded-proto"];
        reply.header(
          "Set-Cookie",
          `sw_session=${cookieValue}; HttpOnly; ${secure ? "Secure; " : ""}SameSite=Strict; Path=/; Max-Age=${sessionConfig.ttlSeconds}`,
        );

        return { verified: true };
      } catch (err) {
        reply.status(400);
        return { error: (err as Error).message };
      }
    },
  );
}
