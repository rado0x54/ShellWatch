import {
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server";
import { and, eq } from "drizzle-orm";
import type { FastifyInstance } from "fastify";
import type { ShellWatchDB } from "../db/connection.js";
import { CREDENTIAL_STATE } from "../db/repositories/credential-queries.js";
import { webauthnCredentials } from "../db/schema.js";
import { consumeChallenge, storeChallenge } from "./challenge-store.js";
import type { RateLimitConfig } from "./routes.js";
import { mintStepUpToken, STEPUP_ACTION, type StepUpAction } from "./stepup-store.js";

export interface StepUpRoutesParams {
  app: FastifyInstance;
  db: ShellWatchDB;
  rpId: string;
  trustedOrigins: string[];
  rateLimitConfig: RateLimitConfig;
}

const STEPUP_ACTIONS = new Set<StepUpAction>([
  STEPUP_ACTION.registerPasskey,
  STEPUP_ACTION.revokePasskey,
]);

function isStepUpAction(value: unknown): value is StepUpAction {
  return typeof value === "string" && STEPUP_ACTIONS.has(value as StepUpAction);
}

export function registerStepUpRoutes(params: StepUpRoutesParams) {
  const { app, db, rpId, trustedOrigins, rateLimitConfig } = params;

  // --- Step-up: generate an assertion challenge scoped to the caller ---
  // Reuses the loginVerify rate limit bucket — the cost shape is the same
  // (one assertion per step-up, gates a sensitive write).
  app.post<{ Body: { action: unknown } }>(
    "/api/webauthn/stepup/options",
    {
      config: {
        rateLimit: {
          max: rateLimitConfig.loginVerify.max,
          timeWindow: `${rateLimitConfig.loginVerify.windowMinutes} minutes`,
        },
      },
    },
    async (request, reply) => {
      const action = request.body?.action;
      if (!isStepUpAction(action)) {
        reply.status(400);
        return { error: "Invalid or missing action" };
      }

      const creds = db
        .select({ credentialId: webauthnCredentials.credentialId })
        .from(webauthnCredentials)
        .where(
          and(
            eq(webauthnCredentials.accountId, request.accountId),
            eq(webauthnCredentials.revoked, false),
            eq(webauthnCredentials.state, CREDENTIAL_STATE.active),
          ),
        )
        .all();

      if (creds.length === 0) {
        // No active credential to assert with — a step-up requirement on a
        // fresh account with no passkey yet would be a chicken-and-egg lock.
        // The only way to reach here is the bootstrap window before the first
        // passkey exists; the gated endpoints handle that by allowing the
        // first add separately (see step-up-gate). For defence-in-depth we
        // still refuse to mint a meaningless options payload.
        reply.status(400);
        return { error: "no_active_credentials" };
      }

      const options = await generateAuthenticationOptions({
        rpID: rpId,
        userVerification: "required",
        allowCredentials: creds.map((c) => ({ id: c.credentialId })),
      });

      const challengeId = storeChallenge(options.challenge);
      return { ...options, challengeId, action };
    },
  );

  // --- Step-up: verify the assertion and mint a single-use token ---
  app.post<{ Body: { challengeId: string; credential: unknown; action: unknown } }>(
    "/api/webauthn/stepup/verify",
    {
      config: {
        rateLimit: {
          max: rateLimitConfig.loginVerify.max,
          timeWindow: `${rateLimitConfig.loginVerify.windowMinutes} minutes`,
        },
      },
    },
    async (request, reply) => {
      const { challengeId, credential, action } = request.body ?? ({} as never);

      if (!isStepUpAction(action)) {
        reply.status(400);
        return { error: "Invalid or missing action" };
      }

      const challenge = consumeChallenge(challengeId);
      if (!challenge) {
        reply.status(400);
        return { error: "Challenge expired or not found" };
      }

      const assertionResponse = credential as {
        id: string;
        rawId: string;
        response: unknown;
        type: string;
      };

      // Look up the credential and require it to belong to the caller AND be
      // active + non-revoked. A different account's credential id (or a
      // revoked / pending one) MUST NOT mint a step-up token for this caller.
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

      if (
        !storedCred ||
        storedCred.accountId !== request.accountId ||
        storedCred.revoked ||
        storedCred.state !== CREDENTIAL_STATE.active
      ) {
        reply.status(400);
        return { error: "Unknown credential" };
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

        // Bump the counter the same way login does — a stale counter would
        // give an attacker who clones the authenticator state a free re-use
        // window (see WebAuthn §6.1.1 signature counter).
        db.update(webauthnCredentials)
          .set({
            counter: verification.authenticationInfo.newCounter,
            lastUsedAt: new Date().toISOString(),
          })
          .where(eq(webauthnCredentials.id, storedCred.id))
          .run();

        const minted = mintStepUpToken({
          accountId: request.accountId,
          action,
        });

        return {
          stepUpToken: minted.token,
          expiresAt: new Date(minted.expiresAt).toISOString(),
          action,
        };
      } catch (err) {
        reply.status(400);
        return { error: (err as Error).message };
      }
    },
  );
}
