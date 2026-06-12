// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import {
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server";
import { and, eq } from "drizzle-orm";
import type { FastifyInstance } from "fastify";
import type { ShellWatchDB } from "../db/connection.js";
import { CREDENTIAL_STATE } from "../db/repositories/credential-queries.js";
import { webauthnCredentials } from "../db/schema.js";
import {
  CHALLENGE_PURPOSE,
  type ChallengePurpose,
  consumeChallenge,
  storeChallenge,
} from "./challenge-store.js";
import type { RateLimitConfig } from "./routes.js";
import { mintStepUpToken, STEPUP_ACTION, type StepUpAction } from "./stepup-store.js";

export interface StepUpRoutesParams {
  app: FastifyInstance;
  db: ShellWatchDB;
  rpId: string;
  trustedOrigins: string[];
  rateLimitConfig: RateLimitConfig;
}

/**
 * Each step-up action gets its own challenge purpose. The challenge minted
 * by /stepup/options is stored under this purpose, and /stepup/verify
 * consumes with the same purpose. An attacker who swaps the `action` field
 * in the verify request body can't surface the challenge — the consume call
 * fails closed.
 */
const ACTION_TO_PURPOSE: Record<StepUpAction, ChallengePurpose> = {
  [STEPUP_ACTION.registerPasskey]: CHALLENGE_PURPOSE.stepupRegisterPasskey,
  [STEPUP_ACTION.revokePasskey]: CHALLENGE_PURPOSE.stepupRevokePasskey,
  [STEPUP_ACTION.confirmPasskey]: CHALLENGE_PURPOSE.stepupConfirmPasskey,
  [STEPUP_ACTION.revokeSession]: CHALLENGE_PURPOSE.stepupRevokeSession,
  [STEPUP_ACTION.revokeAllSessions]: CHALLENGE_PURPOSE.stepupRevokeAllSessions,
};

function isStepUpAction(value: unknown): value is StepUpAction {
  return typeof value === "string" && value in ACTION_TO_PURPOSE;
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
        // Defensive: an authenticated session implies the account has at
        // least one credential row (created at self-register time) and the
        // last-active-passkey guard in /revoke prevents getting back to
        // zero. So this branch is unreachable under normal operation —
        // we 400 rather than mint a meaningless options payload if the
        // invariant is ever violated.
        reply.status(400);
        return { error: "no_active_credentials" };
      }

      const options = await generateAuthenticationOptions({
        rpID: rpId,
        userVerification: "required",
        allowCredentials: creds.map((c) => ({ id: c.credentialId })),
      });

      const challengeId = storeChallenge(options.challenge, ACTION_TO_PURPOSE[action]);
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

      const challenge = consumeChallenge(challengeId, ACTION_TO_PURPOSE[action]);
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

        request.log.info(
          {
            event: "passkey_stepup.minted",
            accountId: request.accountId,
            action,
            credentialRowId: storedCred.id,
          },
          "step-up token minted",
        );

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
