import { randomUUID } from "node:crypto";
import { verifyRegistrationResponse } from "@simplewebauthn/server";
import type { FastifyInstance } from "fastify";
import { deduplicateLabel, hasPasskeys } from "../db/repositories/credential-queries.js";
import type { AccountRepository } from "../db/repositories/account-repo.js";
import type { ShellWatchDB } from "../db/connection.js";
import { accounts, webauthnCredentials } from "../db/schema.js";
import { consumeChallenge } from "./challenge-store.js";
import { coseToAuthorizedKeys } from "./ssh-key-format.js";
import { lookupAAGUID } from "./aaguid-lookup.js";
import type { RateLimitConfig, SessionConfig } from "./routes.js";

export interface SelfRegisterRoutesParams {
  app: FastifyInstance;
  db: ShellWatchDB;
  accountRepo: AccountRepository;
  rpId: string;
  trustedOrigins: string[];

  sessionConfig?: SessionConfig;
  selfRegistrationEnabled: boolean;
  rateLimitConfig: RateLimitConfig;
}

export function registerSelfRegisterRoutes(params: SelfRegisterRoutesParams) {
  const {
    app,
    db,
    accountRepo,
    rpId,
    trustedOrigins,
    sessionConfig,
    selfRegistrationEnabled,
    rateLimitConfig,
  } = params;

  // --- Self-Registration: Create account + passkey atomically ---
  app.post<{
    Body: { name: string; challengeId: string; credential: unknown };
  }>(
    "/api/auth/register",
    {
      config: {
        rateLimit: {
          max: rateLimitConfig.selfRegister.max,
          timeWindow: `${rateLimitConfig.selfRegister.windowMinutes} minutes`,
        },
      },
    },
    async (request, reply) => {
      // Early rejection when self-registration is disabled and system is already
      // bootstrapped. This avoids burning a challenge for a request that will be
      // refused anyway. The authoritative check is inside the transaction below
      // to close the TOCTOU gap on hasPasskeys().
      if (!selfRegistrationEnabled && hasPasskeys(db)) {
        reply.status(403);
        return { error: "Self-registration is disabled" };
      }

      const { name, challengeId, credential } = request.body;
      if (!name || !challengeId || !credential) {
        reply.status(400);
        return { error: "name, challengeId, and credential are required" };
      }

      const challenge = consumeChallenge(challengeId);
      if (!challenge) {
        reply.status(400);
        return { error: "Challenge expired or not found" };
      }

      try {
        const verification = await verifyRegistrationResponse({
          response: credential as Parameters<typeof verifyRegistrationResponse>[0]["response"],
          expectedChallenge: challenge,
          expectedOrigin: trustedOrigins,
          expectedRPID: rpId,
        });

        if (!verification.verified || !verification.registrationInfo) {
          reply.status(400);
          return { error: "Verification failed" };
        }

        const { credential: cred, aaguid } = verification.registrationInfo;
        const baseLabel = lookupAAGUID(aaguid) || "Passkey";

        const credId = randomUUID();
        const now = new Date().toISOString();
        const pubKeyBuf = Buffer.from(cred.publicKey);

        let authorizedKeysEntry: string | null = null;
        try {
          authorizedKeysEntry = coseToAuthorizedKeys(pubKeyBuf, rpId);
        } catch {
          // Non-fatal
        }

        // Wrap account resolution + credential insert in a transaction so two
        // concurrent first-time registrations can't both see hasPasskeys()=false
        // and silently share the admin account.
        const account = db.transaction((tx) => {
          // Re-check inside the transaction to close the TOCTOU gap: between
          // the early guard above and here, another request may have completed
          // bootstrap, making hasPasskeys() true. Without this, a concurrent
          // request could slip through and create an extra account.
          if (!selfRegistrationEnabled && hasPasskeys(tx)) {
            return null;
          }

          const existingAdminId = accountRepo.getAdminAccountId();
          let accountId: string;

          if (!hasPasskeys(tx) && existingAdminId) {
            // Onboarding: adopt seeded admin — name from request is intentionally
            // ignored since the seeded account already has the canonical name.
            accountId = existingAdminId;
          } else {
            accountId = randomUUID();
            const accountNow = new Date().toISOString();
            tx.insert(accounts)
              .values({
                id: accountId,
                name,
                enabled: true,
                maxSessions: 5,
                lastUsedAt: accountNow,
                createdAt: accountNow,
                updatedAt: accountNow,
              })
              .run();
            // First account becomes admin. setAdmin uses INSERT OR IGNORE —
            // first writer wins via singleton CHECK constraint.
            if (!existingAdminId) {
              accountRepo.setAdmin(accountId);
            }
          }

          const label = deduplicateLabel(tx, accountId, baseLabel);

          tx.insert(webauthnCredentials)
            .values({
              id: credId,
              accountId,
              credentialId: cred.id,
              publicKey: pubKeyBuf,
              counter: cred.counter,
              transports: JSON.stringify(cred.transports ?? []),
              label,
              publicKeyOpenSsh: authorizedKeysEntry,
              createdAt: now,
            })
            .run();

          return { id: accountId, label };
        });

        if (!account) {
          reply.status(403);
          return { error: "Self-registration is disabled" };
        }

        // Auto-login: set session cookie
        if (sessionConfig) {
          const { createSessionCookie } = await import("../server/auth/session-cookie.js");
          const cookieValue = createSessionCookie(
            sessionConfig.secret,
            sessionConfig.ttlSeconds,
            account.id,
          );
          const secure = request.protocol === "https" || !!request.headers["x-forwarded-proto"];
          reply.header(
            "Set-Cookie",
            `sw_session=${cookieValue}; HttpOnly; ${secure ? "Secure; " : ""}SameSite=Strict; Path=/; Max-Age=${sessionConfig.ttlSeconds}`,
          );
        }

        return {
          verified: true,
          accountId: account.id,
          credentialId: credId,
          label: account.label,
        };
      } catch (err) {
        reply.status(400);
        return { error: (err as Error).message };
      }
    },
  );
}
