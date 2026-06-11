// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { randomUUID } from "node:crypto";
import { generateRegistrationOptions } from "@simplewebauthn/server";
import type { FastifyInstance } from "fastify";
import { hasPasskeys } from "../db/repositories/credential-queries.js";
import type { AccountRepository } from "../db/repositories/account-repo.js";
import type { ShellWatchDB } from "../db/connection.js";
import { accounts } from "../db/schema.js";
import { CHALLENGE_PURPOSE, storeChallenge } from "./challenge-store.js";
import { insertCredentialRow, verifyAndDecodeRegistration } from "./credential-store.js";
import type { RateLimitConfig } from "./routes.js";

export interface SelfRegisterRoutesParams {
  app: FastifyInstance;
  db: ShellWatchDB;
  accountRepo: AccountRepository;
  rpId: string;
  trustedOrigins: string[];

  selfRegistrationEnabled: boolean;
  rateLimitConfig: RateLimitConfig;
}

export function registerSelfRegisterRoutes(params: SelfRegisterRoutesParams) {
  const { app, db, accountRepo, rpId, trustedOrigins, selfRegistrationEnabled, rateLimitConfig } =
    params;

  // --- Passkey status (anonymous) ---
  // The register page uses this to tell first-run admin bootstrap (no passkeys
  // yet) apart from ordinary self-registration. Replaces the old probe against
  // /api/auth/login/options, which is gone now that web login is a BFF redirect
  // to the Hydra passkey login provider (#217).
  app.get("/api/auth/passkey-status", async () => ({ hasPasskeys: hasPasskeys(db) }));

  // --- Self-Registration: Generate WebAuthn options (anonymous) ---
  // Companion to POST /api/auth/register. Returns no excludeCredentials so
  // we don't leak the global credential-id list to anonymous callers; the
  // tradeoff is that re-registering an authenticator that already exists for
  // another account fails late (at /api/auth/register verify) instead of
  // being prevented by the browser. The authenticated add-passkey flow uses
  // /api/webauthn/register/options, which scopes excludeCredentials to the
  // calling account.
  app.post<{ Body: { name?: string } }>(
    "/api/auth/register/options",
    {
      config: {
        rateLimit: {
          max: rateLimitConfig.selfRegister.max,
          timeWindow: `${rateLimitConfig.selfRegister.windowMinutes} minutes`,
        },
      },
    },
    async (request, reply) => {
      // Same gate as the verify endpoint: don't generate options for a flow
      // that will be refused. Authoritative re-check happens in the verify
      // transaction to close the TOCTOU gap.
      if (!selfRegistrationEnabled && hasPasskeys(db)) {
        reply.status(403);
        return { error: "Self-registration is disabled" };
      }
      const { name } = request.body ?? {};
      const userName = (name || "user").slice(0, 64);
      const options = await generateRegistrationOptions({
        rpName: "ShellWatch",
        rpID: rpId,
        userName,
        userDisplayName: name || "ShellWatch User",
        attestationType: "none",
        authenticatorSelection: {
          residentKey: "preferred",
          userVerification: "required",
        },
        supportedAlgorithmIDs: [-7], // ES256 (P-256) only — OpenSSH sk-* keys don't support Ed25519 webauthn
      });
      const challengeId = storeChallenge(options.challenge, CHALLENGE_PURPOSE.selfRegister);
      return { ...options, challengeId };
    },
  );

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

      try {
        const result = await verifyAndDecodeRegistration({
          challengeId,
          credential,
          rpId,
          trustedOrigins,
          challengePurpose: CHALLENGE_PURPOSE.selfRegister,
        });
        if (!result.ok) {
          reply.status(400);
          return { error: result.error };
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
            // Direct tx.insert (rather than accountRepo.create) because this
            // INSERT must run inside the same transaction as insertCredentialRow
            // below — passing the tx handle through the repo abstraction is more
            // ceremony than payoff for one call site. See #136 follow-up.
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

          const inserted = insertCredentialRow(tx, accountId, result.decoded);
          return { id: accountId, credentialRowId: inserted.id, label: inserted.label };
        });

        if (!account) {
          reply.status(403);
          return { error: "Self-registration is disabled" };
        }

        // No auto-login: the web session is a BFF/Hydra grant (#217), which the
        // client establishes by navigating to /api/auth/bff/login after the
        // passkey is registered. Registration itself sets no session cookie.
        return {
          verified: true,
          accountId: account.id,
          id: account.credentialRowId,
          credentialId: result.decoded.credentialId,
          label: account.label,
        };
      } catch (err) {
        reply.status(400);
        return { error: (err as Error).message };
      }
    },
  );
}
