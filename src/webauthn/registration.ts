import { randomUUID } from "node:crypto";
import { generateRegistrationOptions, verifyRegistrationResponse } from "@simplewebauthn/server";
import type { FastifyInstance } from "fastify";
import { deduplicateLabel, hasPasskeys } from "../db/repositories/credential-queries.js";
import type { AccountRepository } from "../db/repositories/account-repo.js";
import type { ShellWatchDB } from "../db/connection.js";
import { webauthnCredentials } from "../db/schema.js";
import { storeChallenge, consumeChallenge } from "./challenge-store.js";
import { coseToAuthorizedKeys, getSshdConfigLine } from "./ssh-key-format.js";
import { lookupAAGUID } from "./aaguid-lookup.js";
import type { RateLimitConfig } from "./routes.js";

export interface RegistrationRoutesParams {
  app: FastifyInstance;
  db: ShellWatchDB;
  accountRepo: AccountRepository;
  rpId: string;
  trustedOrigins: string[];

  rateLimitConfig: RateLimitConfig;
}

export function registerRegistrationRoutes(params: RegistrationRoutesParams) {
  const { app, db, accountRepo, rpId, trustedOrigins, rateLimitConfig } = params;

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
    async (request) => {
      const { label, name } = request.body;
      // Get existing credentials to exclude (prevent re-registration)
      const existing = db
        .select({ credentialId: webauthnCredentials.credentialId })
        .from(webauthnCredentials)
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
        supportedAlgorithmIDs: [-7, -8], // ES256 (P-256) and EdDSA (Ed25519)
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
    "/api/webauthn/register/verify",
    {
      config: {
        rateLimit: {
          max: rateLimitConfig.passkeyRegister.max,
          timeWindow: `${rateLimitConfig.passkeyRegister.windowMinutes} minutes`,
        },
      },
    },
    async (request, reply) => {
      const { challengeId, credential } = request.body;

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
          requireUserVerification: true,
        });

        if (!verification.verified || !verification.registrationInfo) {
          reply.status(400);
          return { error: "Verification failed" };
        }

        const { credential: cred, aaguid } = verification.registrationInfo;
        const baseLabel = lookupAAGUID(aaguid) || "Passkey";

        const id = randomUUID();
        const now = new Date().toISOString();
        const pubKeyBuf = Buffer.from(cred.publicKey);

        // Resolve account: use authenticated session, or bootstrap admin
        let accountId: string | undefined;
        if (request.accountId) {
          accountId = request.accountId;
        } else if (!hasPasskeys(db)) {
          // No passkeys yet — this is onboarding. Either create admin or use existing.
          const existingAdminId = accountRepo.getAdminAccountId();
          if (existingAdminId) {
            accountId = existingAdminId;
          } else {
            const admin = await accountRepo.create({
              id: randomUUID(),
              name: "admin",
            });
            accountRepo.setAdmin(admin.id);
            accountId = admin.id;
          }
        }

        if (!accountId) {
          reply.status(400);
          return { error: "No account associated with this registration" };
        }

        const label = deduplicateLabel(db, accountId, baseLabel);

        // Convert to OpenSSH authorized_keys format
        let authorizedKeysEntry: string | null = null;
        try {
          authorizedKeysEntry = coseToAuthorizedKeys(pubKeyBuf, rpId);
        } catch (convErr) {
          app.log.error(
            `Failed to convert COSE key to OpenSSH format: ${(convErr as Error).message}`,
          );
        }

        db.insert(webauthnCredentials)
          .values({
            id,
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

        return {
          verified: true,
          credentialId: cred.id,
          id,
          label,
          authorizedKeysEntry,
          sshdConfig: authorizedKeysEntry ? getSshdConfigLine() : null,
        };
      } catch (err) {
        reply.status(400);
        return { error: (err as Error).message };
      }
    },
  );
}
