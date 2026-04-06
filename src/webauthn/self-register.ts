import { randomUUID } from "node:crypto";
import { verifyRegistrationResponse } from "@simplewebauthn/server";
import type { FastifyInstance } from "fastify";
import { deduplicateLabel } from "../db/repositories/credential-queries.js";
import type { AccountRepository } from "../db/repositories/account-repo.js";
import type { ShellWatchDB } from "../db/connection.js";
import { webauthnCredentials } from "../db/schema.js";
import { consumeChallenge } from "./challenge-store.js";
import { coseToAuthorizedKeys } from "./ssh-key-format.js";
import { lookupAAGUID } from "./aaguid-lookup.js";
import type { SessionConfig } from "./routes.js";

export interface SelfRegisterRoutesParams {
  app: FastifyInstance;
  db: ShellWatchDB;
  accountRepo: AccountRepository;
  rpId: string;
  trustedOrigins: string[];
  basePath: string;
  sessionConfig?: SessionConfig;
}

export function registerSelfRegisterRoutes(params: SelfRegisterRoutesParams) {
  const { app, db, accountRepo, rpId, trustedOrigins, basePath, sessionConfig } = params;

  // --- Self-Registration: Create account + passkey atomically ---
  app.post<{
    Body: { name: string; challengeId: string; credential: unknown };
  }>(`${basePath}/api/auth/register`, async (request, reply) => {
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

      // Create account — first account becomes admin
      const account = await accountRepo.create({
        id: randomUUID(),
        name,
        type: "human",
      });
      // First account becomes admin. setAdmin uses INSERT OR IGNORE —
      // first writer wins. Concurrent registrations can't create duplicate
      // admins (singleton CHECK constraint), and the second call is a no-op.
      if (!accountRepo.getAdminAccountId()) {
        accountRepo.setAdmin(account.id);
      }

      const label = deduplicateLabel(db, account.id, baseLabel);
      const credId = randomUUID();
      const now = new Date().toISOString();
      const pubKeyBuf = Buffer.from(cred.publicKey);

      let authorizedKeysEntry: string | null = null;
      try {
        authorizedKeysEntry = coseToAuthorizedKeys(pubKeyBuf, rpId);
      } catch {
        // Non-fatal
      }

      // Create passkey
      db.insert(webauthnCredentials)
        .values({
          id: credId,
          accountId: account.id,
          credentialId: cred.id,
          publicKey: pubKeyBuf,
          counter: cred.counter,
          transports: JSON.stringify(cred.transports ?? []),
          label,
          publicKeyOpenSsh: authorizedKeysEntry,
          createdAt: now,
        })
        .run();

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
          `sw_session=${cookieValue}; HttpOnly; ${secure ? "Secure; " : ""}SameSite=Strict; Path=${basePath || "/"}; Max-Age=${sessionConfig.ttlSeconds}`,
        );
      }

      return { verified: true, accountId: account.id, credentialId: credId, label };
    } catch (err) {
      reply.status(400);
      return { error: (err as Error).message };
    }
  });
}
