import { randomUUID } from "node:crypto";
import { generateRegistrationOptions, verifyRegistrationResponse } from "@simplewebauthn/server";
import { eq } from "drizzle-orm";
import type { FastifyInstance } from "fastify";
import type { ShellWatchDB } from "../db/connection.js";
import { webauthnCredentials } from "../db/schema.js";

// In-memory challenge store (keyed by challenge ID, expires after 5 minutes)
const pendingChallenges = new Map<string, { challenge: string; expires: number }>();

function getOriginAndRpId(request: { hostname: string; protocol: string }) {
  const rpId = request.hostname.split(":")[0]; // strip port
  const origin = `${request.protocol}://${request.hostname}`;
  return { rpId, origin };
}

export function registerWebAuthnRoutes(app: FastifyInstance, db: ShellWatchDB) {
  // --- Registration: Generate Options ---
  app.post<{ Body: { label: string } }>("/api/webauthn/register/options", async (request) => {
    const { label } = request.body;
    const { rpId } = getOriginAndRpId(request);

    // Get existing credentials to exclude (prevent re-registration)
    const existing = db
      .select({ credentialId: webauthnCredentials.credentialId })
      .from(webauthnCredentials)
      .all();

    const options = await generateRegistrationOptions({
      rpName: "ShellWatch",
      rpID: rpId,
      userName: "admin",
      userDisplayName: label || "ShellWatch Admin",
      attestationType: "none",
      authenticatorSelection: {
        residentKey: "preferred",
        userVerification: "preferred",
      },
      supportedAlgorithmIDs: [-7, -8], // ES256 (P-256) and EdDSA (Ed25519)
      excludeCredentials: existing.map((c) => ({
        id: c.credentialId,
      })),
    });

    // Store challenge with expiry
    const challengeId = randomUUID();
    pendingChallenges.set(challengeId, {
      challenge: options.challenge,
      expires: Date.now() + 5 * 60 * 1000,
    });

    // Clean up expired challenges
    for (const [id, { expires }] of pendingChallenges) {
      if (expires < Date.now()) pendingChallenges.delete(id);
    }

    return { ...options, challengeId };
  });

  // --- Registration: Verify Response ---
  app.post<{ Body: { challengeId: string; label: string; credential: unknown } }>(
    "/api/webauthn/register/verify",
    async (request, reply) => {
      const { challengeId, label, credential } = request.body;
      const { rpId, origin } = getOriginAndRpId(request);

      const pending = pendingChallenges.get(challengeId);
      if (!pending || pending.expires < Date.now()) {
        pendingChallenges.delete(challengeId);
        reply.status(400);
        return { error: "Challenge expired or not found" };
      }
      pendingChallenges.delete(challengeId);

      try {
        const verification = await verifyRegistrationResponse({
          response: credential as Parameters<typeof verifyRegistrationResponse>[0]["response"],
          expectedChallenge: pending.challenge,
          expectedOrigin: origin,
          expectedRPID: rpId,
        });

        if (!verification.verified || !verification.registrationInfo) {
          reply.status(400);
          return { error: "Verification failed" };
        }

        const { credential: cred } = verification.registrationInfo;

        const id = randomUUID();
        const now = new Date().toISOString();

        db.insert(webauthnCredentials)
          .values({
            id,
            credentialId: cred.id,
            publicKey: Buffer.from(cred.publicKey),
            counter: cred.counter,
            transports: JSON.stringify(cred.transports ?? []),
            label: label || "Passkey",
            createdAt: now,
          })
          .run();

        return {
          verified: true,
          credentialId: cred.id,
          id,
        };
      } catch (err) {
        reply.status(400);
        return { error: (err as Error).message };
      }
    },
  );

  // --- List Registered Credentials ---
  app.get("/api/webauthn/credentials", async () => {
    const creds = db
      .select({
        id: webauthnCredentials.id,
        credentialId: webauthnCredentials.credentialId,
        label: webauthnCredentials.label,
        createdAt: webauthnCredentials.createdAt,
        lastUsedAt: webauthnCredentials.lastUsedAt,
      })
      .from(webauthnCredentials)
      .all();

    return { credentials: creds };
  });

  // --- Delete Credential ---
  app.delete<{ Params: { id: string } }>("/api/webauthn/credentials/:id", async (request) => {
    db.delete(webauthnCredentials).where(eq(webauthnCredentials.id, request.params.id)).run();
    return { status: "deleted" };
  });
}
