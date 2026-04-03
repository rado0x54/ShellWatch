import { createHash, randomUUID } from "node:crypto";
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";
import { and, eq } from "drizzle-orm";
import type { FastifyInstance } from "fastify";
import type { AccountRepository } from "../db/repositories/account-repo.js";
import { hasPasskeys } from "../db/repositories/credential-queries.js";
import type { ShellWatchDB } from "../db/connection.js";
import { sshKeys, webauthnCredentials } from "../db/schema.js";
import { coseToAuthorizedKeys, getSshdConfigLine } from "./ssh-key-format.js";

// In-memory challenge store (keyed by challenge ID, expires after 5 minutes)
const pendingChallenges = new Map<string, { challenge: string; expires: number }>();

/** Detect algorithm from COSE key (first bytes of the map) */
function detectAlgorithm(coseKey: Buffer): string {
  // COSE alg field (label 3): -7 = ES256 (P-256), -8 = EdDSA (Ed25519)
  if (coseKey.includes(Buffer.from([0x03, 0x26]))) return "ES256 (P-256)";
  if (coseKey.includes(Buffer.from([0x03, 0x27]))) return "EdDSA (Ed25519)";
  return "unknown";
}

/** Compute SHA-256 fingerprint of the COSE public key */
function computeFingerprint(coseKey: Buffer): string {
  return `SHA256:${createHash("sha256").update(coseKey).digest("base64url")}`;
}

interface ProxyHeaderConfig {
  hostHeader?: string;
  protoHeader?: string;
}

function getOriginAndRpId(
  request: { headers: Record<string, string | string[] | undefined>; protocol: string },
  proxy: ProxyHeaderConfig,
) {
  const forwardedHost = proxy.hostHeader ? request.headers[proxy.hostHeader] : undefined;
  const forwardedProto = proxy.protoHeader ? request.headers[proxy.protoHeader] : undefined;
  const host = String(forwardedHost ?? request.headers.host ?? "localhost");
  const protocol = String(forwardedProto ?? request.protocol);
  const rpId = host.split(":")[0];
  const origin = `${protocol}://${host}`;
  return { rpId, origin };
}

export interface SessionConfig {
  secret: string;
  ttlSeconds: number;
}

export interface WebAuthnRoutesParams {
  app: FastifyInstance;
  db: ShellWatchDB;
  accountRepo: AccountRepository;
  basePath?: string;
  proxy?: ProxyHeaderConfig;
  sessionConfig?: SessionConfig;
  trustedOrigins?: string[];
}

export function registerWebAuthnRoutes(params: WebAuthnRoutesParams) {
  const {
    app,
    db,
    accountRepo,
    basePath = "",
    proxy = {},
    sessionConfig,
    trustedOrigins = [],
  } = params;
  // --- Registration: Generate Options ---
  app.post<{ Body: { label: string; name?: string } }>(
    `${basePath}/api/webauthn/register/options`,
    async (request) => {
      const { label, name } = request.body;
      const { rpId } = getOriginAndRpId(request, proxy);

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
    },
  );

  // --- Registration: Verify Response ---
  app.post<{ Body: { challengeId: string; label: string; credential: unknown } }>(
    `${basePath}/api/webauthn/register/verify`,
    async (request, reply) => {
      const { challengeId, label, credential } = request.body;
      const { rpId, origin } = getOriginAndRpId(request, proxy);

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
          expectedOrigin: [origin, ...trustedOrigins],
          expectedRPID: rpId,
        });

        if (!verification.verified || !verification.registrationInfo) {
          reply.status(400);
          return { error: "Verification failed" };
        }

        const { credential: cred } = verification.registrationInfo;

        const id = randomUUID();
        const now = new Date().toISOString();
        const pubKeyBuf = Buffer.from(cred.publicKey);

        // Convert to OpenSSH authorized_keys format
        let authorizedKeysEntry: string | null = null;
        try {
          authorizedKeysEntry = coseToAuthorizedKeys(pubKeyBuf, rpId, label);
        } catch (convErr) {
          app.log.error(
            `Failed to convert COSE key to OpenSSH format: ${(convErr as Error).message}`,
          );
        }

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
              name: label || "Admin",
              type: "human",
            });
            accountRepo.setAdmin(admin.id);
            accountId = admin.id;
          }
        }

        if (!accountId) {
          reply.status(400);
          return { error: "No account associated with this registration" };
        }

        db.insert(webauthnCredentials)
          .values({
            id,
            accountId,
            credentialId: cred.id,
            publicKey: pubKeyBuf,
            counter: cred.counter,
            transports: JSON.stringify(cred.transports ?? []),
            label: label || "Passkey",
            publicKeyOpenSsh: authorizedKeysEntry,
            createdAt: now,
          })
          .run();

        // Also register in ssh_keys so endpoints can reference this key via keyId
        const fingerprint = computeFingerprint(pubKeyBuf);
        db.insert(sshKeys)
          .values({
            id,
            label: `${label || "Passkey"} (webauthn)`,
            type: "webauthn",
            publicKey: authorizedKeysEntry ?? "",
            fingerprint,
            enabled: true,
            createdAt: now,
            updatedAt: now,
          })
          .run();

        return {
          verified: true,
          credentialId: cred.id,
          id,
          authorizedKeysEntry,
          sshdConfig: authorizedKeysEntry ? getSshdConfigLine() : null,
        };
      } catch (err) {
        reply.status(400);
        return { error: (err as Error).message };
      }
    },
  );

  // --- List Registered Credentials (scoped to account) ---
  app.get(`${basePath}/api/webauthn/credentials`, async (request, reply) => {
    if (!request.accountId) {
      reply.status(401);
      return { error: "Not authenticated" };
    }
    const creds = db
      .select({
        id: webauthnCredentials.id,
        credentialId: webauthnCredentials.credentialId,
        publicKey: webauthnCredentials.publicKey,
        publicKeyOpenSsh: webauthnCredentials.publicKeyOpenSsh,
        label: webauthnCredentials.label,
        createdAt: webauthnCredentials.createdAt,
        lastUsedAt: webauthnCredentials.lastUsedAt,
      })
      .from(webauthnCredentials)
      .where(eq(webauthnCredentials.accountId, request.accountId))
      .all();

    return {
      credentials: creds.map((c) => ({
        id: c.id,
        credentialId: c.credentialId,
        label: c.label,
        algorithm: detectAlgorithm(c.publicKey),
        fingerprint: computeFingerprint(c.publicKey),
        authorizedKeysEntry: c.publicKeyOpenSsh ?? null,
        createdAt: c.createdAt,
        lastUsedAt: c.lastUsedAt,
      })),
      sshdConfig: getSshdConfigLine(),
    };
  });

  // --- Delete Credential (scoped to account) ---
  app.delete<{ Params: { id: string } }>(
    `${basePath}/api/webauthn/credentials/:id`,
    async (request, reply) => {
      if (!request.accountId) {
        reply.status(401);
        return { error: "Not authenticated" };
      }
      const { id } = request.params;
      // Verify ownership
      const cred = db
        .select({ id: webauthnCredentials.id })
        .from(webauthnCredentials)
        .where(
          and(eq(webauthnCredentials.id, id), eq(webauthnCredentials.accountId, request.accountId)),
        )
        .get();
      if (!cred) {
        reply.status(404);
        return { error: "Credential not found" };
      }
      db.delete(sshKeys).where(eq(sshKeys.id, id)).run();
      db.delete(webauthnCredentials).where(eq(webauthnCredentials.id, id)).run();
      return { status: "deleted" };
    },
  );

  // --- Login (Assertion): Generate Options ---
  app.post(`${basePath}/api/webauthn/login/options`, async (request) => {
    const { rpId } = getOriginAndRpId(request, proxy);

    const creds = db
      .select({ credentialId: webauthnCredentials.credentialId })
      .from(webauthnCredentials)
      .all();

    if (creds.length === 0) {
      return { error: "no_passkeys" };
    }

    const options = await generateAuthenticationOptions({
      rpID: rpId,
      userVerification: "preferred",
      allowCredentials: creds.map((c) => ({ id: c.credentialId })),
    });

    const challengeId = randomUUID();
    pendingChallenges.set(challengeId, {
      challenge: options.challenge,
      expires: Date.now() + 5 * 60 * 1000,
    });

    return { ...options, challengeId };
  });

  // --- Login (Assertion): Verify ---
  app.post<{ Body: { challengeId: string; credential: unknown } }>(
    `${basePath}/api/webauthn/login/verify`,
    async (request, reply) => {
      if (!sessionConfig) {
        reply.status(500);
        return { error: "Session config not available" };
      }

      const { challengeId, credential } = request.body;
      const { rpId, origin } = getOriginAndRpId(request, proxy);

      const expectedOrigins = [origin, ...trustedOrigins];

      const pending = pendingChallenges.get(challengeId);
      if (!pending || pending.expires < Date.now()) {
        pendingChallenges.delete(challengeId);
        reply.status(400);
        return { error: "Challenge expired or not found" };
      }
      pendingChallenges.delete(challengeId);

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
        })
        .from(webauthnCredentials)
        .where(eq(webauthnCredentials.credentialId, assertionResponse.id))
        .get();

      if (!storedCred) {
        reply.status(400);
        return { error: "Unknown credential" };
      }

      try {
        const verification = await verifyAuthenticationResponse({
          response: credential as Parameters<typeof verifyAuthenticationResponse>[0]["response"],
          expectedChallenge: pending.challenge,
          expectedOrigin: expectedOrigins,
          expectedRPID: rpId,
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
          `sw_session=${cookieValue}; HttpOnly; ${secure ? "Secure; " : ""}SameSite=Strict; Path=${basePath || "/"}; Max-Age=${sessionConfig.ttlSeconds}`,
        );

        return { verified: true };
      } catch (err) {
        reply.status(400);
        return { error: (err as Error).message };
      }
    },
  );

  // --- Self-Registration: Create account + passkey atomically ---
  app.post<{
    Body: { name: string; challengeId: string; label: string; credential: unknown };
  }>(`${basePath}/api/auth/register`, async (request, reply) => {
    const { name, challengeId, label, credential } = request.body;
    if (!name || !challengeId || !credential) {
      reply.status(400);
      return { error: "name, challengeId, and credential are required" };
    }

    const { rpId, origin } = getOriginAndRpId(request, proxy);
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
        expectedOrigin: [origin, ...trustedOrigins],
        expectedRPID: rpId,
      });

      if (!verification.verified || !verification.registrationInfo) {
        reply.status(400);
        return { error: "Verification failed" };
      }

      const { credential: cred } = verification.registrationInfo;

      // Create account — first account becomes admin
      const account = await accountRepo.create({
        id: randomUUID(),
        name,
        type: "human",
      });
      if (!accountRepo.getAdminAccountId()) {
        accountRepo.setAdmin(account.id);
      }

      const credId = randomUUID();
      const now = new Date().toISOString();
      const pubKeyBuf = Buffer.from(cred.publicKey);

      let authorizedKeysEntry: string | null = null;
      try {
        authorizedKeysEntry = coseToAuthorizedKeys(pubKeyBuf, rpId, label);
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
          label: label || "Passkey",
          publicKeyOpenSsh: authorizedKeysEntry,
          createdAt: now,
        })
        .run();

      // Register in ssh_keys
      const fingerprint = computeFingerprint(pubKeyBuf);
      db.insert(sshKeys)
        .values({
          id: credId,
          label: `${label || "Passkey"} (webauthn)`,
          type: "webauthn",
          publicKey: authorizedKeysEntry ?? "",
          fingerprint,
          enabled: true,
          createdAt: now,
          updatedAt: now,
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

      return { verified: true, accountId: account.id };
    } catch (err) {
      reply.status(400);
      return { error: (err as Error).message };
    }
  });
}
