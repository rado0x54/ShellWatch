import { verifyAuthenticationResponse } from "@simplewebauthn/server";
import { eq } from "drizzle-orm";
import type { AccountRepository } from "../db/repositories/account-repo.js";
import type { ShellWatchDB } from "../db/connection.js";
import { webauthnCredentials } from "../db/schema.js";
import { consumeChallenge } from "./challenge-store.js";

/**
 * Shape of the client's assertion payload from `navigator.credentials.get`.
 * Kept loose because the SimpleWebAuthn server validates the structure.
 */
export type AuthenticationResponseLike = {
  id: string;
  rawId: string;
  response: unknown;
  type: string;
  authenticatorAttachment?: string;
  clientExtensionResults?: unknown;
};

export interface VerifyPasskeyInput {
  db: ShellWatchDB;
  accountRepo: AccountRepository;
  rpId: string;
  trustedOrigins: string[];
  challengeId: string;
  credential: AuthenticationResponseLike;
}

export type VerifyPasskeyResult =
  | { ok: true; accountId: string; credentialId: string }
  | { ok: false; status: number; error: string };

/**
 * Shared passkey assertion verifier used by both the Web UI's
 * `/api/webauthn/login/verify` route and the OAuth interaction flow.
 *
 * Produces a plain result object rather than touching a Fastify reply so
 * callers decide what happens after verification (set a session cookie,
 * resolve an OAuth interaction, etc.). Side effects are limited to
 * DB writes (credential counter, account `lastUsedAt`).
 */
export async function verifyPasskeyAssertion(
  input: VerifyPasskeyInput,
): Promise<VerifyPasskeyResult> {
  const challenge = consumeChallenge(input.challengeId);
  if (!challenge) {
    return { ok: false, status: 400, error: "Challenge expired or not found" };
  }

  const storedCred = input.db
    .select({
      id: webauthnCredentials.id,
      accountId: webauthnCredentials.accountId,
      credentialId: webauthnCredentials.credentialId,
      publicKey: webauthnCredentials.publicKey,
      counter: webauthnCredentials.counter,
      transports: webauthnCredentials.transports,
      revoked: webauthnCredentials.revoked,
    })
    .from(webauthnCredentials)
    .where(eq(webauthnCredentials.credentialId, input.credential.id))
    .get();

  if (!storedCred) {
    return { ok: false, status: 400, error: "Unknown credential" };
  }
  if (storedCred.revoked) {
    return { ok: false, status: 403, error: "This passkey has been revoked" };
  }

  try {
    const verification = await verifyAuthenticationResponse({
      response: input.credential as Parameters<typeof verifyAuthenticationResponse>[0]["response"],
      expectedChallenge: challenge,
      expectedOrigin: input.trustedOrigins,
      expectedRPID: input.rpId,
      requireUserVerification: true,
      credential: {
        id: storedCred.credentialId,
        publicKey: new Uint8Array(storedCred.publicKey),
        counter: storedCred.counter,
        transports: storedCred.transports ? JSON.parse(storedCred.transports) : undefined,
      },
    });

    if (!verification.verified) {
      return { ok: false, status: 400, error: "Verification failed" };
    }

    input.db
      .update(webauthnCredentials)
      .set({
        counter: verification.authenticationInfo.newCounter,
        lastUsedAt: new Date().toISOString(),
      })
      .where(eq(webauthnCredentials.id, storedCred.id))
      .run();

    input.accountRepo.touchLastUsed(storedCred.accountId);

    return { ok: true, accountId: storedCred.accountId, credentialId: storedCred.credentialId };
  } catch (err) {
    return { ok: false, status: 400, error: (err as Error).message };
  }
}
