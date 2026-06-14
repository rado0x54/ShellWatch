// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * Reusable passkey (WebAuthn assertion) verification, shared by the Hydra
 * login provider and consent provider (#217). Both need the same primitive:
 * "prove possession of an active passkey", optionally bound to a specific
 * account (consent must be approved by the very subject Hydra is asking about).
 *
 * Extracted from the old /api/auth/login handler so there is exactly one
 * implementation of assertion verification + counter bookkeeping.
 */
import {
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server";
import { and, eq } from "drizzle-orm";
import type { ShellWatchDB } from "../db/connection.js";
import type { AccountRepository } from "../db/repositories/account-repo.js";
import { CREDENTIAL_STATE } from "../db/repositories/credential-queries.js";
import { webauthnCredentials } from "../db/schema.js";
import { CHALLENGE_PURPOSE, consumeChallenge, storeChallenge } from "./challenge-store.js";

export interface AssertionOptionsParams {
  db: ShellWatchDB;
  rpId: string;
  /** When set, restrict allowCredentials to this account's active credentials. */
  accountId?: string;
}

/** Build assertion options + a challenge id. Returns null when there are no usable credentials. */
export async function generatePasskeyAssertionOptions(params: AssertionOptionsParams): Promise<{
  options: Awaited<ReturnType<typeof generateAuthenticationOptions>>;
  challengeId: string;
} | null> {
  const { db, rpId, accountId } = params;
  const creds = db
    .select({ credentialId: webauthnCredentials.credentialId })
    .from(webauthnCredentials)
    .where(
      and(
        eq(webauthnCredentials.revoked, false),
        eq(webauthnCredentials.state, CREDENTIAL_STATE.active),
        accountId ? eq(webauthnCredentials.accountId, accountId) : undefined,
      ),
    )
    .all();

  if (creds.length === 0) return null;

  const options = await generateAuthenticationOptions({
    rpID: rpId,
    userVerification: "required",
    allowCredentials: creds.map((c) => ({ id: c.credentialId })),
  });
  const challengeId = storeChallenge(options.challenge, CHALLENGE_PURPOSE.login);
  return { options, challengeId };
}

export interface VerifyAssertionParams {
  db: ShellWatchDB;
  accountRepo: AccountRepository;
  rpId: string;
  trustedOrigins: string[];
  challengeId: string;
  credential: unknown;
  /** When set, the asserting credential must belong to this account or verification fails. */
  expectedAccountId?: string;
}

export type VerifyAssertionResult =
  | { ok: true; accountId: string }
  | { ok: false; status: number; error: string };

/** Verify a passkey assertion, update its counter, and (optionally) bind it to an expected account. */
export async function verifyPasskeyAssertion(
  params: VerifyAssertionParams,
): Promise<VerifyAssertionResult> {
  const { db, accountRepo, rpId, trustedOrigins, challengeId, credential, expectedAccountId } =
    params;

  const challenge = consumeChallenge(challengeId, CHALLENGE_PURPOSE.login);
  if (!challenge) return { ok: false, status: 400, error: "Challenge expired or not found" };

  const assertion = credential as { id: string };
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
    .where(eq(webauthnCredentials.credentialId, assertion.id))
    .get();

  if (!storedCred) return { ok: false, status: 400, error: "Unknown credential" };
  if (storedCred.revoked) return { ok: false, status: 403, error: "This passkey has been revoked" };
  if (storedCred.state !== CREDENTIAL_STATE.active) {
    return {
      ok: false,
      status: 403,
      error: "This passkey is awaiting confirmation on the original device",
    };
  }
  if (expectedAccountId && storedCred.accountId !== expectedAccountId) {
    // The asserting passkey is not owned by the subject Hydra is asking about.
    return { ok: false, status: 403, error: "Passkey does not match the account being authorized" };
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
    if (!verification.verified) return { ok: false, status: 400, error: "Verification failed" };

    db.update(webauthnCredentials)
      .set({
        counter: verification.authenticationInfo.newCounter,
        lastUsedAt: new Date().toISOString(),
      })
      .where(eq(webauthnCredentials.id, storedCred.id))
      .run();
    accountRepo.touchLastUsed(storedCred.accountId);

    return { ok: true, accountId: storedCred.accountId };
  } catch (err) {
    return { ok: false, status: 400, error: (err as Error).message };
  }
}
