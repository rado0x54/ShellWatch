import { randomUUID } from "node:crypto";
import { verifyRegistrationResponse } from "@simplewebauthn/server";
import type { ShellWatchDB } from "../db/connection.js";
import { deduplicateLabel } from "../db/repositories/credential-queries.js";
import { webauthnCredentials } from "../db/schema.js";
import { lookupAAGUID } from "./aaguid-lookup.js";
import { consumeChallenge } from "./challenge-store.js";
import { coseToAuthorizedKeys } from "./ssh-key-format.js";

export interface VerifyAndDecodeParams {
  challengeId: string;
  credential: unknown;
  rpId: string;
  trustedOrigins: string[];
}

export interface DecodedRegistration {
  credentialId: string;
  publicKey: Buffer;
  counter: number;
  transports: string[];
  baseLabel: string;
  authorizedKeysEntry: string | null;
}

export type VerifyResult =
  | { ok: true; decoded: DecodedRegistration }
  | { ok: false; error: string };

/**
 * Consume a registration challenge, verify the WebAuthn response, and decode
 * the credential payload into a DB-ready shape. No DB writes happen here, so
 * callers can wrap the subsequent insertCredentialRow() in their own
 * transaction (e.g. self-register's account-create + credential-insert atom).
 */
export async function verifyAndDecodeRegistration(
  params: VerifyAndDecodeParams,
): Promise<VerifyResult> {
  const challenge = consumeChallenge(params.challengeId);
  if (!challenge) {
    return { ok: false, error: "Challenge expired or not found" };
  }

  // UV is always required at registration. Both call sites also pass
  // authenticatorSelection.userVerification: "required" at the options step,
  // so this is the matching server-side enforcement (defense-in-depth against
  // an authenticator that ignores the request or a browser that lies).
  // Without it, self-register could enroll a non-UV credential that login.ts
  // would then reject — bricking the freshly-created account.
  const verification = await verifyRegistrationResponse({
    response: params.credential as Parameters<typeof verifyRegistrationResponse>[0]["response"],
    expectedChallenge: challenge,
    expectedOrigin: params.trustedOrigins,
    expectedRPID: params.rpId,
    requireUserVerification: true,
  });

  if (!verification.verified || !verification.registrationInfo) {
    return { ok: false, error: "Verification failed" };
  }

  const { credential: cred, aaguid } = verification.registrationInfo;
  const baseLabel = lookupAAGUID(aaguid) || "Passkey";
  const publicKey = Buffer.from(cred.publicKey);

  // Best-effort COSE → OpenSSH conversion. Only ES256 is allowed at options
  // time (registration.ts/self-register.ts both pin supportedAlgorithmIDs to
  // [-7]), so this should always succeed; null is the defensive fallback.
  let authorizedKeysEntry: string | null = null;
  try {
    authorizedKeysEntry = coseToAuthorizedKeys(publicKey, params.rpId);
  } catch {
    // Credential is still usable for browser-side auth, just won't appear in
    // the OpenSSH authorized_keys export.
  }

  return {
    ok: true,
    decoded: {
      credentialId: cred.id,
      publicKey,
      counter: cred.counter,
      transports: cred.transports ?? [],
      baseLabel,
      authorizedKeysEntry,
    },
  };
}

/**
 * Insert a verified credential row. Caller owns the transactional context —
 * pass the top-level DB for a standalone insert, or a transaction proxy when
 * the insert needs to be atomic with other writes (account creation in
 * self-register; future invite-token consumption). Label is deduplicated
 * against the account's existing passkeys.
 */
export function insertCredentialRow(
  dbOrTx: ShellWatchDB,
  accountId: string,
  decoded: DecodedRegistration,
): { id: string; label: string } {
  const id = randomUUID();
  const label = deduplicateLabel(dbOrTx, accountId, decoded.baseLabel);
  const now = new Date().toISOString();

  dbOrTx
    .insert(webauthnCredentials)
    .values({
      id,
      accountId,
      credentialId: decoded.credentialId,
      publicKey: decoded.publicKey,
      counter: decoded.counter,
      transports: JSON.stringify(decoded.transports),
      label,
      publicKeyOpenSsh: decoded.authorizedKeysEntry,
      createdAt: now,
    })
    .run();

  return { id, label };
}
