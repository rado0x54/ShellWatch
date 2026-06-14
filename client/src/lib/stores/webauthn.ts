// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { apiFetch } from "../api.js";
import { startAuthentication, startRegistration } from "@simplewebauthn/browser";
import { writable } from "svelte/store";

/**
 * Step-up actions recognised by the server. Mirrors STEPUP_ACTION on the
 * backend; kept inline here to avoid importing server code into the client.
 */
export type StepUpAction =
  | "register_passkey"
  | "revoke_passkey"
  | "confirm_passkey"
  | "revoke_session"
  | "revoke_all_sessions";

/**
 * Run the WebAuthn step-up assertion for an action and return the resulting
 * single-use token. The token is bound to {accountId, action} server-side and
 * must be passed via the X-Shellwatch-Stepup-Token header on the gated endpoint.
 *
 * Throws on cancellation (the caller should treat that as "user aborted").
 */
export async function performStepUp(action: StepUpAction): Promise<string> {
  const optionsRes = await apiFetch("/api/webauthn/stepup/options", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ action }),
  });
  if (!optionsRes.ok) {
    const err = await optionsRes.json().catch(() => ({}));
    throw new Error(err.error || "Could not start step-up");
  }
  const { challengeId, action: _, ...assertionOptions } = await optionsRes.json();

  // Browser prompt — throws (DOMException, name "NotAllowedError") if the
  // user cancels. We let it propagate; the caller's catch decides what to
  // surface.
  const credential = await startAuthentication({ optionsJSON: assertionOptions });

  const verifyRes = await apiFetch("/api/webauthn/stepup/verify", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ challengeId, credential, action }),
  });
  if (!verifyRes.ok) {
    const err = await verifyRes.json().catch(() => ({}));
    throw new Error(err.error || "Step-up verification failed");
  }
  const { stepUpToken } = await verifyRes.json();
  return stepUpToken as string;
}

export type CredentialState = "active" | "pending_confirmation";

export interface WebAuthnCredential {
  id: string;
  credentialId: string;
  label: string;
  algorithm: string;
  fingerprint: string | null;
  authorizedKeysEntry: string | null;
  revoked: boolean;
  state: CredentialState;
  createdAt: string;
  lastUsedAt: string | null;
}

export interface PasskeyInvite {
  expiresAt: string;
  createdAt: string;
  token: string;
}

export const credentials = writable<WebAuthnCredential[]>([]);

export async function fetchCredentials(): Promise<void> {
  const res = await apiFetch("/api/webauthn/credentials");
  const data = await res.json();
  credentials.set(data.credentials);
}

/**
 * Register a new passkey for an existing (authenticated) account.
 * Triggers browser prompt, verifies + stores server-side with AAGUID-based
 * label, and returns the credential ID and suggested label for renaming.
 */
export async function startPasskeyRegistration(name?: string): Promise<{
  credentialId: string;
  label: string;
}> {
  // Step-up first: prove fresh possession of an existing passkey before we
  // run the registration ceremony. The token is attached only to /register
  // (the verify call) — /register/options isn't gated, so the user only
  // sees two browser prompts: step-up assertion, then new-passkey ceremony.
  const stepUpToken = await performStepUp("register_passkey");

  const optionsRes = await apiFetch("/api/webauthn/register/options", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ label: "pending", name }),
  });
  if (!optionsRes.ok) {
    const err = await optionsRes.json();
    throw new Error(err.error || "Failed to get registration options");
  }
  const options = await optionsRes.json();
  const { challengeId, ...registrationOptions } = options;

  const credential = await startRegistration({ optionsJSON: registrationOptions });

  const verifyRes = await apiFetch("/api/webauthn/register", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Shellwatch-Stepup-Token": stepUpToken },
    body: JSON.stringify({ challengeId, credential }),
  });
  if (!verifyRes.ok) {
    const err = await verifyRes.json();
    throw new Error(err.error || "Verification failed");
  }
  const result = await verifyRes.json();

  return {
    credentialId: result.id,
    label: result.label,
  };
}

/** Confirm a pending-confirmation credential, flipping it to active. */
export async function confirmPasskey(credentialId: string): Promise<void> {
  // Step-up: confirm is the moment a pending credential becomes a live login
  // factor. A stolen-cookie attacker would otherwise be able to register a
  // passkey from their own device via the invite flow and then confirm it
  // here; the gate forces fresh proof of an existing authenticator.
  const stepUpToken = await performStepUp("confirm_passkey");
  const res = await apiFetch(`/api/webauthn/credentials/${credentialId}/confirm`, {
    method: "POST",
    headers: { "X-Shellwatch-Stepup-Token": stepUpToken },
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || "Failed to confirm passkey");
  }
  await fetchCredentials();
}

// --- Passkey invite (single in-memory slot per account, 5min TTL) ---

/**
 * Fetch the account's currently active invite (if any). Returns null when
 * the slot is empty — that's a 404 from the server, not an error.
 */
export async function fetchActiveInvite(): Promise<PasskeyInvite | null> {
  const res = await apiFetch("/api/webauthn/invite");
  if (res.status === 404) return null;
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || "Failed to fetch invite");
  }
  const data = await res.json();
  return data.invite as PasskeyInvite;
}

/** Create or supersede the active invite for the account. */
export async function createPasskeyInvite(label?: string): Promise<PasskeyInvite> {
  // No step-up here: minting an invite produces a `pending_confirmation`
  // credential that's unusable until the in-account confirm step, which IS
  // step-up gated. Asking for an assertion twice in one chain is overkill.
  const res = await apiFetch("/api/webauthn/invite", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ label }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || "Failed to create invite");
  }
  const data = await res.json();
  return data.invite as PasskeyInvite;
}

/** Fetch invite metadata for the public registration page. */
export async function fetchInviteByToken(token: string): Promise<{
  accountName: string | null;
  expiresAt: string;
}> {
  const res = await apiFetch(`/api/passkey-invite/${encodeURIComponent(token)}`);
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || "Failed to fetch invite");
  }
  return res.json();
}

/**
 * Run the WebAuthn ceremony on device B against an invite token. The server
 * inserts the credential with an AAGUID-derived label and consumes the slot
 * — renaming is left to device A so an intercepted token can't influence the
 * label that device A's confirm UI shows. The fingerprint is for cross-device
 * visual comparison against device A's confirm modal.
 */
export async function registerWithInviteToken(params: { token: string }): Promise<{
  label: string;
  fingerprint: string | null;
}> {
  const optionsRes = await apiFetch("/api/passkey-invite/register/options", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token: params.token }),
  });
  if (!optionsRes.ok) {
    const err = await optionsRes.json().catch(() => ({}));
    throw new Error(err.error || "Failed to get registration options");
  }
  const options = await optionsRes.json();
  const { challengeId, ...registrationOptions } = options;

  const credential = await startRegistration({ optionsJSON: registrationOptions });

  const verifyRes = await apiFetch("/api/passkey-invite/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token: params.token, challengeId, credential }),
  });
  if (!verifyRes.ok) {
    const err = await verifyRes.json().catch(() => ({}));
    throw new Error(err.error || "Registration failed");
  }
  return verifyRes.json();
}

/**
 * Update a credential's label after registration.
 */
export async function renamePasskey(credentialId: string, label: string): Promise<void> {
  const res = await apiFetch(`/api/webauthn/credentials/${credentialId}/label`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ label }),
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.error || "Failed to update label");
  }
  await fetchCredentials();
}

/**
 * Register a new account with a passkey (atomic: creates account + passkey + session).
 * Triggers browser prompt, creates account server-side with AAGUID-based label.
 */
export async function registerAccount(accountName: string): Promise<{
  credentialId: string;
  label: string;
}> {
  const optionsRes = await apiFetch("/api/auth/register/options", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name: accountName }),
  });
  if (!optionsRes.ok) {
    const err = await optionsRes.json();
    throw new Error(err.error || "Failed to get registration options");
  }
  const options = await optionsRes.json();
  const { challengeId, ...registrationOptions } = options;

  const credential = await startRegistration({ optionsJSON: registrationOptions });

  const res = await apiFetch("/api/auth/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name: accountName, challengeId, credential }),
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.error || "Registration failed");
  }
  const data = await res.json();
  return {
    credentialId: data.credentialId,
    label: data.label,
  };
}

// Web login + logout + the auth check live in $lib/oauth.ts now — the web UI is
// a browser PKCE client against Hydra (#217). This store keeps registration and
// step-up (the passkey ceremonies that aren't the OAuth login itself).
export { logout } from "../oauth.js";
