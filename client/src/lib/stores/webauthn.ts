import { startAuthentication, startRegistration } from "@simplewebauthn/browser";
import { writable } from "svelte/store";

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

export type PasskeyInviteStatus = "pending" | "registered" | "expired" | "revoked";

export interface PasskeyInvite {
  id: string;
  label: string;
  expiresAt: string;
  createdAt: string;
  consumedAt: string | null;
  revokedAt: string | null;
  credentialId: string | null;
  status: PasskeyInviteStatus;
  /** Only present in the response of POST /api/webauthn/invites; never on list. */
  token?: string;
}

export const credentials = writable<WebAuthnCredential[]>([]);
export const passkeyInvites = writable<PasskeyInvite[]>([]);

export async function fetchCredentials(): Promise<void> {
  const res = await fetch("/api/webauthn/credentials");
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
  const optionsRes = await fetch("/api/webauthn/register/options", {
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

  const verifyRes = await fetch("/api/webauthn/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
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
  const res = await fetch(`/api/webauthn/credentials/${credentialId}/confirm`, { method: "POST" });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || "Failed to confirm passkey");
  }
  await fetchCredentials();
}

// --- Passkey invites ---

export async function fetchPasskeyInvites(): Promise<void> {
  const res = await fetch("/api/webauthn/invites");
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || "Failed to fetch invites");
  }
  const data = await res.json();
  passkeyInvites.set(data.invites);
}

/** Create a new invite. Returns the full invite including the one-time token. */
export async function createPasskeyInvite(label?: string): Promise<PasskeyInvite> {
  const res = await fetch("/api/webauthn/invites", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ label }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || "Failed to create invite");
  }
  const data = await res.json();
  await fetchPasskeyInvites();
  return data.invite as PasskeyInvite;
}

export async function revokePasskeyInvite(id: string): Promise<void> {
  const res = await fetch(`/api/webauthn/invites/${id}/revoke`, { method: "POST" });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || "Failed to revoke invite");
  }
  await Promise.all([fetchPasskeyInvites(), fetchCredentials()]);
}

/** Fetch invite metadata for the public registration page. */
export async function fetchInviteByToken(token: string): Promise<{
  status: PasskeyInviteStatus;
  label: string;
  expiresAt: string;
}> {
  const res = await fetch(`/api/passkey-invite/${encodeURIComponent(token)}`);
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || "Failed to fetch invite");
  }
  return res.json();
}

/** Run the WebAuthn ceremony on device B against an invite token. */
export async function registerWithInviteToken(token: string): Promise<{ label: string }> {
  const optionsRes = await fetch("/api/passkey-invite/register/options", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token }),
  });
  if (!optionsRes.ok) {
    const err = await optionsRes.json().catch(() => ({}));
    throw new Error(err.error || "Failed to get registration options");
  }
  const options = await optionsRes.json();
  const { challengeId, ...registrationOptions } = options;

  const credential = await startRegistration({ optionsJSON: registrationOptions });

  const verifyRes = await fetch("/api/passkey-invite/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token, challengeId, credential }),
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
  const res = await fetch(`/api/webauthn/credentials/${credentialId}/label`, {
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
  const optionsRes = await fetch("/api/auth/register/options", {
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

  const res = await fetch("/api/auth/register", {
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

export class NoPasskeysError extends Error {
  constructor() {
    super("No passkeys registered");
    this.name = "NoPasskeysError";
  }
}

export async function login(): Promise<void> {
  const optionsRes = await fetch("/api/auth/login/options", { method: "POST" });
  if (!optionsRes.ok) {
    const err = await optionsRes.json();
    throw new Error(err.error || "Failed to get login options");
  }
  const data = await optionsRes.json();
  if (data.error === "no_passkeys") {
    throw new NoPasskeysError();
  }
  const { challengeId, ...options } = data;

  const credential = await startAuthentication({ optionsJSON: options });

  const verifyRes = await fetch("/api/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ challengeId, credential }),
  });
  if (!verifyRes.ok) {
    const err = await verifyRes.json();
    throw new Error(err.error || "Verification failed");
  }
}

export async function logout(): Promise<void> {
  await fetch("/api/auth/logout", { method: "POST" });
  window.location.href = "/login";
}

/**
 * Check auth state by probing a protected endpoint.
 * Returns whether the user has a valid session.
 */
export async function checkAuth(): Promise<{ authenticated: boolean }> {
  try {
    const res = await fetch("/api/auth/me");
    return { authenticated: res.ok };
  } catch {
    return { authenticated: false };
  }
}
