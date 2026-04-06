import { startAuthentication, startRegistration } from "@simplewebauthn/browser";
import { get, writable } from "svelte/store";
import { basePath } from "./connection.js";

export interface WebAuthnCredential {
  id: string;
  credentialId: string;
  label: string;
  algorithm: string;
  fingerprint: string;
  authorizedKeysEntry: string | null;
  revoked: boolean;
  createdAt: string;
  lastUsedAt: string | null;
}

export const credentials = writable<WebAuthnCredential[]>([]);

export async function fetchCredentials(): Promise<void> {
  const base = get(basePath);
  const res = await fetch(`${base}/api/webauthn/credentials`);
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
  const base = get(basePath);
  const optionsRes = await fetch(`${base}/api/webauthn/register/options`, {
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

  const verifyRes = await fetch(`${base}/api/webauthn/register/verify`, {
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

/**
 * Update a credential's label after registration.
 */
export async function renamePasskey(credentialId: string, label: string): Promise<void> {
  const base = get(basePath);
  const res = await fetch(`${base}/api/webauthn/credentials/${credentialId}/label`, {
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
  const base = get(basePath);
  const optionsRes = await fetch(`${base}/api/webauthn/register/options`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ label: "pending", name: accountName }),
  });
  if (!optionsRes.ok) {
    const err = await optionsRes.json();
    throw new Error(err.error || "Failed to get registration options");
  }
  const options = await optionsRes.json();
  const { challengeId, ...registrationOptions } = options;

  const credential = await startRegistration({ optionsJSON: registrationOptions });

  const res = await fetch(`${base}/api/auth/register`, {
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
  const base = get(basePath);

  const optionsRes = await fetch(`${base}/api/webauthn/login/options`, { method: "POST" });
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

  const verifyRes = await fetch(`${base}/api/webauthn/login/verify`, {
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
  const base = get(basePath);
  await fetch(`${base}/api/auth/logout`, { method: "POST" });
  window.location.href = `${base}/login`;
}

/**
 * Check auth state by probing a protected endpoint.
 * Returns whether the user has a valid session.
 */
export async function checkAuth(): Promise<{ authenticated: boolean }> {
  const base = get(basePath);
  try {
    const res = await fetch(`${base}/api/auth/me`);
    return { authenticated: res.ok };
  } catch {
    return { authenticated: false };
  }
}
