import { startRegistration } from "@simplewebauthn/browser";

export async function registerPasskey(
  label: string,
): Promise<{ credentialId: string; id: string }> {
  // Step 1: Get registration options from server
  const optionsRes = await fetch("/api/webauthn/register/options", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ label }),
  });
  if (!optionsRes.ok) {
    const err = await optionsRes.json();
    throw new Error(err.error || "Failed to get registration options");
  }
  const options = await optionsRes.json();
  const { challengeId, ...registrationOptions } = options;

  // Step 2: Browser WebAuthn prompt (user touches key)
  const credential = await startRegistration({ optionsJSON: registrationOptions });

  // Step 3: Verify with server
  const verifyRes = await fetch("/api/webauthn/register/verify", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ challengeId, label, credential }),
  });
  if (!verifyRes.ok) {
    const err = await verifyRes.json();
    throw new Error(err.error || "Verification failed");
  }

  return verifyRes.json();
}

export interface WebAuthnCredential {
  id: string;
  credentialId: string;
  label: string;
  algorithm: string;
  fingerprint: string;
  authorizedKeysEntry: string | null;
  createdAt: string;
  lastUsedAt: string | null;
}

export async function listCredentials(): Promise<WebAuthnCredential[]> {
  const res = await fetch("/api/webauthn/credentials");
  const data = await res.json();
  return data.credentials;
}

export async function deleteCredential(id: string): Promise<void> {
  await fetch(`/api/webauthn/credentials/${id}`, { method: "DELETE" });
}
