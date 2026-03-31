import { startRegistration } from "@simplewebauthn/browser";
import type { RegistrationResponseJSON } from "@simplewebauthn/browser";
import { basePath } from "./base-path.js";

export interface RegistrationResult {
  credentialId: string;
  id: string;
  suggestedLabel: string;
}

/** Derive a human-readable label hint from the credential response. */
function suggestLabel(credential: RegistrationResponseJSON): string {
  const transports = credential.response.transports ?? [];
  const attachment = credential.authenticatorAttachment;

  // Chrome 132+ may expose authenticatorDisplayName
  const displayName = (credential.clientExtensionResults as Record<string, unknown>)
    ?.credProps as { authenticatorDisplayName?: string } | undefined;
  if (displayName?.authenticatorDisplayName) {
    return displayName.authenticatorDisplayName;
  }

  if (attachment === "platform") {
    const ua = navigator.userAgent.toLowerCase();
    if (ua.includes("iphone") || ua.includes("ipad")) return "iPhone/iPad";
    if (ua.includes("mac")) return "Mac Touch ID";
    if (ua.includes("android")) return "Android";
    if (ua.includes("windows")) return "Windows Hello";
    return "Built-in Passkey";
  }

  if (transports.includes("usb")) return "Security Key (USB)";
  if (transports.includes("nfc")) return "Security Key (NFC)";
  if (transports.includes("ble")) return "Security Key (BLE)";
  if (transports.includes("hybrid")) return "Phone/Tablet Passkey";

  return "Passkey";
}

/** Step 1+2: Get options from server and prompt user. Returns credential + challenge. */
export async function startPasskeyRegistration(): Promise<{
  challengeId: string;
  credential: RegistrationResponseJSON;
  suggestedLabel: string;
}> {
  const optionsRes = await fetch(`${basePath}/api/webauthn/register/options`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ label: "pending" }),
  });
  if (!optionsRes.ok) {
    const err = await optionsRes.json();
    throw new Error(err.error || "Failed to get registration options");
  }
  const options = await optionsRes.json();
  const { challengeId, ...registrationOptions } = options;

  const credential = await startRegistration({ optionsJSON: registrationOptions });

  return { challengeId, credential, suggestedLabel: suggestLabel(credential) };
}

/** Step 3: Verify credential with server and save with the chosen label. */
export async function finishPasskeyRegistration(
  challengeId: string,
  credential: RegistrationResponseJSON,
  label: string,
): Promise<RegistrationResult> {
  const verifyRes = await fetch(`${basePath}/api/webauthn/register/verify`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ challengeId, label, credential }),
  });
  if (!verifyRes.ok) {
    const err = await verifyRes.json();
    throw new Error(err.error || "Verification failed");
  }

  const result = await verifyRes.json();
  return { ...result, suggestedLabel: label };
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
  const res = await fetch(`${basePath}/api/webauthn/credentials`);
  const data = await res.json();
  return data.credentials;
}

export async function deleteCredential(id: string): Promise<void> {
  await fetch(`${basePath}/api/webauthn/credentials/${id}`, { method: "DELETE" });
}
