import type { RegistrationResponseJSON } from "@simplewebauthn/browser";
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

export async function deleteCredential(id: string): Promise<void> {
  const base = get(basePath);
  await fetch(`${base}/api/webauthn/credentials/${id}`, { method: "DELETE" });
  await fetchCredentials();
}

function suggestLabel(credential: RegistrationResponseJSON): string {
  const transports = credential.response.transports ?? [];
  const attachment = credential.authenticatorAttachment;

  const displayName = (credential.clientExtensionResults as Record<string, unknown>)?.credProps as
    | { authenticatorDisplayName?: string }
    | undefined;
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

export async function startPasskeyRegistration(): Promise<{
  challengeId: string;
  credential: RegistrationResponseJSON;
  suggestedLabel: string;
}> {
  const base = get(basePath);
  const optionsRes = await fetch(`${base}/api/webauthn/register/options`, {
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

export async function finishPasskeyRegistration(
  challengeId: string,
  credential: RegistrationResponseJSON,
  label: string,
): Promise<void> {
  const base = get(basePath);
  const verifyRes = await fetch(`${base}/api/webauthn/register/verify`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ challengeId, label, credential }),
  });
  if (!verifyRes.ok) {
    const err = await verifyRes.json();
    throw new Error(err.error || "Verification failed");
  }
  await fetchCredentials();
}

export async function login(): Promise<void> {
  const base = get(basePath);

  const optionsRes = await fetch(`${base}/api/webauthn/login/options`, { method: "POST" });
  if (!optionsRes.ok) {
    const err = await optionsRes.json();
    throw new Error(err.error || "Failed to get login options");
  }
  const { challengeId, ...options } = await optionsRes.json();

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

export type InitStatus = "setup_required" | "passkey_required" | "ready";

export async function checkAuth(): Promise<{ initStatus: InitStatus; authenticated: boolean }> {
  const base = get(basePath);
  try {
    const res = await fetch(`${base}/api/webauthn/status`);
    if (!res.ok) return { initStatus: "setup_required", authenticated: false };
    const data = await res.json();
    const initStatus: InitStatus = data.status;

    if (initStatus !== "ready") {
      return { initStatus, authenticated: false };
    }

    // System is ready — check if we have a valid session
    const authCheck = await fetch(`${base}/api/sessions`);
    return { initStatus, authenticated: authCheck.status !== 401 };
  } catch {
    return { initStatus: "setup_required", authenticated: false };
  }
}
