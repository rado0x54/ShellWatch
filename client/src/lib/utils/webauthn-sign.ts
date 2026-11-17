// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { apiFetch } from "../api.js";
/** Encode an ArrayBuffer as a base64url string (no padding). */
export function bufferToBase64url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export interface SignCeremonyParams {
  credentialId: string;
  /** Standard base64-encoded challenge (not base64url) */
  challenge: string;
  rpId: string;
  /** Per-endpoint WebAuthn userVerification policy. Defaults to "required". */
  userVerification?: "required" | "preferred" | "discouraged";
}

export interface SignCeremonyResult {
  authenticatorData: string;
  signature: string;
  clientDataJSON: string;
}

/**
 * Perform the WebAuthn signing ceremony: decode the challenge,
 * call navigator.credentials.get(), and return the assertion
 * fields encoded as base64url strings ready for the resolve API.
 */
export async function performSignCeremony(params: SignCeremonyParams): Promise<SignCeremonyResult> {
  const decoded = atob(params.challenge);
  const challengeBytes = Uint8Array.from(decoded, (c) => c.charCodeAt(0));

  const credIdBytes = Uint8Array.from(
    atob(params.credentialId.replace(/-/g, "+").replace(/_/g, "/")),
    (c) => c.charCodeAt(0),
  );

  const assertion = (await navigator.credentials.get({
    publicKey: {
      challenge: challengeBytes,
      rpId: params.rpId,
      allowCredentials: [
        {
          id: credIdBytes,
          type: "public-key",
          transports: ["usb", "nfc", "ble", "internal"],
        },
      ],
      userVerification: params.userVerification ?? "required",
      timeout: 60000,
    },
  })) as PublicKeyCredential;

  if (!assertion?.response) {
    throw new Error("No assertion returned");
  }

  const authResponse = assertion.response as AuthenticatorAssertionResponse;

  return {
    authenticatorData: bufferToBase64url(authResponse.authenticatorData),
    signature: bufferToBase64url(authResponse.signature),
    clientDataJSON: new TextDecoder().decode(authResponse.clientDataJSON),
  };
}

export interface ResolveResponse {
  redirectTo?: string;
}

/** A server-computed redirect is only followed when it is a same-origin path. */
export function isSafeRedirect(path: string): boolean {
  return path.startsWith("/") && !path.startsWith("//");
}

/**
 * The session a post-approval `redirectTo` points at (`/session/<id>`, set for
 * sign requests raised while opening a session or from inside one), or null —
 * e.g. agent-proxy requests carry no destination (#273).
 */
export function sessionIdFromRedirect(redirectTo: string | undefined): string | null {
  if (!redirectTo || !isSafeRedirect(redirectTo)) return null;
  const match = /^\/session\/([^/?#]+)$/.exec(redirectTo);
  return match ? decodeURIComponent(match[1]) : null;
}

/** Resolve a PendingAction via the REST API after a successful ceremony. */
export async function resolveAction(
  actionId: string,
  result: SignCeremonyResult,
): Promise<ResolveResponse> {
  const res = await apiFetch(`/api/actions/${actionId}/resolve`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(result),
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({ error: "Unknown error" }));
    throw new Error(body.error ?? `HTTP ${res.status}`);
  }
  return (await res.json()) as ResolveResponse;
}

/** Approve a key-approve PendingAction (no WebAuthn ceremony needed). */
export async function approveAction(actionId: string): Promise<ResolveResponse> {
  const res = await apiFetch(`/api/actions/${actionId}/resolve`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: "{}",
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({ error: "Unknown error" }));
    throw new Error(body.error ?? `HTTP ${res.status}`);
  }
  return (await res.json()) as ResolveResponse;
}

/** Human-readable labels for sign request sources. */
export const sourceLabels: Record<string, string> = {
  "agent-proxy": "Agent Proxy",
  "endpoint-auth": "Endpoint Authentication",
  "agent-forwarding": "Agent Forwarding",
};

/** Human-readable labels for endpoint-auth trigger kinds. */
export const triggerKindLabels: Record<string, string> = {
  ui: "Web UI",
  mcp: "MCP Client",
  ticket: "One-time access ticket",
};

/**
 * Outcome of a skip (#308). "Skip" drops this one key; ShellWatch then offers
 * the next key the server accepts, which arrives as a new request. The wire
 * still calls it deny (`POST /api/actions/{id}/deny`, status "denied").
 *
 * - `skipped`: the key was skipped.
 * - `ended`: the request was no longer pending (it expired just before, or was
 *   swept) — nothing to skip, the request is over either way.
 */
export type SkipResult = { kind: "skipped" } | { kind: "ended"; status: string };

/** The skip call itself failed: nothing was skipped, the prompt stays. */
export class SkipFailedError extends Error {
  constructor(detail: string) {
    super(`Failed to skip: ${detail}`);
    this.name = "SkipFailedError";
  }
}

/** Skip a pending sign / key-approve request. Throws SkipFailedError. */
export async function skipAction(actionId: string): Promise<SkipResult> {
  let res: Response;
  try {
    res = await apiFetch(`/api/actions/${actionId}/deny`, { method: "POST" });
  } catch (err) {
    throw new SkipFailedError(err instanceof Error ? err.message : String(err));
  }
  if (res.ok) {
    // The server reports the store-asserted outcome: "denied", or "expired"
    // when the action lapsed just before the skip landed.
    const body = (await res.json().catch(() => ({}))) as { status?: string };
    return body.status === "expired" ? { kind: "ended", status: "expired" } : { kind: "skipped" };
  }
  // 404: swept in between; it had expired. Anything else (409 lost a race
  // against a resolve, 5xx) is a failed skip.
  if (res.status === 404) return { kind: "ended", status: "expired" };
  const body = (await res.json().catch(() => ({}))) as { error?: string };
  throw new SkipFailedError(body.error ?? `HTTP ${res.status}`);
}

/**
 * Whether a ceremony failure means "this device can't or won't use that
 * passkey". Browsers fold "no matching passkey here", "dialog dismissed" and
 * "timed out" into one NotAllowedError and don't tell them apart; every other
 * error (SecurityError, AbortError, ...) is a real failure and does not skip.
 */
export function isCeremonyCancelled(err: unknown): boolean {
  return (
    typeof err === "object" &&
    err !== null &&
    (err as { name?: unknown }).name === "NotAllowedError"
  );
}

export type SignOrSkipOutcome =
  | { kind: "signed"; response: ResolveResponse }
  | { kind: "auto-skipped"; skip: SkipResult };

export interface SignOrSkipDeps {
  ceremony?: (p: SignCeremonyParams) => Promise<SignCeremonyResult>;
  resolve?: (actionId: string, r: SignCeremonyResult) => Promise<ResolveResponse>;
  skip?: (actionId: string) => Promise<SkipResult>;
}

/**
 * Run the passkey ceremony and resolve the request; a cancelled ceremony
 * (NotAllowedError only) runs the Skip flow automatically (#308). Throws the
 * ceremony / resolve error otherwise, and SkipFailedError when the automatic
 * skip call fails — in both cases nothing was skipped.
 */
export async function signOrAutoSkip(
  actionId: string,
  params: SignCeremonyParams,
  deps: SignOrSkipDeps = {},
): Promise<SignOrSkipOutcome> {
  const ceremony = deps.ceremony ?? performSignCeremony;
  const resolveFn = deps.resolve ?? resolveAction;
  const skip = deps.skip ?? skipAction;
  let result: SignCeremonyResult;
  try {
    result = await ceremony(params);
  } catch (err) {
    if (!isCeremonyCancelled(err)) throw err;
    return { kind: "auto-skipped", skip: await skip(actionId) };
  }
  return { kind: "signed", response: await resolveFn(actionId, result) };
}

/** Info toast after a manual skip. */
export function manualSkipMessage(keyLabel: string | undefined): string {
  return `Skipped ${keyLabel || "key"}. If another key matches, a new request follows.`;
}

/** Info toast after an automatic skip (cancelled / unavailable passkey). */
export function autoSkipMessage(passkeyLabel: string | undefined): string {
  return `Skipped ${passkeyLabel || "passkey"}: not available on this device`;
}

/** Info toast when a skip found the request already over. */
export function endedMessage(status: string): string {
  return status === "expired"
    ? "The request had already expired."
    : `The request was already ${status}.`;
}

/** The toast text for a finished skip, manual or automatic. */
export function skipResultMessage(
  skip: SkipResult,
  mode: "manual" | "auto",
  label: string | undefined,
): string {
  if (skip.kind === "ended") return endedMessage(skip.status);
  return mode === "auto" ? autoSkipMessage(label) : manualSkipMessage(label);
}
