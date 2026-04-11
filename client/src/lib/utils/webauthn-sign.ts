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
      userVerification: "discouraged",
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

/** Resolve a PendingAction via the REST API after a successful ceremony. */
export async function resolveAction(actionId: string, result: SignCeremonyResult): Promise<void> {
  const res = await fetch(`/api/actions/${actionId}/resolve`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(result),
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({ error: "Unknown error" }));
    throw new Error(body.error ?? `HTTP ${res.status}`);
  }
}

/** Approve a key-approve PendingAction (no WebAuthn ceremony needed). */
export async function approveAction(actionId: string): Promise<void> {
  const res = await fetch(`/api/actions/${actionId}/resolve`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: "{}",
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({ error: "Unknown error" }));
    throw new Error(body.error ?? `HTTP ${res.status}`);
  }
}

/** Human-readable labels for sign request sources. */
export const sourceLabels: Record<string, string> = {
  "agent-proxy": "Agent Proxy",
  ui: "SSH Connection",
  mcp: "MCP Client",
  "forwarding-agent": "Agent Forwarding",
};
