import { wsSend } from "$lib/stores/ws.js";

function bufferToBase64url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export async function handleFidoSignRequest(request: {
  requestId: string;
  credentialId: string;
  challenge: string;
  rpId: string;
}): Promise<void> {
  try {
    const decoded = atob(request.challenge);
    const challengeBytes = Uint8Array.from(decoded, (c) => c.charCodeAt(0));

    const credIdBytes = Uint8Array.from(
      atob(request.credentialId.replace(/-/g, "+").replace(/_/g, "/")),
      (c) => c.charCodeAt(0),
    );

    const assertion = (await navigator.credentials.get({
      publicKey: {
        challenge: challengeBytes,
        rpId: request.rpId,
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

    wsSend({
      type: "fido:sign-response",
      requestId: request.requestId,
      authenticatorData: bufferToBase64url(authResponse.authenticatorData),
      signature: bufferToBase64url(authResponse.signature),
      clientDataJSON: new TextDecoder().decode(authResponse.clientDataJSON),
    });
  } catch (err) {
    console.error("[FIDO] Signing failed:", err);
    wsSend({
      type: "fido:sign-error",
      requestId: request.requestId,
      error: (err as Error).message,
    });
  }
}
