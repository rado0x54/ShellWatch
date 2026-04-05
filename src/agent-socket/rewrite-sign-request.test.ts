import { describe, expect, it } from "vitest";
import { rewriteSkEcdsaSignRequest } from "./socket-agent-handler.js";

const SK_ECDSA = "sk-ecdsa-sha2-nistp256@openssh.com";
const WEBAUTHN_SK_ECDSA = "webauthn-sk-ecdsa-sha2-nistp256@openssh.com";

/** Build a minimal SSH agent SIGN_REQUEST frame with the given algorithm name. */
function buildSignRequestFrame(algo: string): Buffer {
  const algoBuf = Buffer.from(algo);
  // Key blob: string algo + 8 bytes of fake key material
  const keyMaterial = Buffer.from("testdata");
  const keyBlobLen = 4 + algoBuf.length + keyMaterial.length;
  // Data to sign
  const signData = Buffer.from("sign-this");
  const signDataLen = signData.length;
  // Flags
  const flags = Buffer.alloc(4);

  const payloadLen = 1 + 4 + keyBlobLen + 4 + signDataLen + 4;
  const frame = Buffer.alloc(4 + payloadLen);
  let offset = 0;

  // Total payload length
  frame.writeUInt32BE(payloadLen, offset);
  offset += 4;
  // Message type: SSH_AGENTC_SIGN_REQUEST = 13
  frame[offset++] = 13;
  // Key blob length
  frame.writeUInt32BE(keyBlobLen, offset);
  offset += 4;
  // Algorithm name (string)
  frame.writeUInt32BE(algoBuf.length, offset);
  offset += 4;
  algoBuf.copy(frame, offset);
  offset += algoBuf.length;
  // Key material
  keyMaterial.copy(frame, offset);
  offset += keyMaterial.length;
  // Data to sign (string)
  frame.writeUInt32BE(signDataLen, offset);
  offset += 4;
  signData.copy(frame, offset);
  offset += signDataLen;
  // Flags
  flags.copy(frame, offset);

  return frame;
}

describe("rewriteSkEcdsaSignRequest", () => {
  it("rewrites sk-ecdsa to webauthn-sk-ecdsa in SIGN_REQUEST", () => {
    const original = buildSignRequestFrame(SK_ECDSA);
    const rewritten = rewriteSkEcdsaSignRequest(original);

    expect(rewritten.length).toBe(original.length + 9); // webauthn- prefix adds 9 bytes

    // Message type preserved
    expect(rewritten[4]).toBe(13);

    // Total payload length updated
    const origPayloadLen = original.readUInt32BE(0);
    expect(rewritten.readUInt32BE(0)).toBe(origPayloadLen + 9);

    // Key blob length updated
    const origKeyBlobLen = original.readUInt32BE(5);
    expect(rewritten.readUInt32BE(5)).toBe(origKeyBlobLen + 9);

    // Algorithm name is now webauthn-sk-ecdsa
    const algoLen = rewritten.readUInt32BE(9);
    expect(algoLen).toBe(WEBAUTHN_SK_ECDSA.length);
    const algo = rewritten.subarray(13, 13 + algoLen).toString();
    expect(algo).toBe(WEBAUTHN_SK_ECDSA);

    // Key material after algo is preserved
    const origKeyMaterial = original.subarray(13 + SK_ECDSA.length);
    const newKeyMaterial = rewritten.subarray(13 + WEBAUTHN_SK_ECDSA.length);
    expect(newKeyMaterial.equals(origKeyMaterial)).toBe(true);
  });

  it("passes through frames with webauthn-sk-ecdsa unchanged", () => {
    const frame = buildSignRequestFrame(WEBAUTHN_SK_ECDSA);
    const result = rewriteSkEcdsaSignRequest(frame);
    expect(result).toBe(frame); // Same reference, no copy
  });

  it("passes through non-SIGN_REQUEST frames unchanged", () => {
    // Type 11 = SSH_AGENTC_REQUEST_IDENTITIES
    const frame = Buffer.from([0, 0, 0, 1, 11]);
    const result = rewriteSkEcdsaSignRequest(frame);
    expect(result).toBe(frame);
  });

  it("passes through frames with other key types unchanged", () => {
    const frame = buildSignRequestFrame("ssh-ed25519");
    const result = rewriteSkEcdsaSignRequest(frame);
    expect(result).toBe(frame);
  });
});
