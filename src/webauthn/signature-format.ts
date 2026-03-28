/**
 * WebAuthn to SSH signature format conversion.
 *
 * SSH signature wire format for webauthn-sk-ecdsa-sha2-nistp256@openssh.com:
 *
 *   string  "webauthn-sk-ecdsa-sha2-nistp256@openssh.com"   (algorithm)
 *   string  signature_blob:
 *     string  ecdsa_signature  (SSH wire: uint32 R_len || R || uint32 S_len || S)
 *     byte    flags            (authenticator data flags)
 *     uint32  counter          (authenticator counter)
 *     string  origin           (e.g., "http://localhost:3000")
 *     string  clientDataJSON   (from WebAuthn assertion)
 *     string  extensions       (empty for now)
 *
 * The ECDSA signature comes from the WebAuthn response as ASN.1 DER encoded.
 * It must be decoded and re-encoded in SSH wire format.
 *
 * Based on the ssheasy project (github.com/hullarb/ssheasy).
 */

const ALGORITHM = "webauthn-sk-ecdsa-sha2-nistp256@openssh.com";

/** Write a uint32 big-endian */
function _writeU32(buf: Buffer, offset: number, value: number): number {
  buf.writeUInt32BE(value, offset);
  return offset + 4;
}

/** Encode a string/bytes as SSH wire string (uint32 length + data) */
function sshString(data: string | Buffer): Buffer {
  const payload = typeof data === "string" ? Buffer.from(data, "utf-8") : data;
  const buf = Buffer.alloc(4 + payload.length);
  buf.writeUInt32BE(payload.length, 0);
  payload.copy(buf, 4);
  return buf;
}

/**
 * Parse ASN.1 DER encoded ECDSA signature into R and S components.
 * DER format: 0x30 <len> 0x02 <r_len> <r> 0x02 <s_len> <s>
 */
export function parseAsn1Signature(derSig: Buffer): { r: Buffer; s: Buffer } {
  let offset = 0;

  if (derSig[offset++] !== 0x30) {
    throw new Error("Invalid ASN.1 signature: expected SEQUENCE tag");
  }

  // Read sequence length (may be 1 or 2 bytes)
  let seqLen = derSig[offset++];
  if (seqLen & 0x80) {
    const numBytes = seqLen & 0x7f;
    seqLen = 0;
    for (let i = 0; i < numBytes; i++) {
      seqLen = (seqLen << 8) | derSig[offset++];
    }
  }

  // Read R
  if (derSig[offset++] !== 0x02) {
    throw new Error("Invalid ASN.1 signature: expected INTEGER tag for R");
  }
  const rLen = derSig[offset++];
  let r = derSig.subarray(offset, offset + rLen);
  offset += rLen;

  // Read S
  if (derSig[offset++] !== 0x02) {
    throw new Error("Invalid ASN.1 signature: expected INTEGER tag for S");
  }
  const sLen = derSig[offset++];
  let s = derSig.subarray(offset, offset + sLen);

  // Strip leading zero bytes (ASN.1 uses them for positive sign)
  if (r.length > 32 && r[0] === 0x00) r = r.subarray(1);
  if (s.length > 32 && s[0] === 0x00) s = s.subarray(1);

  // Pad to 32 bytes if shorter
  if (r.length < 32) r = Buffer.concat([Buffer.alloc(32 - r.length), r]);
  if (s.length < 32) s = Buffer.concat([Buffer.alloc(32 - s.length), s]);

  return { r, s };
}

/**
 * Parse the WebAuthn assertion response to extract signature components.
 *
 * @param authenticatorData - Raw authenticator data from the assertion
 * @param signature - ASN.1 DER encoded ECDSA signature from the assertion
 */
export function parseWebAuthnSignature(
  authenticatorData: Buffer,
  signature: Buffer,
): { r: Buffer; s: Buffer; flags: number; counter: number } {
  const { r, s } = parseAsn1Signature(signature);

  // Authenticator data: first 32 bytes = rpIdHash, then flags (1 byte), then counter (4 bytes BE)
  const flags = authenticatorData[32];
  const counter = authenticatorData.readUInt32BE(33);

  return { r, s, flags, counter };
}

/**
 * Build the SSH signature blob for webauthn-sk-ecdsa-sha2-nistp256@openssh.com.
 *
 * This is what gets returned from the agent's sign() callback.
 * Note: ssh2's agent protocol will strip the algorithm name and use only the blob.
 */
export function buildSshSignatureBlob(
  r: Buffer,
  s: Buffer,
  flags: number,
  counter: number,
  clientDataJSON: string,
): Buffer {
  // Build the ECDSA signature in SSH wire format: string R || string S
  const ecdsaSig = Buffer.concat([sshString(r), sshString(s)]);

  // Build the inner blob: ecdsa_sig || flags || counter || origin || clientData || extensions
  // Extract origin from clientDataJSON
  let origin = "";
  try {
    const clientData = JSON.parse(clientDataJSON);
    origin = clientData.origin || "";
  } catch {
    // If we can't parse, leave origin empty
  }

  const ecdsaSigStr = sshString(ecdsaSig);
  const flagsBuf = Buffer.from([flags]);
  const counterBuf = Buffer.alloc(4);
  counterBuf.writeUInt32BE(counter, 0);
  const originStr = sshString(origin);
  const clientDataStr = sshString(clientDataJSON);
  const extensionsStr = sshString("");

  const innerBlob = Buffer.concat([
    ecdsaSigStr,
    flagsBuf,
    counterBuf,
    originStr,
    clientDataStr,
    extensionsStr,
  ]);

  // Wrap: algorithm name + inner blob
  const algoStr = sshString(ALGORITHM);
  const blobStr = sshString(innerBlob);

  return Buffer.concat([algoStr, blobStr]);
}
