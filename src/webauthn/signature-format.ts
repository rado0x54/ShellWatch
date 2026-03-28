/**
 * WebAuthn to SSH signature format conversion.
 *
 * Wire format on the SSH packet (from OpenSSH PROTOCOL.u2f):
 *
 *   string  "webauthn-sk-ecdsa-sha2-nistp256@openssh.com"
 *   string  ecdsa_signature    ← Blob: string R_mpint || string S_mpint
 *   byte    flags              ← Rest: appended raw after the Blob string
 *   uint32  counter
 *   string  origin
 *   string  clientData
 *   string  extensions
 *
 * ssh2's agent.js strips the algorithm name from the agent response and reads
 * the remaining bytes as a single string. Protocol.js then writes that string
 * into the SSH packet as: string algo + string <agent's returned bytes>.
 *
 * So the agent must return:
 *   string algo + (string ecdsaSig + byte flags + uint32 counter + string origin + string clientData + string extensions)
 *
 * Where the part after algo is NOT wrapped in sshString — it's returned as the
 * second readString() from the agent response, then written verbatim by Protocol.js.
 *
 * Based on the ssheasy project (github.com/hullarb/ssheasy).
 */

const ALGORITHM = "webauthn-sk-ecdsa-sha2-nistp256@openssh.com";

/** Encode a string/bytes as SSH wire string (uint32 length + data) */
function sshString(data: string | Buffer): Buffer {
  const payload = typeof data === "string" ? Buffer.from(data, "utf-8") : data;
  const buf = Buffer.alloc(4 + payload.length);
  buf.writeUInt32BE(payload.length, 0);
  payload.copy(buf, 4);
  return buf;
}

/**
 * Encode a big integer as SSH mpint (length-prefixed, big-endian, with sign padding).
 * If the MSB is set, prepend a 0x00 byte to indicate positive.
 */
function sshMpint(value: Buffer): Buffer {
  // Strip leading zeros
  let start = 0;
  while (start < value.length - 1 && value[start] === 0) start++;
  let trimmed = value.subarray(start);

  // Add leading 0x00 if MSB is set (SSH mpint convention for positive numbers)
  if (trimmed[0] & 0x80) {
    trimmed = Buffer.concat([Buffer.from([0x00]), trimmed]);
  }

  return sshString(trimmed);
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
  const r = derSig.subarray(offset, offset + rLen);
  offset += rLen;

  // Read S
  if (derSig[offset++] !== 0x02) {
    throw new Error("Invalid ASN.1 signature: expected INTEGER tag for S");
  }
  const sLen = derSig[offset++];
  const s = derSig.subarray(offset, offset + sLen);

  // Return raw ASN.1 integer bytes (may include leading 0x00 for sign)
  return { r: Buffer.from(r), s: Buffer.from(s) };
}

/**
 * Parse the WebAuthn assertion response to extract signature components.
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
 * Returns the full agent response format: string algo + string sigData
 * ssh2's agent.js will strip algo and return sigData to Protocol.js.
 * Protocol.js writes it into the SSH packet.
 */
export function buildSshSignatureBlob(
  r: Buffer,
  s: Buffer,
  flags: number,
  counter: number,
  clientDataJSON: string,
): Buffer {
  // ECDSA signature in SSH wire format: mpint R || mpint S
  // Go's ssh.Marshal on *big.Int produces mpint encoding
  const ecdsaSig = Buffer.concat([sshMpint(r), sshMpint(s)]);

  // Extract origin from clientDataJSON
  let origin = "";
  try {
    const clientData = JSON.parse(clientDataJSON);
    origin = clientData.origin || "";
  } catch {
    // leave empty
  }

  const flagsBuf = Buffer.from([flags]);
  const counterBuf = Buffer.alloc(4);
  counterBuf.writeUInt32BE(counter, 0);

  // The signature data that goes into the SSH packet:
  //   string ecdsaSig     ← Blob (wrapped once as sshString)
  //   byte   flags        ← Rest (raw, NOT wrapped)
  //   uint32 counter
  //   string origin
  //   string clientData
  //   string extensions
  const sigData = Buffer.concat([
    sshString(ecdsaSig),
    flagsBuf,
    counterBuf,
    sshString(origin),
    sshString(clientDataJSON),
    sshString(""),
  ]);

  // Agent response format: string algorithm + string sigData
  // ssh2 agent.js reads: readString() → algorithm (discarded)
  //                      readString() → sigData (returned to Protocol.js)
  return Buffer.concat([sshString(ALGORITHM), sshString(sigData)]);
}
