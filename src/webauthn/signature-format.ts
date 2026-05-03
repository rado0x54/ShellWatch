// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
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
 * Based on the OpenSSH PROTOCOL.u2f specification.
 */

const _ALGORITHM = "webauthn-sk-ecdsa-sha2-nistp256@openssh.com";

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

/** WebAuthn authenticatorData UV (user verified) flag bit. */
const AUTH_DATA_FLAG_UV = 0x04;

/** True if authenticatorData's UV (user verified) flag is set. */
export function isUserVerified(authenticatorData: Buffer): boolean {
  if (authenticatorData.length < 33) return false;
  return (authenticatorData[32] & AUTH_DATA_FLAG_UV) !== 0;
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
  // ECDSA signature: string(mpint R + mpint S)
  // The ecdsaSig is wrapped as a string because the server reads it via sshbuf_froms
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
  // Protocol.js wraps our return as: string algo + string <our return value>
  // The server then reads ktype from algo, then sshbuf_froms to get our blob as "sigbuf".
  // Inside sigbuf, it does sshbuf_get_bignum2 for R, then S.
  // So our blob must have R and S as raw mpints (NOT wrapped in sshString).
  // After that, the server reads flags, counter, origin, clientData, extensions
  // from the OUTER buffer (after sigbuf is consumed).
  //
  // Wait — actually sshbuf_froms creates a SUB-buffer from our blob. Then:
  //   sigbuf = our entire blob
  //   sshbuf_get_bignum2(sigbuf, R)  ← reads mpint R from start of our blob
  //   sshbuf_get_bignum2(sigbuf, S)  ← reads mpint S
  //   Then flags, counter etc. are read from the OUTER buffer b (not sigbuf)
  //
  // But that means R+S must be a separate sub-buffer, not part of the outer flow.
  // sshbuf_froms reads uint32 len + data and creates a sub-buffer of that data.
  // So the outer buffer after ktype looks like:
  //   uint32 ecdsaSigLen   ← sshbuf_froms reads this
  //   <ecdsaSig bytes>     ← contains mpint R + mpint S
  //   byte flags           ← read from outer buffer AFTER froms
  //   uint32 counter
  //   string origin
  //   string clientData
  //   string extensions
  //
  // This IS what sshString(ecdsaSig) produces! The issue is that Protocol.js
  // ALSO wraps our entire blob in another string. So the server sees:
  //
  //   string ktype
  //   uint32 outerLen       ← Protocol.js wraps our blob
  //     uint32 ecdsaSigLen  ← our sshString(ecdsaSig)
  //     <ecdsaSig>
  //     byte flags
  //     ...
  //
  // The server does sshbuf_froms(b) which reads outerLen + outerData.
  // Then sigbuf = outerData = our ENTIRE blob.
  // Then sshbuf_get_bignum2(sigbuf, R) reads from sigbuf.
  // sigbuf starts with uint32 ecdsaSigLen — but get_bignum2 interprets
  // that as the length of R! So it reads 73 bytes as R, which is wrong.
  //
  // FIX: Don't wrap ecdsaSig in sshString. Put R and S as raw mpints.
  // The server's sshbuf_froms gets our entire blob, then reads R and S directly.
  // Wire format (matches Go's ssh.Signature: string Blob + raw Rest):
  //   string ecdsaSig     ← sshbuf_froms reads this as sub-buffer containing R+S
  //   byte flags           ← sshbuf_get_u8 from outer buf
  //   uint32 counter       ← sshbuf_get_u32 from outer buf
  //   string origin        ← sshbuf_get_cstring from outer buf
  //   string clientData    ← sshbuf_froms from outer buf
  //   string extensions    ← sshbuf_froms from outer buf
  //
  // Protocol.js (fork) writes this raw into the packet (no extra string wrapper)
  return Buffer.concat([
    sshString(ecdsaSig),
    flagsBuf,
    counterBuf,
    sshString(origin),
    sshString(clientDataJSON),
    sshString(""),
  ]);
}
