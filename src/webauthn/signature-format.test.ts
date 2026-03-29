/**
 * Test the SSH signature wire format against known-good structure.
 * Compares our output with the expected OpenSSH wire format.
 */
import { describe, expect, it } from "vitest";
import {
  buildSshSignatureBlob,
  parseAsn1Signature,
  parseWebAuthnSignature,
} from "./signature-format.js";

// Test data: a fake ECDSA signature in ASN.1 DER format
// R = 32 bytes (no leading zero needed), S = 32 bytes with MSB set (needs 0x00 prefix)
const fakeR = Buffer.from(
  "60f4d78b87930861ffa4fab85139651cd01f29c1d3fa601c1e5cec3da99b162c",
  "hex",
);
const fakeSWithMsb = Buffer.from(
  "81b5031af4c13987d520e20481686527fbb875c4caf68b7105c6b4509524f13d",
  "hex",
);

// Build ASN.1 DER: 0x30 <len> 0x02 <r_len> <r> 0x02 <s_len> <s>
function buildDerSignature(r: Buffer, s: Buffer): Buffer {
  // Add leading 0x00 for ASN.1 if MSB set
  const rDer = r[0] & 0x80 ? Buffer.concat([Buffer.from([0x00]), r]) : r;
  const sDer = s[0] & 0x80 ? Buffer.concat([Buffer.from([0x00]), s]) : s;
  const inner = Buffer.concat([
    Buffer.from([0x02, rDer.length]),
    rDer,
    Buffer.from([0x02, sDer.length]),
    sDer,
  ]);
  return Buffer.concat([Buffer.from([0x30, inner.length]), inner]);
}

// Fake authenticator data: 32 bytes rpIdHash + 1 byte flags + 4 bytes counter
function buildAuthData(flags: number, counter: number): Buffer {
  const buf = Buffer.alloc(37);
  // rpIdHash (32 bytes of zeros for test)
  buf[32] = flags;
  buf.writeUInt32BE(counter, 33);
  return buf;
}

function sshString(data: string | Buffer): Buffer {
  const payload = typeof data === "string" ? Buffer.from(data, "utf-8") : data;
  const buf = Buffer.alloc(4 + payload.length);
  buf.writeUInt32BE(payload.length, 0);
  payload.copy(buf, 4);
  return buf;
}

function sshMpint(value: Buffer): Buffer {
  let start = 0;
  while (start < value.length - 1 && value[start] === 0) start++;
  let trimmed = value.subarray(start);
  if (trimmed[0] & 0x80) {
    trimmed = Buffer.concat([Buffer.from([0x00]), trimmed]);
  }
  return sshString(trimmed);
}

describe("parseAsn1Signature", () => {
  it("parses a standard ECDSA DER signature", () => {
    const der = buildDerSignature(fakeR, fakeSWithMsb);
    const { r, s } = parseAsn1Signature(der);

    // R should be returned as-is (no MSB set)
    expect(r.toString("hex")).toBe(fakeR.toString("hex"));

    // S has MSB set, so ASN.1 includes 0x00 prefix — parser should return it with the prefix
    expect(s[0]).toBe(0x00);
    expect(s.subarray(1).toString("hex")).toBe(fakeSWithMsb.toString("hex"));
  });
});

describe("parseWebAuthnSignature", () => {
  it("extracts flags and counter from authenticator data", () => {
    const authData = buildAuthData(0x19, 42);
    const der = buildDerSignature(fakeR, fakeSWithMsb);
    const { r, s, flags, counter } = parseWebAuthnSignature(authData, der);

    expect(flags).toBe(0x19);
    expect(counter).toBe(42);
    expect(r.length).toBe(32);
    expect(s.length).toBe(33); // includes ASN.1 leading 0x00
  });
});

describe("buildSshSignatureBlob", () => {
  it("produces correct wire format structure", () => {
    const clientDataJSON =
      '{"type":"webauthn.get","challenge":"dGVzdA","origin":"http://localhost:3000","crossOrigin":false}';

    const blob = buildSshSignatureBlob(fakeR, fakeSWithMsb, 0x19, 42, clientDataJSON);

    // Parse the blob to verify structure
    let offset = 0;

    function readU32(): number {
      const val = blob.readUInt32BE(offset);
      offset += 4;
      return val;
    }
    function readBytes(len: number): Buffer {
      const data = blob.subarray(offset, offset + len);
      offset += len;
      return data;
    }
    function readString(): Buffer {
      const len = readU32();
      return readBytes(len);
    }

    // 1. string ecdsa_sig
    const ecdsaSig = readString();

    // Inside ecdsa_sig: mpint R + mpint S
    let innerOffset = 0;
    const rLen = ecdsaSig.readUInt32BE(innerOffset);
    innerOffset += 4;
    const rBytes = ecdsaSig.subarray(innerOffset, innerOffset + rLen);
    innerOffset += rLen;
    const sLen = ecdsaSig.readUInt32BE(innerOffset);
    innerOffset += 4;
    const sBytes = ecdsaSig.subarray(innerOffset, innerOffset + sLen);

    expect(rBytes.toString("hex")).toBe(fakeR.toString("hex"));
    // S should have leading 0x00 (MSB set in original)
    expect(sBytes[0]).toBe(0x00);
    expect(sBytes.subarray(1).toString("hex")).toBe(fakeSWithMsb.toString("hex"));

    // 2. byte flags
    expect(blob[offset]).toBe(0x19);
    offset += 1;

    // 3. uint32 counter
    expect(readU32()).toBe(42);

    // 4. string origin
    const origin = readString();
    expect(origin.toString()).toBe("http://localhost:3000");

    // 5. string clientData
    const clientData = readString();
    expect(clientData.toString()).toBe(clientDataJSON);

    // 6. string extensions
    const extensions = readString();
    expect(extensions.length).toBe(0);

    // No remaining bytes
    expect(offset).toBe(blob.length);
  });

  it("matches Go's ssh.Signature wire format (Blob + Rest)", () => {
    // In Go's ssh.Signature: Blob = ssh.Marshal(ECDSASignature{R,S}), Rest = ssh.Marshal(extra{...})
    // Wire format: string algo + string Blob + <Rest raw>
    // But since BaseAgent returns directly to Protocol.js (no algorithm prefix needed),
    // our blob should be: string(mpint(R)+mpint(S)) + byte flags + uint32 counter + string origin + string clientData + string extensions

    const clientDataJSON =
      '{"type":"webauthn.get","challenge":"test","origin":"http://localhost:3000"}';

    const blob = buildSshSignatureBlob(fakeR, fakeSWithMsb, 0x01, 0, clientDataJSON);

    // Manually construct what Go would produce
    const expectedEcdsaSig = Buffer.concat([sshMpint(fakeR), sshMpint(fakeSWithMsb)]);
    const expectedBlob = Buffer.concat([
      sshString(expectedEcdsaSig),
      Buffer.from([0x01]),
      Buffer.alloc(4), // counter = 0
      sshString("http://localhost:3000"),
      sshString(clientDataJSON),
      sshString(""),
    ]);

    expect(blob.toString("hex")).toBe(expectedBlob.toString("hex"));
  });
});
