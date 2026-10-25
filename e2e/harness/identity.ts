// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * Identities for the e2e suite (#244) — built on the fake WebAuthn
 * authenticator (e2e/lib/fake-authenticator.ts, #162), which produces real
 * P-256 assertions. Everything derived from it here (COSE key,
 * OpenSSH `webauthn-sk-*` line) is re-implemented from the public wire formats
 * so the suite stays independent of the server's `internal/webauthn` — and so
 * a mismatch with what the server derives shows up as a test failure, not a
 * shared bug.
 */
import { execFileSync } from "node:child_process";
import { createPublicKey, generateKeyPairSync, type KeyObject } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  createFakeAuthenticator,
  type CeremonyOverrides,
  type FakeAuthenticator,
} from "../lib/fake-authenticator.js";
import { RP_ID, WEBAUTHN_ORIGIN } from "./env.js";
import { b64ToB64url } from "./util.js";

export const WEBAUTHN_SSH_ALGORITHM = "webauthn-sk-ecdsa-sha2-nistp256@openssh.com";
export const SK_KEY_TYPE = "sk-ecdsa-sha2-nistp256@openssh.com";

export interface PasskeyIdentity {
  label: string;
  fake: FakeAuthenticator;
  /** base64url credential id — the `credentialId` the server stores. */
  credentialId: string;
  /** COSE_Key (EC2/P-256/ES256) as hex — the `publicKeyHex` for seedAdminPasskeys. */
  cosePublicKeyHex: string;
  /** OpenSSH authorized_keys line for the credential (application = rpId). */
  openSshLine: string;
  /**
   * The same key as OpenSSH itself prints it (`ssh-add -L`, `ssh-keygen -lf`):
   * type `sk-ecdsa-sha2-nistp256@openssh.com`, identical blob body. OpenSSH
   * canonicalizes the key type — `webauthn-` is a signature algorithm, not a
   * key type (see docs/api/agent-proxy-protocol.md).
   */
  skOpenSshLine: string;
}

function p256Coordinates(publicKey: KeyObject): { x: Buffer; y: Buffer } {
  const jwk = publicKey.export({ format: "jwk" }) as { x: string; y: string };
  const pad = (b: Buffer) =>
    b.length === 32 ? b : Buffer.concat([Buffer.alloc(32 - b.length), b]);
  return { x: pad(Buffer.from(jwk.x, "base64url")), y: pad(Buffer.from(jwk.y, "base64url")) };
}

/**
 * Canonical CBOR for a COSE EC2 P-256 key:
 *   { 1: 2 (kty EC2), 3: -7 (alg ES256), -1: 1 (crv P-256), -2: x, -3: y }
 * Hand-encoded: a5 01 02 03 26 20 01 21 58 20 <x> 22 58 20 <y>.
 */
export function coseP256(x: Buffer, y: Buffer): Buffer {
  return Buffer.concat([
    Buffer.from([0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]),
    x,
    Buffer.from([0x22, 0x58, 0x20]),
    y,
  ]);
}

function sshString(data: string | Buffer): Buffer {
  const payload = typeof data === "string" ? Buffer.from(data, "utf8") : data;
  const len = Buffer.alloc(4);
  len.writeUInt32BE(payload.length, 0);
  return Buffer.concat([len, payload]);
}

/** OpenSSH PROTOCOL.u2f public key: string type, string "nistp256", string point, string application. */
export function skOpenSshLine(keyType: string, x: Buffer, y: Buffer, application: string): string {
  const blob = Buffer.concat([
    sshString(keyType),
    sshString("nistp256"),
    sshString(Buffer.concat([Buffer.from([0x04]), x, y])),
    sshString(application),
  ]);
  return `${keyType} ${blob.toString("base64")}`;
}

/** Fresh P-256 passkey bound to the e2e rpId/origin. */
export function createPasskeyIdentity(label = "E2E Passkey"): PasskeyIdentity {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const fake = createFakeAuthenticator({ rpId: RP_ID, origin: WEBAUTHN_ORIGIN, privateKeyPem });
  const { x, y } = p256Coordinates(createPublicKey(privateKey));
  return {
    label,
    fake,
    credentialId: fake.credentialId,
    cosePublicKeyHex: coseP256(x, y).toString("hex"),
    openSshLine: skOpenSshLine(WEBAUTHN_SSH_ALGORITHM, x, y, RP_ID),
    skOpenSshLine: skOpenSshLine(SK_KEY_TYPE, x, y, RP_ID),
  };
}

/** Body for `POST /api/actions/:id/resolve` on a webauthn-sign action. */
export interface SshSignPayload {
  authenticatorData: string;
  signature: string;
  clientDataJSON: string;
}

/**
 * Sign an SSH `webauthn-sign` challenge the way the browser does on /sign/:id:
 * the action's `challenge` is standard base64 of the SSH data-to-sign; the
 * authenticator receives those raw bytes and base64url-encodes them into
 * clientDataJSON ("challenge" right after "type", then "origin" — the exact
 * prefix OpenSSH's webauthn verifier reconstructs). Origin is `https://<rpId>`,
 * what a browser serving the UI over TLS on the rpId host would produce.
 */
export function signSshChallenge(
  identity: PasskeyIdentity,
  challengeB64: string,
  overrides: CeremonyOverrides = {},
): SshSignPayload {
  const assertion = identity.fake.authenticate(b64ToB64url(challengeB64), {
    origin: `https://${RP_ID}`,
    ...overrides,
  });
  return {
    authenticatorData: assertion.response.authenticatorData,
    signature: assertion.response.signature,
    clientDataJSON: Buffer.from(assertion.response.clientDataJSON, "base64url").toString("utf8"),
  };
}

export interface FileKeyIdentity {
  /** Path of the private key inside the server's keyDirectory (`*.pem`, as the scanner expects). */
  privateKeyPath: string;
  /** `ssh-ed25519 AAAA… comment` — the authorized_keys line. */
  publicKeyLine: string;
  /** `SHA256:…` fingerprint as `ssh-keygen -lf` prints it. */
  fingerprint: string;
}

/** `ssh-keygen -t ed25519` into the key directory (the server scans `*.pem`). */
export function generateFileKey(keyDirectory: string, name = "e2e-filekey"): FileKeyIdentity {
  const privateKeyPath = join(keyDirectory, `${name}.pem`);
  execFileSync("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-C", name, "-f", privateKeyPath]);
  const publicKeyLine = readFileSync(`${privateKeyPath}.pub`, "utf8").trim();
  const fingerprint = execFileSync("ssh-keygen", ["-lf", `${privateKeyPath}.pub`], {
    encoding: "utf8",
  }).split(/\s+/)[1]!;
  return { privateKeyPath, publicKeyLine, fingerprint };
}
