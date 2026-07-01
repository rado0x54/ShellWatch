// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * In-memory fake WebAuthn authenticator for ceremony-level integration tests
 * (#162). Holds a P-256 (ES256 / alg -7) keypair — matching every ShellWatch
 * `/options` endpoint's `supportedAlgorithmIDs: [-7]` — and produces real,
 * cryptographically-valid registration and authentication responses in the
 * `@simplewebauthn/server` JSON shapes, ready to drop into a verify endpoint's
 * `credential` body.
 *
 * This closes the gap where the most security-critical path — *successful*
 * `verifyRegistrationResponse` / `verifyAuthenticationResponse` — was covered
 * only by the library's own tests. It also enables negative tests (counter
 * rollback, UV-not-set, origin/rp mismatch) that need a signer we control.
 *
 * CBOR is encoded with the library's own `isoCBOR` (tiny-cbor) so the bytes
 * decode identically in the verifier; COSE keys and the attestation object are
 * built as JS `Map`s as tiny-cbor requires.
 */
import { createHash, generateKeyPairSync, type KeyObject, sign } from "node:crypto";
import { isoCBOR } from "@simplewebauthn/server/helpers";
import type { AuthenticationResponseJSON, RegistrationResponseJSON } from "@simplewebauthn/server";

const b64url = (b: Uint8Array): string => Buffer.from(b).toString("base64url");
const sha256 = (b: Uint8Array): Uint8Array =>
  new Uint8Array(createHash("sha256").update(b).digest());

/** Left-pad a big-endian coordinate to exactly 32 bytes (P-256). */
function pad32(b: Buffer): Uint8Array {
  if (b.length === 32) return new Uint8Array(b);
  const out = new Uint8Array(32);
  out.set(b, 32 - b.length);
  return out;
}

/** Authenticator flag bits (WebAuthn §6.1). */
const FLAG_UP = 0x01; // user present
const FLAG_UV = 0x04; // user verified
const FLAG_AT = 0x40; // attested credential data included

function u16be(n: number): Uint8Array {
  return new Uint8Array([(n >> 8) & 0xff, n & 0xff]);
}
function u32be(n: number): Uint8Array {
  return new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
}
function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

export interface FakeAuthenticatorOptions {
  /** Relying-party id the credential is bound to. Default "localhost" (test rpId). */
  rpId?: string;
  /** Origin placed in clientDataJSON. Default "http://localhost" (test origin). */
  origin?: string;
  /** 16-byte AAGUID. Default all-zero (self-attestation-ish, "none" fmt). */
  aaguid?: Uint8Array;
}

export interface CeremonyOverrides {
  /** Override the rpId hashed into authData (for rp-mismatch negatives). */
  rpId?: string;
  /** Override the origin in clientDataJSON (for origin-mismatch negatives). */
  origin?: string;
  /** Set the User Verified flag. Default true. */
  uv?: boolean;
  /** Set the User Present flag. Default true. */
  up?: boolean;
  /** Force a specific signCount instead of the internal counter (for rollback negatives). */
  signCount?: number;
}

export interface FakeAuthenticator {
  /** base64url credential id — matches what the verifier stores as `credential.id`. */
  readonly credentialId: string;
  /** Current internal signature counter (increments on each authenticate()). */
  readonly signCount: number;
  /** Build a RegistrationResponseJSON for a registration `challenge` (base64url). */
  register(challenge: string, overrides?: CeremonyOverrides): RegistrationResponseJSON;
  /** Build an AuthenticationResponseJSON for an assertion `challenge` (base64url). */
  authenticate(challenge: string, overrides?: CeremonyOverrides): AuthenticationResponseJSON;
}

/**
 * Create a fake authenticator with a fresh P-256 keypair and a random 32-byte
 * credential id. `register()` and `authenticate()` produce responses a real
 * ShellWatch verify endpoint accepts (given a matching challenge/rpId/origin).
 */
export function createFakeAuthenticator(options: FakeAuthenticatorOptions = {}): FakeAuthenticator {
  const rpId = options.rpId ?? "localhost";
  const origin = options.origin ?? "http://localhost";
  const aaguid = options.aaguid ?? new Uint8Array(16);
  const credentialIdBytes = new Uint8Array(32);
  crypto.getRandomValues(credentialIdBytes);

  const { publicKey, privateKey }: { publicKey: KeyObject; privateKey: KeyObject } =
    generateKeyPairSync("ec", { namedCurve: "P-256" });

  // COSE_Key for ES256 (EC2 / P-256), built from the JWK coordinates.
  const jwk = publicKey.export({ format: "jwk" }) as { x: string; y: string };
  const x = pad32(Buffer.from(jwk.x, "base64url"));
  const y = pad32(Buffer.from(jwk.y, "base64url"));
  const coseKey = new Map<number, number | Uint8Array>([
    [1, 2], // kty: EC2
    [3, -7], // alg: ES256
    [-1, 1], // crv: P-256
    [-2, x], // x-coordinate
    [-3, y], // y-coordinate
  ]);
  const cosePublicKey = new Uint8Array(isoCBOR.encode(coseKey));

  let counter = 0;

  function clientDataJSON(
    type: "webauthn.create" | "webauthn.get",
    challenge: string,
    orig: string,
  ) {
    return new Uint8Array(
      Buffer.from(JSON.stringify({ type, challenge, origin: orig, crossOrigin: false }), "utf8"),
    );
  }

  function flags(up: boolean, uv: boolean, at: boolean): number {
    return (up ? FLAG_UP : 0) | (uv ? FLAG_UV : 0) | (at ? FLAG_AT : 0);
  }

  return {
    get credentialId() {
      return b64url(credentialIdBytes);
    },
    get signCount() {
      return counter;
    },

    register(challenge, overrides = {}): RegistrationResponseJSON {
      const rp = overrides.rpId ?? rpId;
      const orig = overrides.origin ?? origin;
      const signCount = overrides.signCount ?? 0;
      const rpIdHash = sha256(new Uint8Array(Buffer.from(rp, "utf8")));

      const attestedCredentialData = concat(
        aaguid,
        u16be(credentialIdBytes.length),
        credentialIdBytes,
        cosePublicKey,
      );
      const authData = concat(
        rpIdHash,
        new Uint8Array([flags(overrides.up ?? true, overrides.uv ?? true, true)]),
        u32be(signCount),
        attestedCredentialData,
      );
      const attestationObject = new Uint8Array(
        isoCBOR.encode(
          new Map<string, string | Uint8Array | Map<never, never>>([
            ["fmt", "none"],
            ["attStmt", new Map<never, never>()], // empty attStmt for "none" attestation
            ["authData", authData],
          ]),
        ),
      );

      const cdj = clientDataJSON("webauthn.create", challenge, orig);
      return {
        id: b64url(credentialIdBytes),
        rawId: b64url(credentialIdBytes),
        response: {
          clientDataJSON: b64url(cdj),
          attestationObject: b64url(attestationObject),
          transports: ["internal"],
        },
        clientExtensionResults: {},
        type: "public-key",
        authenticatorAttachment: "platform",
      };
    },

    authenticate(challenge, overrides = {}): AuthenticationResponseJSON {
      const rp = overrides.rpId ?? rpId;
      const orig = overrides.origin ?? origin;
      const signCount = overrides.signCount ?? ++counter;
      const rpIdHash = sha256(new Uint8Array(Buffer.from(rp, "utf8")));

      const authData = concat(
        rpIdHash,
        new Uint8Array([flags(overrides.up ?? true, overrides.uv ?? true, false)]),
        u32be(signCount),
      );
      const cdj = clientDataJSON("webauthn.get", challenge, orig);
      // ES256 assertion: DER-encoded ECDSA signature over authData || SHA256(clientDataJSON).
      const signature = sign("sha256", concat(authData, sha256(cdj)), privateKey);

      return {
        id: b64url(credentialIdBytes),
        rawId: b64url(credentialIdBytes),
        response: {
          clientDataJSON: b64url(cdj),
          authenticatorData: b64url(authData),
          signature: b64url(new Uint8Array(signature)),
        },
        clientExtensionResults: {},
        type: "public-key",
        authenticatorAttachment: "platform",
      };
    },
  };
}
