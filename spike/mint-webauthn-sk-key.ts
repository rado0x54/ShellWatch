// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * Mint a P-256 keypair and emit its OpenSSH `webauthn-sk-*` public key for
 * the Go rewrite Phase 0 spike (#232 item 4). Models a WebAuthn credential
 * the way ShellWatch derives one (see src/webauthn/ssh-key-format.ts):
 *
 *   string  "webauthn-sk-ecdsa-sha2-nistp256@openssh.com"
 *   string  "nistp256"
 *   string  uncompressed EC point (0x04 || X || Y)
 *   string  application (the WebAuthn rpId)
 *
 * The private key stands in for the passkey: the spike's fake authenticator
 * signs WebAuthn assertions with it (same P-256 crypto as a real passkey,
 * see src/test/helpers fake authenticator from #162/#228).
 *
 * Usage: pnpm exec tsx spike/mint-webauthn-sk-key.ts <output-basename>
 *   SPIKE_RP_ID overrides the application string (default: localhost)
 */
import { generateKeyPairSync } from "node:crypto";
import { writeFileSync } from "node:fs";

const out = process.argv[2];
if (!out) {
  console.error("usage: tsx spike/mint-webauthn-sk-key.ts <output-basename>");
  process.exit(1);
}

const RP_ID = process.env.SPIKE_RP_ID ?? "localhost";
const KEY_TYPE = "webauthn-sk-ecdsa-sha2-nistp256@openssh.com";

const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const x = Buffer.from(jwk.x!, "base64url");
const y = Buffer.from(jwk.y!, "base64url");
const ecPoint = Buffer.concat([Buffer.from([0x04]), x, y]);

function sshString(value: Buffer | string): Buffer {
  const buf = typeof value === "string" ? Buffer.from(value) : value;
  const len = Buffer.alloc(4);
  len.writeUInt32BE(buf.length, 0);
  return Buffer.concat([len, buf]);
}

const blob = Buffer.concat([
  sshString(KEY_TYPE),
  sshString("nistp256"),
  sshString(ecPoint),
  sshString(RP_ID),
]);

writeFileSync(`${out}.pub`, `${KEY_TYPE} ${blob.toString("base64")} shellwatch-spike\n`);
writeFileSync(`${out}.pem`, privateKey.export({ type: "pkcs8", format: "pem" }).toString());
writeFileSync(
  `${out}.meta.json`,
  JSON.stringify(
    {
      keyType: KEY_TYPE,
      curve: "nistp256",
      application: RP_ID,
      privateKey: `${out}.pem (PKCS#8; signs WebAuthn assertions in the spike's fake authenticator)`,
    },
    null,
    2,
  ) + "\n",
);
console.log(`wrote ${out}.pub ${out}.pem ${out}.meta.json (application=${RP_ID})`);
