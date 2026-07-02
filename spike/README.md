<!-- SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0 -->

# Phase 0 spike environment — Go rewrite

Reproducible target for the de-risk spike of the Go backend rewrite
([#210], [#232] item 4; plan in
[`docs/go-backend-architecture.md`](../docs/go-backend-architecture.md) §9):
an OpenSSH server with `TrustedUserCAKeys`, a throwaway user CA, and a
`webauthn-sk` identity + user certificate to drive
`ssh.NewCertSigner(cert, webauthnSigner)` against.

Everything under `out/` is generated, throwaway, and git-ignored.

## Usage

```bash
./gen-spike-env.sh              # CA + control identity + webauthn-sk identity + certs
docker compose up -d --build    # sshd on 127.0.0.1:2222, user "spike", cert-only auth

# Control case (plain ed25519 cert) — proves the CA/sshd plumbing:
ssh -p 2222 -o IdentitiesOnly=yes \
    -i out/keys/control -o CertificateFile=out/keys/control-cert.pub \
    -o StrictHostKeyChecking=no spike@127.0.0.1 true

docker compose logs sshd        # LogLevel VERBOSE shows which cert/key each auth used
```

Requirements: Docker, OpenSSH ≥ 9.x on the host for `ssh-keygen` cert
signing of the sk key (the project targets 10.3+ anyway), Node/pnpm (the
key-mint script runs via `tsx`).

## Generated material

| File                             | What                                                                                                                                    |
| -------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| `out/ca/user_ca(.pub)`           | throwaway user CA (ed25519); pub is mounted into sshd as `TrustedUserCAKeys`                                                            |
| `out/keys/control(-cert.pub)`    | plain ed25519 identity + cert — the control case                                                                                        |
| `out/keys/webauthn-sk.pub`       | OpenSSH `webauthn-sk-ecdsa-sha2-nistp256@openssh.com` public key (application = rpId, default `localhost`; override with `SPIKE_RP_ID`) |
| `out/keys/webauthn-sk.pem`       | P-256 private key (PKCS#8) standing in for the passkey — the spike's fake authenticator signs WebAuthn assertions with it               |
| `out/keys/webauthn-sk.meta.json` | key type / curve / application record                                                                                                   |
| `out/keys/webauthn-sk-cert.pub`  | user certificate over the sk key, 7-day validity, principal `spike`                                                                     |

## The Go spike (`go/`) — all three Phase 0 goals PROVEN (2026-07)

```bash
cd go && go test -v ./...   # needs the sshd up and gen-spike-env.sh run
```

1. **Custom `ssh.Signer`** (`go/webauthn.go`) producing a
   `webauthn-sk-ecdsa-sha2-nistp256@openssh.com` signature
   (`ssh.Signature.Blob` = mpint R ‖ mpint S; `.Rest` =
   `flags ‖ counter ‖ origin ‖ clientDataJSON ‖ extensions` per
   PROTOCOL.u2f), assertion minted from `webauthn-sk.pem` by a fake
   authenticator (Go port of the #162/#228 construction). ✅
2. **Cert composition**: `ssh.NewCertSigner(cert, webauthnSigner)`
   authenticates as `spike` against this sshd — log evidence:
   `Accepted publickey … ECDSA-SK-CERT … ID spike-webauthn … CA ED25519`.
   No custom `ssh.PublicKey` type was needed: the signer's public key is
   simply `cert.Key` (the natively-parsed sk-ecdsa key), and only the
   returned `ssh.Signature` uses the webauthn format. Unmodified
   `x/crypto/ssh` — **the ssh2 fork's job is reproducible without a
   fork**. ✅
3. **MCP go-sdk** (v1.6.1) serving one tool over streamable HTTP,
   round-tripped with the SDK client (`go/mcp_test.go`). ✅

## Findings from the Go spike (2026-07)

- **`clientDataJSON` key order is load-bearing.** sshd's webauthn check
  does not parse the JSON — it **byte-compares the prefix** against the
  literal `{"type":"webauthn.get","challenge":"<b64url>","origin":"<origin>"`
  (openssh `ssh-ecdsa-sk.c`). Go's `json.Marshal(map)` sorts keys
  alphabetically and can never match; the JSON must be assembled literally
  in browser order. This was the only failure in the first live run
  (`… unverified: invalid format` at DEBUG3).
- **Challenge encoding is base64url-no-pad** (browser convention) — sshd
  converts its expected standard-b64 to b64url before comparing; the
  standard-b64 fallback probe was never needed.
- **The sk-cert + webauthn-signature pairing is accepted**: pkalg
  `sk-ecdsa-…-cert-v01@openssh.com` on the wire carrying a signature whose
  inner type is `webauthn-sk-ecdsa-…` — the exact pairing the
  canonicalization finding below predicted.
- The `origin` must appear identically in the signature's origin field and
  in `clientDataJSON`; `https://<application>` works (hostname matches the
  key's application/rpId).

## Finding already captured (2026-07)

`ssh-keygen -s` (OpenSSH 10.3) **canonicalizes the certificate key type to
`sk-ecdsa-sha2-nistp256-cert-v01@openssh.com`** — the `webauthn-` prefix is
a _signature algorithm_, not a key type, so it does not survive into the
cert blob (same canonicalization the agent protocol shows, see
[`docs/api/agent-proxy-protocol.md`](../docs/api/agent-proxy-protocol.md)).
The application field (rpId) is preserved inside the embedded sk key.
Consequence for the spike: the Go signer wraps the cert as
`sk-ecdsa-…-cert-v01` on the wire while the _signature_ it returns uses the
webauthn algorithm — validate that sshd accepts exactly this pairing; that
is the crux of #210's Phase 0.

[#210]: https://github.com/rado0x54/ShellWatch/issues/210
[#232]: https://github.com/rado0x54/ShellWatch/issues/232
