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

## What the Go spike must prove here

1. **Custom `ssh.Signer`** producing a `webauthn-sk-ecdsa-sha2-nistp256@openssh.com`
   signature (`ssh.Signature.Rest` = `flags ‖ counter ‖ origin ‖ clientDataJSON ‖ extensions`
   per PROTOCOL.u2f), with the WebAuthn assertion minted from
   `webauthn-sk.pem` by a fake authenticator (port of #162/#228).
2. **Cert composition**: `ssh.NewCertSigner(cert, webauthnSigner)`
   authenticating as `spike` against this sshd.
3. (Elsewhere: MCP go-sdk serving one tool to the unchanged SvelteKit
   client — needs no material from this directory.)

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
