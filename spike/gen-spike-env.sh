#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
# Generate the Phase 0 spike key material (#232 item 4):
#   out/ca/user_ca(.pub)            throwaway user CA
#   out/keys/control(-cert.pub)     plain ed25519 identity + cert (control case)
#   out/keys/webauthn-sk.*          webauthn-sk P-256 identity (pub/pem/meta)
#   out/keys/webauthn-sk-cert.pub   webauthn-sk-ecdsa-...-cert-v01 user cert
# Idempotent: existing keys are kept, certs are re-minted (7-day validity).
# Requires OpenSSH >= 9.x on the host for the webauthn-sk cert signing (this
# repo targets 10.3+ anyway); run `ssh -V` to check.
set -euo pipefail
cd "$(dirname "$0")"

mkdir -p out/ca out/keys

[ -f out/ca/user_ca ] || ssh-keygen -q -t ed25519 -f out/ca/user_ca -N "" -C "shellwatch-spike-user-ca"

# Control identity: proves CA/sshd plumbing independent of webauthn-sk.
[ -f out/keys/control ] || ssh-keygen -q -t ed25519 -f out/keys/control -N "" -C "spike-control"
ssh-keygen -q -s out/ca/user_ca -I spike-control -n spike -V +7d out/keys/control.pub

# webauthn-sk identity: the composition under test (#210 Phase 0) is
# ssh.NewCertSigner(cert, webauthnSigner) presenting this cert.
[ -f out/keys/webauthn-sk.pub ] || (cd .. && pnpm exec tsx spike/mint-webauthn-sk-key.ts spike/out/keys/webauthn-sk)
ssh-keygen -q -s out/ca/user_ca -I spike-webauthn -n spike -V +7d out/keys/webauthn-sk.pub

echo "--- webauthn-sk certificate ---"
ssh-keygen -L -f out/keys/webauthn-sk-cert.pub
echo
echo "Next: docker compose up -d --build   (sshd on 127.0.0.1:2222, user 'spike')"
echo "Control check: ssh -p 2222 -o IdentitiesOnly=yes -i out/keys/control -o CertificateFile=out/keys/control-cert.pub -o StrictHostKeyChecking=no spike@127.0.0.1 true"
