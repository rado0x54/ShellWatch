// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Package signing is the leaf signing vocabulary (spec §5.8, W2 cycle-break):
// SignRequest/SignResponse types plus WebAuthn-assertion -> SSH PROTOCOL.u2f
// signature conversion. It imports no other ShellWatch package, so both the
// approval layer and sshx depend downward on it. The wire construction is the
// one proven in the Phase 0 spike against real OpenSSH 10.3.
package signing

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
	"golang.org/x/crypto/ssh"
)

// WebAuthnSKAlgo is the OpenSSH signature algorithm for browser passkeys.
const WebAuthnSKAlgo = "webauthn-sk-ecdsa-sha2-nistp256@openssh.com"

// SignRequest is what a signer asks the broker to fulfill (SignRequest in
// ssh-agent.ts). DataToSign is the SSH signing payload.
type SignRequest struct {
	CredentialID     string
	DataToSign       []byte
	RpID             string
	UserVerification string
	PasskeyLabel     string
	ConnectionID     string
}

// SignResponse is the browser's WebAuthn assertion (SignResponse in
// ssh-agent.ts): the three fields the resolve endpoint receives.
type SignResponse struct {
	AuthenticatorData []byte
	Signature         []byte // DER ECDSA
	ClientDataJSON    []byte
}

// AuthDataFlagUV is the User-Verified bit in authenticatorData (byte 32).
const AuthDataFlagUV = 0x04

// IsUserVerified reports whether authenticatorData's UV flag is set.
func IsUserVerified(authData []byte) bool {
	return len(authData) >= 33 && authData[32]&AuthDataFlagUV != 0
}

// BuildSSHSignature converts a WebAuthn assertion into the SSH PROTOCOL.u2f
// signature (buildSshSignatureBlob in signature-format.ts + the spike). The
// origin is read from clientDataJSON; extensions are empty.
func BuildSSHSignature(resp SignResponse) (*ssh.Signature, error) {
	if len(resp.AuthenticatorData) < 37 {
		return nil, fmt.Errorf("authenticatorData too short")
	}
	flags := resp.AuthenticatorData[32]
	counter := binary.BigEndian.Uint32(resp.AuthenticatorData[33:37])

	r, s, err := parseECDSASignature(resp.Signature)
	if err != nil {
		return nil, err
	}

	var cd struct {
		Origin string `json:"origin"`
	}
	_ = json.Unmarshal(resp.ClientDataJSON, &cd)

	blob := append(mpint(r), mpint(s)...)

	rest := []byte{flags}
	rest = binary.BigEndian.AppendUint32(rest, counter)
	rest = appendSSHString(rest, []byte(cd.Origin))
	rest = appendSSHString(rest, resp.ClientDataJSON)
	rest = appendSSHString(rest, nil) // extensions: empty

	return &ssh.Signature{Format: WebAuthnSKAlgo, Blob: blob, Rest: rest}, nil
}

func parseECDSASignature(der []byte) (*big.Int, *big.Int, error) {
	var r, s big.Int
	input := cryptobyte.String(der)
	var inner cryptobyte.String
	if !input.ReadASN1(&inner, cbasn1.SEQUENCE) ||
		!inner.ReadASN1Integer(&r) || !inner.ReadASN1Integer(&s) {
		return nil, nil, fmt.Errorf("invalid ASN.1 ECDSA signature")
	}
	return &r, &s, nil
}

func appendSSHString(dst, s []byte) []byte {
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(s)))
	return append(dst, s...)
}

// mpint encodes a positive big.Int as an SSH mpint (0x00-padded when MSB set).
func mpint(v *big.Int) []byte {
	b := v.Bytes()
	if len(b) > 0 && b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	return appendSSHString(nil, b)
}

var _ = sha256.Sum256
