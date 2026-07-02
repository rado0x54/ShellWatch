// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// COSE -> OpenSSH conversion (port of src/webauthn/ssh-key-format.ts): derive
// the `webauthn-sk-ecdsa-sha2-nistp256@openssh.com` authorized_keys line from
// a credential's COSE public key. Pinned by the webauthn-register golden's
// authorizedKeysEntry.
package webauthn

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"

	"github.com/go-webauthn/webauthn/protocol/webauthncose"
)

const (
	sshAlgorithm = "webauthn-sk-ecdsa-sha2-nistp256@openssh.com"
	sshCurve     = "nistp256"
)

// SshdConfigLine is the sshd_config directive that accepts this key type
// (getSshdConfigLine()).
func SshdConfigLine() string {
	return "PubkeyAcceptedAlgorithms=+" + sshAlgorithm
}

func sshString(b []byte) []byte {
	out := make([]byte, 4+len(b))
	binary.BigEndian.PutUint32(out, uint32(len(b)))
	copy(out[4:], b)
	return out
}

// pad32 left-pads a coordinate to 32 bytes (P-256), matching the fake
// authenticator + @simplewebauthn behavior.
func pad32(b []byte) []byte {
	if len(b) >= 32 {
		return b[len(b)-32:]
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

// CoseToAuthorizedKeys converts a COSE EC2/P-256 public key to the full
// OpenSSH authorized_keys line. Returns "" if the key isn't a P-256 EC2 key
// (defensive fallback; options pin supportedAlgorithmIDs to [-7]).
func CoseToAuthorizedKeys(coseKey []byte, rpID string) (string, error) {
	parsed, err := webauthncose.ParsePublicKey(coseKey)
	if err != nil {
		return "", err
	}
	ec2, ok := parsed.(webauthncose.EC2PublicKeyData)
	if !ok {
		return "", fmt.Errorf("credential public key is not EC2/P-256")
	}

	// Uncompressed EC point: 0x04 || X || Y.
	ecPoint := append([]byte{0x04}, append(pad32(ec2.XCoord), pad32(ec2.YCoord)...)...)

	// SSH wire format: type || curve || point || application(rpId).
	blob := make([]byte, 0, 96)
	blob = append(blob, sshString([]byte(sshAlgorithm))...)
	blob = append(blob, sshString([]byte(sshCurve))...)
	blob = append(blob, sshString(ecPoint)...)
	blob = append(blob, sshString([]byte(rpID))...)

	return sshAlgorithm + " " + base64.StdEncoding.EncodeToString(blob), nil
}
