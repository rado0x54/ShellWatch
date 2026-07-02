// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// COSE -> OpenSSH conversion (port of src/webauthn/ssh-key-format.ts): derive
// the `webauthn-sk-ecdsa-sha2-nistp256@openssh.com` authorized_keys line from
// a credential's COSE public key. Pinned by the webauthn-register golden's
// authorizedKeysEntry.
package webauthn

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"

	"github.com/go-webauthn/webauthn/protocol/webauthncose"
)

const (
	sshAlgorithm = "webauthn-sk-ecdsa-sha2-nistp256@openssh.com"
	sshSKKeyType = "sk-ecdsa-sha2-nistp256@openssh.com"
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

// FingerprintFromAuthorizedKeys computes the OpenSSH SHA256 fingerprint
// (SHA256:<base64-no-pad>) of an authorized_keys line, matching
// `ssh-keygen -lf` — the fingerprint OpenSSH shows for the sk key type (the
// `webauthn-` prefix is a signature algorithm, not a key type). Port of
// fingerprint.ts fingerprintFromAuthorizedKeys. Returns "" for an empty line.
func FingerprintFromAuthorizedKeys(authorizedKeysEntry string) string {
	if authorizedKeysEntry == "" {
		return ""
	}
	blob := publicKeyBlobFromLine(authorizedKeysEntry)
	if blob == nil {
		return ""
	}
	sk := toSkPublicKeyBlob(blob)
	sum := sha256.Sum256(sk)
	b64 := base64.StdEncoding.EncodeToString(sum[:])
	return "SHA256:" + trimEqual(b64)
}

// publicKeyBlobFromLine decodes the base64 blob from "algo <base64> [comment]".
func publicKeyBlobFromLine(line string) []byte {
	var b64 string
	for i := 0; i < len(line); i++ {
		if line[i] == ' ' {
			rest := line[i+1:]
			end := len(rest)
			for j := 0; j < len(rest); j++ {
				if rest[j] == ' ' {
					end = j
					break
				}
			}
			b64 = rest[:end]
			break
		}
	}
	if b64 == "" {
		return nil
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil
	}
	return raw
}

// toSkPublicKeyBlob swaps the leading `string type` from webauthn-sk-... to
// sk-... (toSkPublicKeyBlob in ssh-key-format.ts), so hashing yields the
// fingerprint OpenSSH displays.
func toSkPublicKeyBlob(webauthnBlob []byte) []byte {
	if len(webauthnBlob) < 4 {
		return webauthnBlob
	}
	typeLen := binary.BigEndian.Uint32(webauthnBlob[:4])
	rest := webauthnBlob[4+typeLen:]
	return append(sshString([]byte(sshSKKeyType)), rest...)
}

func trimEqual(s string) string {
	for len(s) > 0 && s[len(s)-1] == '=' {
		s = s[:len(s)-1]
	}
	return s
}
