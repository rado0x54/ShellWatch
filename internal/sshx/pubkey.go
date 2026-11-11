// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// webauthnPublicKey is the client-side ssh.PublicKey for a browser passkey.
// x/crypto/ssh doesn't natively recognize the webauthn-sk-* type (golang/go
// #69999 gap), so ShellWatch supplies it: Type()/Marshal() present the stored
// blob in the userauth offer, and real OpenSSH on the remote validates the
// signature. Verify is never called on the client path.
package sshx

import (
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/rado0x54/shellwatch/internal/signing"
)

type webauthnPublicKey struct {
	blob []byte
}

func (k webauthnPublicKey) Type() string    { return signing.WebAuthnSKAlgo }
func (k webauthnPublicKey) Marshal() []byte { return k.blob }
func (k webauthnPublicKey) Verify([]byte, *ssh.Signature) error {
	return fmt.Errorf("webauthn-sk verification is server-side only")
}

// parseWebauthnPublicKey extracts the raw blob from an OpenSSH authorized_keys
// line ("webauthn-sk-ecdsa-... <base64> [comment]").
func parseWebauthnPublicKey(authorizedKeysLine string) (ssh.PublicKey, error) {
	fields := strings.Fields(authorizedKeysLine)
	if len(fields) < 2 {
		return nil, fmt.Errorf("invalid authorized_keys line")
	}
	blob, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		return nil, err
	}
	return webauthnPublicKey{blob: blob}, nil
}
