// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Registration + authentication verification (port of
// src/webauthn/credential-store.ts verifyAndDecodeRegistration and the
// assertion verification in stepup.ts), wrapping go-webauthn's protocol
// package. UV is always required, matching the Node backend.
package webauthn

import (
	"encoding/base64"
	"fmt"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
)

// es256Params pins the accepted algorithm to ES256/P-256 (the [-7] the
// options endpoints advertise; OpenSSH sk-* keys don't support Ed25519).
var es256Params = []protocol.CredentialParameter{
	{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgES256},
}

// DecodedRegistration is the DB-ready credential shape (DecodedRegistration
// in credential-store.ts).
type DecodedRegistration struct {
	CredentialID        string // base64url of the raw credential id
	PublicKeyCOSE       []byte
	Counter             uint32
	Transports          []string
	BaseLabel           string
	AuthorizedKeysEntry string // "" when COSE->OpenSSH derivation fails
}

// VerifyRegistration parses and verifies a registration response body
// (@simplewebauthn JSON shape) and decodes it. rawBody is the `credential`
// object bytes.
func VerifyRegistration(rawCredential []byte, challenge, rpID string, origins []string) (*DecodedRegistration, error) {
	pcc, err := protocol.ParseCredentialCreationResponseBytes(rawCredential)
	if err != nil {
		return nil, fmt.Errorf("parse registration response: %w", err)
	}
	// verifyUser=true (UV required), verifyUserPresence=true.
	if _, err := pcc.Verify(challenge, rpID, origins, nil,
		protocol.TopOriginDefaultVerificationMode, false, true, true, nil, es256Params); err != nil {
		return nil, fmt.Errorf("verification failed: %w", err)
	}

	att := pcc.Response.AttestationObject.AuthData.AttData
	coseKey := att.CredentialPublicKey

	authorized, _ := CoseToAuthorizedKeys(coseKey, rpID) // "" on failure (defensive)
	transports := make([]string, 0, len(pcc.Response.Transports))
	for _, t := range pcc.Response.Transports {
		transports = append(transports, string(t))
	}

	return &DecodedRegistration{
		CredentialID:        base64.RawURLEncoding.EncodeToString(att.CredentialID),
		PublicKeyCOSE:       coseKey,
		Counter:             pcc.Response.AttestationObject.AuthData.Counter,
		Transports:          transports,
		BaseLabel:           lookupAAGUID(att.AAGUID),
		AuthorizedKeysEntry: authorized,
	}, nil
}

// AssertionResult is the outcome of a verified authentication assertion.
type AssertionResult struct {
	CredentialID string // base64url of the asserted credential id
	NewCounter   uint32
}

// VerifyAssertion verifies an authentication response against a stored
// credential's COSE public key (stepup.ts verifyAuthenticationResponse). UV
// required; returns the bumped counter.
func VerifyAssertion(rawCredential []byte, challenge, rpID string, origins []string, storedCOSE []byte, storedCounter uint32) (*AssertionResult, error) {
	pca, err := protocol.ParseCredentialRequestResponseBytes(rawCredential)
	if err != nil {
		return nil, fmt.Errorf("parse assertion: %w", err)
	}
	if err := pca.Verify(challenge, rpID, "", origins, nil,
		protocol.TopOriginDefaultVerificationMode, false, true, true, storedCOSE); err != nil {
		return nil, fmt.Errorf("verification failed: %w", err)
	}
	_ = storedCounter // counter regression is enforced inside Verify
	return &AssertionResult{
		CredentialID: base64.RawURLEncoding.EncodeToString(pca.RawID),
		NewCounter:   pca.Response.AuthenticatorData.Counter,
	}, nil
}
