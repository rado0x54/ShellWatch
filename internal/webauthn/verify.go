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

// Verification policies passed to protocol.Verify. These mirror the defaults
// go-webauthn's Config.validate applies (its most restrictive settings);
// protocol-level callers must state them explicitly.
var (
	defaultAttestationPolicy = protocol.AttestationPolicy{
		AndroidKey: protocol.AndroidKeyPolicy{AuthorizationScope: protocol.AndroidKeyAuthorizationScopeTEEEnforced},
		Compound:   protocol.CompoundPolicy{SubStatementScope: protocol.CompoundSubStatementScopeAll},
	}
	defaultSignaturePolicy = protocol.SignaturePolicy{ECDSAEncoding: protocol.ECDSASignatureEncodingDER}
)

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
	// verifyUser=true (UV required), verifyUserPresence=true. No opaque/top
	// origins, no MDS. The attestation/signature policies are go-webauthn's
	// own defaults (what webauthn.New would fill in): TEE-enforced Android
	// key scope, all compound sub-statements, strict DER ECDSA signatures.
	if _, err := pcc.Verify(challenge, rpID, origins, nil, nil,
		protocol.TopOriginDefaultVerificationMode, false, true, true, nil, es256Params,
		defaultAttestationPolicy, defaultSignaturePolicy); err != nil {
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

// AssertionParams carries everything VerifyAssertion needs (5+ args ->
// params struct, per the repo convention).
type AssertionParams struct {
	RawCredential []byte
	Challenge     string
	RpID          string
	Origins       []string
	// Stored credential state the assertion is checked against.
	StoredCOSE    []byte
	StoredCounter uint32
}

// VerifyAssertion verifies an authentication response against a stored
// credential's COSE public key (stepup.ts verifyAuthenticationResponse). UV
// required; returns the bumped counter.
func VerifyAssertion(p AssertionParams) (*AssertionResult, error) {
	pca, err := protocol.ParseCredentialRequestResponseBytes(p.RawCredential)
	if err != nil {
		return nil, fmt.Errorf("parse assertion: %w", err)
	}
	if err := pca.Verify(p.Challenge, p.RpID, "", p.Origins, nil, nil,
		protocol.TopOriginDefaultVerificationMode, false, true, true, p.StoredCOSE,
		defaultSignaturePolicy); err != nil {
		return nil, fmt.Errorf("verification failed: %w", err)
	}
	// Clone detection (protocol.Verify is signature-level only and never sees
	// the stored counter): when either side reports a counter, the response
	// counter must strictly increase — a regression means a cloned/replayed
	// authenticator. Same rule + wording as @simplewebauthn (assertion.ts).
	responseCounter := pca.Response.AuthenticatorData.Counter
	if responseCounter > 0 || p.StoredCounter > 0 {
		if responseCounter <= p.StoredCounter {
			return nil, fmt.Errorf("verification failed: response counter value %d was lower than expected %d",
				responseCounter, p.StoredCounter)
		}
	}
	return &AssertionResult{
		CredentialID: base64.RawURLEncoding.EncodeToString(pca.RawID),
		NewCounter:   pca.Response.AuthenticatorData.Counter,
	}, nil
}
