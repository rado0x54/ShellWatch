// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// webauthnSigner is the ssh.Signer for browser passkeys (spec §5.11): it holds
// no private key — Sign fires a request at the broker and blocks until a human
// approves in the browser, then converts the returned assertion into the SSH
// PROTOCOL.u2f signature. This is the human-in-the-loop heart: a real passkey
// signs an SSH challenge only after explicit approval.
package sshx

import (
	"context"
	"io"

	"golang.org/x/crypto/ssh"

	"github.com/rado0x54/shellwatch/internal/approval"
	"github.com/rado0x54/shellwatch/internal/signing"
)

// SignBroker is the narrow interface sshx depends on (implemented by
// approval.Broker). Deny/expire return a sentinel error.
type SignBroker interface {
	RequestSign(ctx context.Context, accountID string, req signing.SignRequest, actionCtx approval.Context, redirectTo string) (signing.SignResponse, error)
}

// WebAuthnSigner presents a passkey public key and signs via human approval.
type WebAuthnSigner struct {
	// Pub is the ssh.PublicKey advertised (the webauthn-sk-* key derived from
	// the stored COSE credential, or a cert wrapping it via ssh.NewCertSigner).
	Pub ssh.PublicKey

	Broker       SignBroker
	AccountID    string
	CredentialID string
	RpID         string
	Origin       string
	UVPolicy     string
	PasskeyLabel string
	ConnectionID string
	ActionCtx    approval.Context
	RedirectTo   string

	// Ctx bounds the approval wait (the connection's dial context).
	Ctx context.Context
}

var _ ssh.Signer = (*WebAuthnSigner)(nil)

func (s *WebAuthnSigner) PublicKey() ssh.PublicKey { return s.Pub }

// Sign requests human approval for signing data, then builds the SSH signature
// from the browser's WebAuthn assertion.
func (s *WebAuthnSigner) Sign(_ io.Reader, data []byte) (*ssh.Signature, error) {
	ctx := s.Ctx
	if ctx == nil {
		ctx = context.Background()
	}
	resp, err := s.Broker.RequestSign(ctx, s.AccountID, signing.SignRequest{
		CredentialID:     s.CredentialID,
		DataToSign:       data,
		RpID:             s.RpID,
		UserVerification: s.UVPolicy,
		PasskeyLabel:     s.PasskeyLabel,
		ConnectionID:     s.ConnectionID,
	}, s.ActionCtx, s.RedirectTo)
	if err != nil {
		return nil, err
	}
	return signing.BuildSSHSignature(resp)
}
