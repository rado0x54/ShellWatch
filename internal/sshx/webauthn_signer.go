// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// webauthnSigner is the ssh.Signer for browser passkeys (spec §5.11): it holds
// no private key — Sign fires a request at the broker and blocks until a human
// approves in the browser, then converts the returned assertion into the SSH
// PROTOCOL.u2f signature. This is the human-in-the-loop heart: a real passkey
// signs an SSH challenge only after explicit approval.
package sshx

import (
	"context"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/ssh"

	"github.com/rado0x54/shellwatch/internal/approval"
	"github.com/rado0x54/shellwatch/internal/signing"
)

// SignBroker is the narrow interface sshx depends on (implemented by
// approval.Broker). Deny/expire return a sentinel error.
type SignBroker interface {
	RequestSign(ctx context.Context, accountID string, req signing.SignRequest, actionCtx approval.Context, redirectTo string) (signing.SignResponse, error)
	// RequestKeyApproval gates a file-key sign — used by the forwarding agent.
	// The returned action id names the approval (host-key pin audit, #241).
	RequestKeyApproval(ctx context.Context, p approval.KeyApproval) (string, error)
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

	// Host-key pinning (#241): HostState is this connection's observed-key
	// record; a provisional ("new") key is pinned via HostKeys as part of the
	// approval this signer collects. Both nil on paths without a dialed
	// connection (agent forwarding), where no pin decision exists.
	EndpointID string
	HostKeys   HostKeys
	HostState  *HostKeyState

	// Ctx bounds the approval wait (the connection's dial context).
	Ctx context.Context
}

var _ ssh.Signer = (*WebAuthnSigner)(nil)

func (s *WebAuthnSigner) PublicKey() ssh.PublicKey { return s.Pub }

// Sign requests human approval for signing data, then builds the SSH signature
// from the browser's WebAuthn assertion. On an unpinned endpoint the same
// approval pins the observed host key — persisted BEFORE the signature is
// returned, so no authentication completes against a host no human vouched for.
func (s *WebAuthnSigner) Sign(_ io.Reader, data []byte) (*ssh.Signature, error) {
	ctx := s.Ctx
	if ctx == nil {
		ctx = context.Background()
	}
	actionCtx, provisional := withHostKeyContext(s.ActionCtx, s.HostState)
	resp, err := s.Broker.RequestSign(ctx, s.AccountID, signing.SignRequest{
		CredentialID:     s.CredentialID,
		DataToSign:       data,
		RpID:             s.RpID,
		UserVerification: s.UVPolicy,
		PasskeyLabel:     s.PasskeyLabel,
		ConnectionID:     s.ConnectionID,
	}, actionCtx, s.RedirectTo)
	if err != nil {
		// Any rejection — deny, TTL expiry, store destroy — is returned as-is.
		// Connect offers one publickey method per key (auth.go), so x/crypto
		// moves on to the next key instead of aborting the handshake (Node's
		// SKIP_IDENTITY_SIGNATURE for every reject, ssh-agent.ts:24-36; M11).
		// A dead dial context stops the key iteration there.
		return nil, err
	}
	if err := pinAfterApproval(ctx, s.HostKeys, s.HostState, s.EndpointID, provisional, s.CredentialID, resp.ActionID); err != nil {
		return nil, err
	}
	return signing.BuildSSHSignature(resp)
}

// withHostKeyContext annotates an endpoint-auth action context with this
// connection's host-key state; the returned observed key is non-nil when the
// approval must also pin it ("new").
func withHostKeyContext(actionCtx approval.Context, state *HostKeyState) (approval.Context, *ObservedHostKey) {
	if state == nil {
		return actionCtx, nil
	}
	st, observed, pinned := state.Snapshot()
	if st == HostKeyUnseen {
		return actionCtx, nil
	}
	status := string(HostKeyKnown)
	var provisional *ObservedHostKey
	if st == HostKeyNew && !pinned {
		status = string(HostKeyNew)
		o := observed
		provisional = &o
	}
	actionCtx.HostKey = &approval.HostKeyInfo{Type: observed.Type, Fingerprint: observed.Fingerprint, Status: status}
	return actionCtx, provisional
}

// pinAfterApproval persists a provisional host key the human just approved.
// Compare-and-set: if a different pin landed first (two concurrent first
// connections, one possibly an attacker), the approval fails and the
// connection aborts rather than riding on someone else's trust decision.
func pinAfterApproval(ctx context.Context, hostKeys HostKeys, state *HostKeyState, endpointID string, provisional *ObservedHostKey, pinnedBy, actionID string) error {
	if provisional == nil {
		return nil
	}
	if hostKeys == nil {
		return errors.New("host key pin required but no pin store is wired")
	}
	if err := hostKeys.Pin(ctx, endpointID, *provisional, pinnedBy, actionID); err != nil {
		return fmt.Errorf("host key pin failed: %w", err)
	}
	state.MarkPinned()
	return nil
}
