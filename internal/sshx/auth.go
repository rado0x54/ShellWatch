// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Per-key publickey authentication. x/crypto's PublicKeys(all...) method
// treats a signer error as fatal to the whole method, so a human denying one
// of several offered keys would abort the connection. Connect therefore
// offers every key as its own publickey method, handed to x/crypto through
// ClientConfig.AuthCallback after the previous one fails: a denied or expired
// prompt is a plain signer error, x/crypto records that method as failed and
// asks for the next key. Nothing but the harmless key query (which sshd does
// not count toward MaxAuthTries) ever reaches the server for a denied key —
// previously a deliberately invalid signature was sent to force the same
// fall-through (parity finding L10). x/crypto queries the server before it
// asks a signer to sign, so humans are only prompted for keys the server
// would accept.
package sshx

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"

	"github.com/rado0x54/shellwatch/internal/terminal"
)

// keyAuth hands x/crypto one publickey method per signer, in order, and keeps
// the last signer error so Connect can report why authentication ran out of
// keys (x/crypto itself only returns a generic "unable to authenticate").
type keyAuth struct {
	ctx     context.Context
	signers []ssh.Signer

	// extendDeadline pushes the handshake deadline forward, set by Connect
	// once the socket exists (#257). Each callback invocation may block on a
	// human approving one key, so the bound has to be per round rather than
	// one window for the whole handshake. nil in tests that drive the
	// callback directly.
	extendDeadline func()

	mu      sync.Mutex
	next    int
	lastErr error
	// signed is sticky: set the first time any signer of this connection
	// returns a signature, never cleared (#311). Kept apart from lastErr,
	// which keeps the last rejection for the failed-handshake diagnostics
	// even when a later key succeeded.
	signed bool
}

func newKeyAuth(ctx context.Context, signers []ssh.Signer) *keyAuth {
	return &keyAuth{ctx: ctx, signers: signers}
}

// callback is the ssh.ClientAuthCallback: called after the initial "none"
// attempt and after every failed method. Returning (nil, nil) ends the
// handshake with x/crypto's own error; returning an error aborts immediately.
func (k *keyAuth) callback(actx *ssh.ClientAuthContext) (ssh.AuthMethod, error) {
	if err := k.ctx.Err(); err != nil {
		return nil, err // dial context died (session-create cancelled)
	}
	// A new auth round starts here, and it may wait on a human (approval.
	// ActionTTL). Give it a fresh window: the deadline exists to catch a peer
	// that stops talking, not to cap how many keys a host may offer.
	if k.extendDeadline != nil {
		k.extendDeadline()
	}
	if len(actx.AllowedMethods) > 0 && !slices.Contains(actx.AllowedMethods, "publickey") {
		return nil, nil // server will not take public keys at all
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.next >= len(k.signers) {
		return nil, nil
	}
	s := k.signers[k.next]
	k.next++
	return ssh.PublicKeys(wrapRecording(s, k.record)), nil
}

// record is called with the result of every Sign / SignWithAlgorithm: an
// error becomes lastErr, a success sets the sticky signed flag.
func (k *keyAuth) record(err error) {
	k.mu.Lock()
	if err != nil {
		k.lastErr = err
	} else {
		k.signed = true
	}
	k.mu.Unlock()
}

// signatureProduced reports whether any signer of this connection returned a
// signature (#311). A handshake that succeeded without one was accepted by
// the server without authentication ("none").
func (k *keyAuth) signatureProduced() bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.signed
}

// authError returns the most useful error for a failed handshake: the last
// signer rejection (deny / expiry — the human-visible reason) when there was
// one, else x/crypto's error.
// authError turns the handshake error into the message a user sees in the UI
// (the body of the failed POST /api/sessions). Every authentication failure
// reads "All configured authentication methods failed" — the wording users
// have always seen — with the broker's rejection appended when a human denied
// or let a prompt expire (still errors.Is-able), instead of x/crypto's
// "unable to authenticate, attempted methods [...]" internals. Non-auth
// failures (host key, protocol) pass through unchanged.
func (k *keyAuth) authError(handshakeErr error) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.lastErr != nil {
		return fmt.Errorf("%s: %w", authFailedMessage, k.lastErr)
	}
	if strings.Contains(handshakeErr.Error(), "unable to authenticate") {
		return errors.New(authFailedMessage)
	}
	return handshakeErr
}

// authFailedMessage is the user-facing summary of an SSH authentication
// failure (no key accepted, denied, or expired).
const authFailedMessage = "All configured authentication methods failed"

// wrapRecording returns s with every Sign result (error or nil) reported to rec, preserving the
// AlgorithmSigner / MultiAlgorithmSigner capabilities x/crypto type-asserts
// (an RSA key wrapped as a plain Signer would be forced down to ssh-rsa/SHA-1).
func wrapRecording(s ssh.Signer, rec func(error)) ssh.Signer {
	base := recordingSigner{Signer: s, rec: rec}
	if ms, ok := s.(ssh.MultiAlgorithmSigner); ok {
		return &recordingMultiSigner{recordingAlgoSigner{base, ms}, ms}
	}
	if as, ok := s.(ssh.AlgorithmSigner); ok {
		return &recordingAlgoSigner{base, as}
	}
	return &base
}

type recordingSigner struct {
	ssh.Signer
	rec func(error)
}

func (r *recordingSigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	sig, err := r.Signer.Sign(rand, data)
	r.rec(err)
	return sig, err
}

type recordingAlgoSigner struct {
	recordingSigner
	as ssh.AlgorithmSigner
}

func (r *recordingAlgoSigner) SignWithAlgorithm(rand io.Reader, data []byte, algorithm string) (*ssh.Signature, error) {
	sig, err := r.as.SignWithAlgorithm(rand, data, algorithm)
	r.rec(err)
	return sig, err
}

type recordingMultiSigner struct {
	recordingAlgoSigner
	ms ssh.MultiAlgorithmSigner
}

func (r *recordingMultiSigner) Algorithms() []string { return r.ms.Algorithms() }

// UnauthenticatedEndpointError refuses a connection whose server completed
// the handshake without any signer of this connection producing a signature,
// i.e. it accepted SSH "none" authentication (#311). There is no approval to
// give and no way to allow it: Connect closes the connection before any
// channel is opened.
type UnauthenticatedEndpointError struct {
	EndpointID string
	// Observed host key, for the audit row ("" when none was recorded).
	HostKeyType        string
	HostKeyFingerprint string
}

func (e *UnauthenticatedEndpointError) Error() string {
	return "the endpoint accepted the connection without authentication; ShellWatch refuses such connections"
}

// UnauthenticatedEndpointEvent is the account-facing payload a factory emits
// when Connect refused an endpoint that accepted "none" auth: no pending
// action exists, so audit + WS + push are the only surfaces that tell the
// human.
type UnauthenticatedEndpointEvent struct {
	AccountID          string
	EndpointID         string
	EndpointLabel      string
	EndpointAddress    string
	RemoteUser         string
	HostKeyType        string
	HostKeyFingerprint string
	Trigger            terminal.Trigger
}
