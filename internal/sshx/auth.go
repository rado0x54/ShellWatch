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
	"io"
	"slices"
	"sync"

	"errors"
	"fmt"
	"golang.org/x/crypto/ssh"
	"strings"
)

// keyAuth hands x/crypto one publickey method per signer, in order, and keeps
// the last signer error so Connect can report why authentication ran out of
// keys (x/crypto itself only returns a generic "unable to authenticate").
type keyAuth struct {
	ctx     context.Context
	signers []ssh.Signer

	mu      sync.Mutex
	next    int
	lastErr error
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

func (k *keyAuth) record(err error) {
	k.mu.Lock()
	k.lastErr = err
	k.mu.Unlock()
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

// wrapRecording returns s with Sign errors reported to rec, preserving the
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
	if err != nil {
		r.rec(err)
	}
	return sig, err
}

type recordingAlgoSigner struct {
	recordingSigner
	as ssh.AlgorithmSigner
}

func (r *recordingAlgoSigner) SignWithAlgorithm(rand io.Reader, data []byte, algorithm string) (*ssh.Signature, error) {
	sig, err := r.as.SignWithAlgorithm(rand, data, algorithm)
	if err != nil {
		r.rec(err)
	}
	return sig, err
}

type recordingMultiSigner struct {
	recordingAlgoSigner
	ms ssh.MultiAlgorithmSigner
}

func (r *recordingMultiSigner) Algorithms() []string { return r.ms.Algorithms() }
