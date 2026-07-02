// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Broker is the SignBroker sshx signers depend on (spec §5.8, replaces the
// create-factory.ts closures, W1). RequestSign creates a webauthn-sign action,
// dispatches notifications, and blocks until the browser resolves, the TTL
// expires, or the context is cancelled. Deny/expire returns a sentinel the
// signer maps to skip-identity (try-next-key).
package approval

import (
	"context"
	"encoding/base64"
	"errors"

	"github.com/rado0x54/shellwatch/internal/signing"
)

var (
	// ErrDenied is returned when the human denies the request.
	ErrDenied = errors.New("signing request denied")
	// ErrExpired is returned when the action TTL elapses.
	ErrExpired = errors.New("signing request expired")
)

// Channel delivers an action to a notification surface (WS toast, push).
type Channel interface {
	Notify(action *Action, deepLink string)
	Resolved(action *Action)
}

// Broker fulfills sign requests via the pending-action store + channels.
type Broker struct {
	store    *Store
	channels []Channel
	baseURL  func() string
}

// NewBroker builds the broker. baseURL yields the deep-link origin
// (externalUrl); channels fan out notifications.
func NewBroker(store *Store, baseURL func() string, channels ...Channel) *Broker {
	return &Broker{store: store, channels: channels, baseURL: baseURL}
}

// RequestSign handles a passkey sign request (signing-bridge.handleSignRequest
// + the blocking wait), returning the raw browser assertion — the caller
// (signer) does the SSH conversion.
func (b *Broker) RequestSign(ctx context.Context, accountID string, req signing.SignRequest, actionCtx Context, redirectTo string) (signing.SignResponse, error) {
	// Standard base64 (not base64url) — matches OpenSSH's verifier
	// reconstructing clientDataJSON (signing-bridge.ts).
	challenge := base64.StdEncoding.EncodeToString(req.DataToSign)

	resultCh := make(chan signing.SignResponse, 1)
	errCh := make(chan error, 1)

	action := b.store.Create(CreateParams{
		AccountID: accountID, Type: TypeWebAuthnSign, Context: actionCtx,
		RedirectTo: redirectTo, ConnectionID: req.ConnectionID, CredentialID: req.CredentialID,
		Challenge: challenge, RpID: req.RpID, PasskeyLabel: req.PasskeyLabel,
		UserVerification: orDefault(req.UserVerification, "required"),
		ResolveSign:      func(r signing.SignResponse) { resultCh <- r },
		Reject:           func(err error) { errCh <- err },
	})

	deepLink := b.baseURL() + "/sign/" + action.ID
	for _, ch := range b.channels {
		ch.Notify(action, deepLink)
	}

	select {
	case r := <-resultCh:
		b.notifyResolved(action)
		return r, nil
	case err := <-errCh:
		b.notifyResolved(action)
		return signing.SignResponse{}, err
	case <-ctx.Done():
		return signing.SignResponse{}, ctx.Err()
	}
}

func (b *Broker) notifyResolved(a *Action) {
	for _, ch := range b.channels {
		ch.Resolved(a)
	}
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
