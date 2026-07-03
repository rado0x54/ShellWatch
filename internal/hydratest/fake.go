// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Package hydratest is the in-memory fake Hydra admin (port of
// src/test/helpers/fake-hydra.ts): lets integration tests exercise the login
// provider, mediated DCR, and bearer gate without a live Hydra. Login
// challenges reject unless seeded (SetLoginRequest), mirroring how Hydra
// answers an unknown/expired challenge.
package hydratest

import (
	"context"
	"fmt"
	"sync"

	"github.com/rado0x54/shellwatch/internal/hydra"
)

// FakeAdmin implements hydra.Admin in memory.
type FakeAdmin struct {
	mu              sync.Mutex
	tokens          map[string]hydra.Introspection
	clients         map[string]hydra.OAuth2Client
	loginChallenge  map[string]bool
	consent         map[string]hydra.ConsentRequest
	consentSessions map[string][]hydra.ConsentSession
	RevokedConsent  []string
	RevokedLogin    []string
	logout          map[string]hydra.LogoutRequest
	RejectedLogout  []string
	counter         int
}

func New() *FakeAdmin {
	return &FakeAdmin{
		tokens:         map[string]hydra.Introspection{},
		clients:        map[string]hydra.OAuth2Client{},
		loginChallenge: map[string]bool{},
	}
}

// RegisterToken sets what introspect(token) returns (defaults to an active
// access token).
func (f *FakeAdmin) RegisterToken(token string, ins hydra.Introspection) {
	f.mu.Lock()
	defer f.mu.Unlock()
	ins.Active = true
	if ins.TokenUse == "" {
		ins.TokenUse = "access_token"
	}
	f.tokens[token] = ins
}

// SetLoginRequest seeds a login challenge so AcceptLoginRequest resolves for it.
func (f *FakeAdmin) SetLoginRequest(challenge string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.loginChallenge[challenge] = true
}

// Clients returns a snapshot of created clients.
func (f *FakeAdmin) Clients() map[string]hydra.OAuth2Client {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make(map[string]hydra.OAuth2Client, len(f.clients))
	for k, v := range f.clients {
		out[k] = v
	}
	return out
}

func (f *FakeAdmin) Introspect(_ context.Context, token string) (hydra.Introspection, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if ins, ok := f.tokens[token]; ok {
		return ins, nil
	}
	return hydra.Introspection{Active: false}, nil
}

func (f *FakeAdmin) AcceptLoginRequest(_ context.Context, challenge string, _ hydra.AcceptLogin) (hydra.Redirect, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.loginChallenge[challenge] {
		return hydra.Redirect{}, &hydra.APIError{Status: 404, Msg: "fake-hydra: acceptLoginRequest — unknown challenge"}
	}
	return hydra.Redirect{RedirectTo: "https://hydra.test/login-callback?c=" + challenge}, nil
}

// consent challenges seeded for the consent-provider tests.
func (f *FakeAdmin) SetConsentRequest(challenge string, req hydra.ConsentRequest) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.consent == nil {
		f.consent = map[string]hydra.ConsentRequest{}
	}
	f.consent[challenge] = req
}

func (f *FakeAdmin) GetLoginRequest(_ context.Context, challenge string) (hydra.LoginRequest, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.loginChallenge[challenge] {
		return hydra.LoginRequest{Challenge: challenge}, nil
	}
	return hydra.LoginRequest{}, &hydra.APIError{Status: 404, Msg: "fake-hydra: unknown login challenge"}
}

func (f *FakeAdmin) GetConsentRequest(_ context.Context, challenge string) (hydra.ConsentRequest, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if c, ok := f.consent[challenge]; ok {
		return c, nil
	}
	return hydra.ConsentRequest{}, &hydra.APIError{Status: 404, Msg: "fake-hydra: unknown consent challenge"}
}

func (f *FakeAdmin) AcceptConsentRequest(_ context.Context, challenge string, _ hydra.AcceptConsent) (hydra.Redirect, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.consent[challenge]; !ok {
		return hydra.Redirect{}, &hydra.APIError{Status: 404, Msg: "fake-hydra: unknown consent challenge"}
	}
	return hydra.Redirect{RedirectTo: "https://hydra.test/consent-callback?c=" + challenge}, nil
}

// SetConsentSessions seeds the list a subject's /api/auth/sessions returns.
func (f *FakeAdmin) SetConsentSessions(subject string, sessions []hydra.ConsentSession) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.consentSessions == nil {
		f.consentSessions = map[string][]hydra.ConsentSession{}
	}
	f.consentSessions[subject] = sessions
}

// RevokedConsent/RevokedLogin record what the revoke routes were called with.
func (f *FakeAdmin) ListConsentSessions(_ context.Context, subject string) ([]hydra.ConsentSession, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.consentSessions[subject], nil
}

func (f *FakeAdmin) RevokeConsentSessions(_ context.Context, subject, clientID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.RevokedConsent = append(f.RevokedConsent, subject+"/"+clientID)
	return nil
}

func (f *FakeAdmin) RevokeLoginSessions(_ context.Context, subject string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.RevokedLogin = append(f.RevokedLogin, subject)
	return nil
}

// SetLogoutRequest seeds a logout challenge.
func (f *FakeAdmin) SetLogoutRequest(challenge string, req hydra.LogoutRequest) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.logout == nil {
		f.logout = map[string]hydra.LogoutRequest{}
	}
	f.logout[challenge] = req
}

func (f *FakeAdmin) GetLogoutRequest(_ context.Context, challenge string) (hydra.LogoutRequest, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if lr, ok := f.logout[challenge]; ok {
		return lr, nil
	}
	return hydra.LogoutRequest{}, &hydra.APIError{Status: 404, Msg: "fake-hydra: unknown logout challenge"}
}

func (f *FakeAdmin) AcceptLogoutRequest(_ context.Context, challenge string) (hydra.Redirect, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.logout[challenge]; !ok {
		return hydra.Redirect{}, &hydra.APIError{Status: 404, Msg: "fake-hydra: unknown logout challenge"}
	}
	return hydra.Redirect{RedirectTo: "https://hydra.test/logout-callback?c=" + challenge}, nil
}

func (f *FakeAdmin) RejectLogoutRequest(_ context.Context, challenge string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.RejectedLogout = append(f.RejectedLogout, challenge)
	return nil
}

func (f *FakeAdmin) CreateClient(_ context.Context, client hydra.OAuth2Client) (hydra.OAuth2Client, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.counter++
	if client.ClientID == "" {
		client.ClientID = fmt.Sprintf("hydra-client-%d", f.counter)
	}
	if client.ClientSecret == "" {
		client.ClientSecret = fmt.Sprintf("secret-%d", f.counter)
	}
	f.clients[client.ClientID] = client
	return client, nil
}

func (f *FakeAdmin) GetClient(_ context.Context, clientID string) (*hydra.OAuth2Client, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if c, ok := f.clients[clientID]; ok {
		return &c, nil
	}
	return nil, nil
}

func (f *FakeAdmin) UpdateClient(_ context.Context, clientID string, client hydra.OAuth2Client) (hydra.OAuth2Client, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	client.ClientID = clientID
	f.clients[clientID] = client
	return client, nil
}

var _ hydra.Admin = (*FakeAdmin)(nil)
