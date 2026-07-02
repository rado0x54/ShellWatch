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
	mu             sync.Mutex
	tokens         map[string]hydra.Introspection
	clients        map[string]hydra.OAuth2Client
	loginChallenge map[string]bool
	counter        int
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
