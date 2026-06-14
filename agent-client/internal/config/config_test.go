// SPDX-License-Identifier: MIT
package config

import (
	"os"
	"testing"

	"github.com/rado0x54/shellwatch-agent/internal/credstore"
	"github.com/rado0x54/shellwatch-agent/internal/oauth"
)

// fakeStore is the default credstore swapped in for the duration of every
// config test. Lets us assert credstore-precedence logic without touching
// the developer's real keyring.
type fakeStore struct {
	tokens map[string]string
}

func (s *fakeStore) Get(serverURL string) (string, error) {
	if t, ok := s.tokens[serverURL]; ok {
		return t, nil
	}
	return "", credstore.ErrNotFound
}
func (s *fakeStore) Set(serverURL, token string) error {
	if s.tokens == nil {
		s.tokens = map[string]string{}
	}
	s.tokens[serverURL] = token
	return nil
}
func (s *fakeStore) Delete(serverURL string) error {
	if _, ok := s.tokens[serverURL]; !ok {
		return credstore.ErrNotFound
	}
	delete(s.tokens, serverURL)
	return nil
}

// withCredStore swaps newCredStore for the duration of a test. Each test
// that needs a populated store calls this; the TestMain default is empty.
func withCredStore(t *testing.T, store credstore.Store) {
	t.Helper()
	prev := newCredStore
	newCredStore = func() (credstore.Store, error) { return store, nil }
	t.Cleanup(func() { newCredStore = prev })
}

func TestMain(m *testing.M) {
	// Block the real OS keyring for the entire package by default. Tests
	// that need credstore behavior install their own fake via withCredStore.
	newCredStore = func() (credstore.Store, error) { return &fakeStore{}, nil }
	os.Exit(m.Run())
}

func TestResolveServerPrecedence(t *testing.T) {
	tests := []struct {
		name       string
		flagServer string
		flagSet    bool
		envServer  string
		want       string
	}{
		{
			name: "no flag, no env -> default",
			want: DefaultServer,
		},
		{
			name:      "env only -> env wins",
			envServer: "https://env.example.com",
			want:      "https://env.example.com",
		},
		{
			name:       "explicit flag only -> flag wins",
			flagServer: "https://flag.example.com",
			flagSet:    true,
			want:       "https://flag.example.com",
		},
		{
			name:       "explicit flag overrides env",
			flagServer: "https://flag.example.com",
			flagSet:    true,
			envServer:  "https://env.example.com",
			want:       "https://flag.example.com",
		},
		{
			name:       "default-valued flag does not clobber env",
			flagServer: DefaultServer, // matches the default; flag.Visit would not report it
			flagSet:    false,
			envServer:  "https://env.example.com",
			want:       "https://env.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fv := flagValues{
				server:   tt.flagServer,
				explicit: map[string]bool{},
			}
			if tt.flagSet {
				fv.explicit["server"] = true
			}
			ev := envValues{server: tt.envServer}

			cfg := resolve(fv, ev)
			if cfg.Server != tt.want {
				t.Errorf("Server = %q, want %q", cfg.Server, tt.want)
			}
		})
	}
}

// tokenString resolves the bearer a Config would present, or "" if none. A
// raw credstore/flag value decodes as a StaticToken (not OAuth-client JSON), so
// Token() returns it verbatim — which is what these precedence tests assert.
func tokenString(t *testing.T, cfg *Config) string {
	t.Helper()
	if cfg.Token == nil {
		return ""
	}
	tok, err := cfg.Token.Token()
	if err != nil {
		t.Fatalf("Token() error: %v", err)
	}
	return tok
}

func TestResolveTokenPrecedence(t *testing.T) {
	// explicit flag overrides env
	cfg := resolve(
		flagValues{token: "from-flag", explicit: map[string]bool{"token": true}},
		envValues{token: "from-env"},
	)
	if got := tokenString(t, cfg); got != "from-flag" {
		t.Errorf("token = %q, want from-flag", got)
	}

	// env used when flag not set
	cfg = resolve(
		flagValues{explicit: map[string]bool{}},
		envValues{token: "from-env"},
	)
	if got := tokenString(t, cfg); got != "from-env" {
		t.Errorf("token = %q, want from-env", got)
	}
}

func TestResolveToken_FallsBackToCredstore(t *testing.T) {
	// Neither flag nor env set; credstore has a (legacy raw) value for the
	// resolved server URL — resolve() should pick it up as a static bearer.
	withCredStore(t, &fakeStore{tokens: map[string]string{
		DefaultServer: "from-credstore",
	}})

	cfg := resolve(flagValues{explicit: map[string]bool{}}, envValues{})
	if got := tokenString(t, cfg); got != "from-credstore" {
		t.Errorf("token = %q, want from-credstore", got)
	}
}

func TestResolveToken_FlagBeatsCredstore(t *testing.T) {
	// Static flag must win even when the credstore has a value — this is
	// the documented precedence and the path CI environments rely on.
	withCredStore(t, &fakeStore{tokens: map[string]string{
		DefaultServer: "from-credstore",
	}})

	cfg := resolve(
		flagValues{token: "from-flag", explicit: map[string]bool{"token": true}},
		envValues{},
	)
	if got := tokenString(t, cfg); got != "from-flag" {
		t.Errorf("token = %q, want from-flag", got)
	}
}

func TestResolveToken_CredstoreLookedUpByServerURL(t *testing.T) {
	// Different servers must isolate cleanly: a value saved for prod
	// must not satisfy a daemon configured to point at dev.
	withCredStore(t, &fakeStore{tokens: map[string]string{
		"https://prod.example.com": "prod-token",
	}})

	cfg := resolve(
		flagValues{server: "https://dev.example.com", explicit: map[string]bool{"server": true}},
		envValues{},
	)
	if cfg.Token != nil {
		t.Errorf("token for dev should be nil (only prod value saved); got %v", cfg.Token)
	}
}

func TestValidateRequiresCredentials(t *testing.T) {
	if err := (&Config{Server: DefaultServer}).Validate(); err == nil {
		t.Fatal("expected error for missing credentials")
	}
	if err := (&Config{Server: DefaultServer, Token: oauth.StaticToken("k")}).Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
