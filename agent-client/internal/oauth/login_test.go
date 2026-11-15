// SPDX-License-Identifier: MIT
package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

// fakeAS stands in for ShellWatch + Hydra: discovery, a counting registration
// endpoint (only `login --dcr` may hit it), the authorization endpoint (auto-approves,
// redirecting to the loopback), and the token endpoint (PKCE-validating
// authcode → access + refresh).
type fakeAS struct {
	srv        *httptest.Server
	issuedCode string
	// issuer is what discovery advertises; mutable to simulate a change.
	issuer atomic.Value
	// cimd toggles client_id_metadata_document_supported.
	cimd atomic.Bool
	// registrations counts calls to the DCR endpoint.
	registrations atomic.Int32
	// authorized records the client_id / redirect_uri of the last authorize.
	authorizedClientID atomic.Value
	authorizedRedirect atomic.Value
	tokenClientIDs     []string
}

func newFakeAS(t *testing.T) *fakeAS {
	f := &fakeAS{issuedCode: "auth-code-xyz"}
	f.cimd.Store(true)
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		doc := map[string]any{
			"issuer":                 f.issuer.Load(),
			"authorization_endpoint": f.srv.URL + "/oauth2/auth",
			"token_endpoint":         f.srv.URL + "/oauth2/token",
			"registration_endpoint":  f.srv.URL + "/api/hydra/register",
		}
		if f.cimd.Load() {
			doc["client_id_metadata_document_supported"] = true
		}
		_ = json.NewEncoder(w).Encode(doc)
	})
	mux.HandleFunc("/api/hydra/register", func(w http.ResponseWriter, _ *http.Request) {
		f.registrations.Add(1)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"client_id": "dcr-client-1"})
	})
	// Auto-approve: redirect straight back to the loopback redirect_uri.
	mux.HandleFunc("/oauth2/auth", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		f.authorizedClientID.Store(q.Get("client_id"))
		f.authorizedRedirect.Store(q.Get("redirect_uri"))
		redirect := q.Get("redirect_uri")
		state := q.Get("state")
		loc, _ := url.Parse(redirect)
		rq := loc.Query()
		rq.Set("code", f.issuedCode)
		rq.Set("state", state)
		loc.RawQuery = rq.Encode()
		http.Redirect(w, r, loc.String(), http.StatusFound)
	})
	mux.HandleFunc("/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f.tokenClientIDs = append(f.tokenClientIDs, r.PostFormValue("client_id"))
		grant := r.PostFormValue("grant_type")
		// Hydra rotates refresh tokens: authcode → refresh-1, then each
		// refresh_token grant issues a fresh one (here: refresh-2).
		refresh := "refresh-1"
		if grant == "authorization_code" {
			if r.PostFormValue("code") != f.issuedCode || r.PostFormValue("code_verifier") == "" {
				http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
				return
			}
		} else if grant == "refresh_token" {
			refresh = "refresh-2"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "access-1",
			"refresh_token": refresh,
			"expires_in":    1800,
			"token_type":    "bearer",
		})
	})
	f.srv = httptest.NewServer(mux)
	f.issuer.Store(f.srv.URL)
	t.Cleanup(f.srv.Close)
	return f
}

// fakeBrowser drives the redirect: GET the authorize URL, then follow the 302
// to the loopback callback so Login's listener receives the code.
func fakeBrowser(t *testing.T) func(string) error {
	return func(authorizeURL string) error {
		noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}}
		resp, err := noRedirect.Get(authorizeURL)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		loc := resp.Header.Get("Location")
		if loc == "" {
			t.Fatalf("authorize did not redirect; status %d", resp.StatusCode)
		}
		cb, err := http.Get(loc) // hit the loopback /callback
		if err != nil {
			return err
		}
		cb.Body.Close()
		return nil
	}
}

func TestLogin_UsesMetadataDocumentClientID(t *testing.T) {
	f := newFakeAS(t)

	result, err := Login(context.Background(), LoginOptions{
		ServerURL:     f.srv.URL,
		Scope:         "agent",
		AllowInsecure: true, // httptest is http://
		OpenBrowser:   fakeBrowser(t),
	})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if result.ClientID != ClientID {
		t.Errorf("ClientID = %q, want %q", result.ClientID, ClientID)
	}
	if got := f.authorizedClientID.Load(); got != ClientID {
		t.Errorf("authorize client_id = %v, want %q", got, ClientID)
	}
	if got := strings.Join(f.tokenClientIDs, ","); got != ClientID {
		t.Errorf("token client_id = %q, want %q", got, ClientID)
	}
	if n := f.registrations.Load(); n != 0 {
		t.Errorf("registration endpoint called %d times, want 0", n)
	}
	if result.Issuer != f.srv.URL {
		t.Errorf("Issuer = %q, want %q", result.Issuer, f.srv.URL)
	}
	if result.RefreshToken != "refresh-1" {
		t.Errorf("RefreshToken = %q, want refresh-1", result.RefreshToken)
	}
	// The document only registers loopback IP literals; a hostname such as
	// "localhost" would not get the any-port exception (#281).
	redirect, _ := url.Parse(f.authorizedRedirect.Load().(string))
	if redirect.Hostname() != "127.0.0.1" || redirect.Path != "/callback" || redirect.Port() == "" {
		t.Errorf("redirect_uri = %s, want http://127.0.0.1:<port>/callback", redirect)
	}
}

func TestLogin_ClientIDOverride(t *testing.T) {
	f := newFakeAS(t)
	const override = "https://127.0.0.1:8443/.well-known/client.json"
	result, err := Login(context.Background(), LoginOptions{
		ServerURL:     f.srv.URL,
		AllowInsecure: true,
		ClientID:      override,
		OpenBrowser:   fakeBrowser(t),
	})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if result.ClientID != override || f.authorizedClientID.Load() != override {
		t.Errorf("override not used: result %q, authorize %v", result.ClientID, f.authorizedClientID.Load())
	}
}

func TestLogin_RequiresMetadataDocumentSupport(t *testing.T) {
	f := newFakeAS(t)
	f.cimd.Store(false)
	opened := false
	_, err := Login(context.Background(), LoginOptions{
		ServerURL:     f.srv.URL,
		AllowInsecure: true,
		OpenBrowser:   func(string) error { opened = true; return nil },
	})
	if err == nil || !strings.Contains(err.Error(), "Client ID Metadata Documents") || !strings.Contains(err.Error(), "--dcr") {
		t.Fatalf("err = %v, want a CIMD-unsupported error that points at --dcr", err)
	}
	if opened {
		t.Error("browser opened although the server cannot resolve the client_id")
	}
	if n := f.registrations.Load(); n != 0 {
		t.Errorf("registration endpoint called %d times, want 0 (no DCR fallback)", n)
	}
}

// --dcr is explicit: it registers even when the server supports CIMD, and it
// is the only way to log in when the server does not.
func TestLogin_DCROptIn(t *testing.T) {
	for _, cimd := range []bool{true, false} {
		f := newFakeAS(t)
		f.cimd.Store(cimd)
		result, err := Login(context.Background(), LoginOptions{
			ServerURL:     f.srv.URL,
			AllowInsecure: true,
			UseDCR:        true,
			OpenBrowser:   fakeBrowser(t),
		})
		if err != nil {
			t.Fatalf("cimd=%v: Login: %v", cimd, err)
		}
		if n := f.registrations.Load(); n != 1 {
			t.Errorf("cimd=%v: registrations = %d, want 1", cimd, n)
		}
		if result.ClientID != "dcr-client-1" || f.authorizedClientID.Load() != "dcr-client-1" {
			t.Errorf("cimd=%v: client_id result %q, authorize %v; want dcr-client-1", cimd, result.ClientID, f.authorizedClientID.Load())
		}
		if result.Issuer != f.srv.URL {
			t.Errorf("cimd=%v: Issuer = %q, want %q", cimd, result.Issuer, f.srv.URL)
		}
	}
}

func TestLogin_DCRRejectsClientIDOverride(t *testing.T) {
	_, err := Login(context.Background(), LoginOptions{
		ServerURL: "https://example.invalid",
		UseDCR:    true,
		ClientID:  "https://127.0.0.1:8443/.well-known/client.json",
	})
	if err == nil {
		t.Fatal("want an error for --dcr combined with a client_id override")
	}
}

func TestRefreshTokenSource(t *testing.T) {
	f := newFakeAS(t)
	var rotated string
	src := NewRefreshTokenSource(RefreshTokenSourceParams{
		ServerURL:     f.srv.URL,
		Creds:         StoredCreds{Issuer: f.srv.URL, ClientID: ClientID, RefreshToken: "refresh-1"},
		AllowInsecure: true,
		OnRotate:      func(rt string) { rotated = rt },
	})
	tok, err := src.Token()
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if tok != "access-1" {
		t.Errorf("access token = %q, want access-1", tok)
	}
	if rotated != "refresh-2" {
		t.Errorf("onRotate got %q, want refresh-2 (rotated)", rotated)
	}
	// Second call is cached (no second mint needed) — still returns the token.
	if tok2, _ := src.Token(); tok2 != "access-1" {
		t.Errorf("cached token = %q, want access-1", tok2)
	}
}

func TestRefreshTokenSource_RefusesChangedIssuer(t *testing.T) {
	f := newFakeAS(t)
	f.issuer.Store("https://other-issuer.example")
	src := NewRefreshTokenSource(RefreshTokenSourceParams{
		ServerURL:     f.srv.URL,
		Creds:         StoredCreds{Issuer: f.srv.URL, ClientID: ClientID, RefreshToken: "refresh-1"},
		AllowInsecure: true,
	})
	if _, err := src.Token(); !errors.Is(err, ErrIssuerChanged) {
		t.Fatalf("err = %v, want ErrIssuerChanged", err)
	}
	if len(f.tokenClientIDs) != 0 {
		t.Error("refresh token was presented to the token endpoint despite the issuer change")
	}
}

// Credentials stored before #256 carry no issuer; they keep refreshing.
func TestRefreshTokenSource_LegacyCredsWithoutIssuer(t *testing.T) {
	f := newFakeAS(t)
	src := NewRefreshTokenSource(RefreshTokenSourceParams{
		ServerURL:     f.srv.URL,
		Creds:         StoredCreds{ClientID: "dcr-client-1", RefreshToken: "refresh-1"},
		AllowInsecure: true,
	})
	if _, err := src.Token(); err != nil {
		t.Fatalf("Token: %v", err)
	}
}

func TestDecodeCreds(t *testing.T) {
	c := StoredCreds{Issuer: "https://issuer.example", ClientID: "id", RefreshToken: "rt"}
	blob, err := c.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	got, ok := DecodeCreds(blob)
	if !ok || got != c {
		t.Errorf("round-trip failed: ok=%v got=%+v", ok, got)
	}
	if _, ok := DecodeCreds("sw_legacy_token"); ok {
		t.Error("raw token should not decode as creds")
	}
}
