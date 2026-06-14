// SPDX-License-Identifier: MIT
package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// fakeAS stands in for ShellWatch + Hydra: discovery, mediated DCR, the
// authorization endpoint (auto-approves, redirecting to the loopback), and the
// token endpoint (PKCE-validating authcode → access + refresh).
type fakeAS struct {
	srv        *httptest.Server
	issuedCode string
}

func newFakeAS(t *testing.T) *fakeAS {
	f := &fakeAS{issuedCode: "auth-code-xyz"}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"authorization_endpoint": f.srv.URL + "/oauth2/auth",
			"token_endpoint":         f.srv.URL + "/oauth2/token",
			"registration_endpoint":  f.srv.URL + "/oauth2/register",
		})
	})
	mux.HandleFunc("/oauth2/register", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"client_id": "dcr-client-1"})
	})
	// Auto-approve: redirect straight back to the loopback redirect_uri.
	mux.HandleFunc("/oauth2/auth", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
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

func TestLogin_LoopbackAuthCode(t *testing.T) {
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
	if result.ClientID != "dcr-client-1" {
		t.Errorf("ClientID = %q, want dcr-client-1", result.ClientID)
	}
	if result.RefreshToken != "refresh-1" {
		t.Errorf("RefreshToken = %q, want refresh-1", result.RefreshToken)
	}
}

func TestRefreshTokenSource(t *testing.T) {
	f := newFakeAS(t)
	var rotated string
	src := NewRefreshTokenSource(f.srv.URL, "dcr-client-1", "refresh-1", true, func(rt string) {
		rotated = rt
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

func TestDecodeCreds(t *testing.T) {
	c := StoredCreds{ClientID: "id", RefreshToken: "rt"}
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
