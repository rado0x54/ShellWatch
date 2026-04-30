package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// fakeAuthServer stands in for ShellWatch's /oauth endpoints. It
// remembers the verifier challenge, validates PKCE on token exchange,
// and issues a stub `sw_…` token. Lets us exercise the loopback flow
// end-to-end without a real ShellWatch instance.
type fakeAuthServer struct {
	t          *testing.T
	codes      map[string]storedCode
	issueToken string
}

type storedCode struct {
	challenge string
	redirect  string
}

func newFakeAuthServer(t *testing.T) *httptest.Server {
	fas := &fakeAuthServer{t: t, codes: map[string]storedCode{}, issueToken: "sw_fake_token_xxxxxxxxxxxxxxxx"}
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth/authorize", fas.handleAuthorize)
	mux.HandleFunc("/oauth/token", fas.handleToken)
	return httptest.NewServer(mux)
}

func (f *fakeAuthServer) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("response_type") != "code" {
		http.Error(w, "bad response_type", http.StatusBadRequest)
		return
	}
	redirect := q.Get("redirect_uri")
	state := q.Get("state")
	challenge := q.Get("code_challenge")
	if redirect == "" || state == "" || challenge == "" {
		http.Error(w, "missing param", http.StatusBadRequest)
		return
	}
	// Real server would render an HTML consent page; we auto-approve.
	code := "code-" + state[:8]
	f.codes[code] = storedCode{challenge: challenge, redirect: redirect}
	target, _ := url.Parse(redirect)
	rq := target.Query()
	rq.Set("code", code)
	rq.Set("state", state)
	target.RawQuery = rq.Encode()
	http.Redirect(w, r, target.String(), http.StatusFound)
}

func (f *fakeAuthServer) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	code := r.PostForm.Get("code")
	verifier := r.PostForm.Get("code_verifier")
	stored, ok := f.codes[code]
	if !ok {
		http.Error(w, "unknown code", http.StatusBadRequest)
		return
	}
	delete(f.codes, code)

	// Verify PKCE: S256(verifier) must equal stored challenge.
	sum := sha256.Sum256([]byte(verifier))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	if want != stored.challenge {
		http.Error(w, "PKCE mismatch", http.StatusBadRequest)
		return
	}
	if r.PostForm.Get("redirect_uri") != stored.redirect {
		http.Error(w, "redirect_uri mismatch", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"access_token": f.issueToken,
		"token_type":   "Bearer",
	})
}

// fakeBrowser fetches the authorize URL the way a real browser would —
// follow the 302 to the loopback callback. Substituted in via
// LoginOptions.OpenBrowser so the flow runs to completion in-process.
func fakeBrowser(t *testing.T) func(rawURL string) error {
	return func(rawURL string) error {
		client := &http.Client{
			Timeout: 5 * time.Second,
			// Don't auto-follow — we want to manually GET the loopback URL
			// so the callback handler in shellwatch-agent runs.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
		resp, err := client.Get(rawURL)
		if err != nil {
			return err
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusFound {
			t.Fatalf("authorize returned %d, want 302", resp.StatusCode)
		}
		// The Location header is the redirect to the loopback callback.
		// Hit it so the agent's HTTP server gets the code.
		callback := resp.Header.Get("Location")
		if callback == "" {
			t.Fatal("authorize 302 had no Location header")
		}
		resp2, err := client.Get(callback)
		if err != nil {
			return err
		}
		_, _ = io.Copy(io.Discard, resp2.Body)
		resp2.Body.Close()
		return nil
	}
}

func TestLogin_HappyPath(t *testing.T) {
	srv := newFakeAuthServer(t)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := Login(ctx, LoginOptions{
		ServerURL:     srv.URL,
		AllowInsecure: true, // httptest serves http://
		OpenBrowser:   fakeBrowser(t),
		Stdout:        io.Discard,
	})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if !strings.HasPrefix(result.AccessToken, "sw_") {
		t.Errorf("AccessToken: got %q, want sw_ prefix", result.AccessToken)
	}
	if result.TokenType != "Bearer" {
		t.Errorf("TokenType: got %q, want Bearer", result.TokenType)
	}
	if result.ServerURL != srv.URL {
		t.Errorf("ServerURL: got %q, want %q", result.ServerURL, srv.URL)
	}
}

func TestLogin_RejectsHTTPWithoutInsecure(t *testing.T) {
	_, err := Login(context.Background(), LoginOptions{
		ServerURL: "http://example.com",
		Stdout:    io.Discard,
		// OpenBrowser intentionally not set — we should fail before reaching it.
	})
	if err == nil {
		t.Fatal("Login on http:// without --insecure: want error, got nil")
	}
	if !strings.Contains(err.Error(), "https") {
		t.Errorf("error should mention https requirement, got %v", err)
	}
}

func TestLogin_StateMismatchIsRejected(t *testing.T) {
	srv := newFakeAuthServer(t)
	defer srv.Close()

	// Synchronously deliver a forged-state callback to the loopback
	// listener and assert the agent's handler rejected it (HTTP 400 with
	// the "State mismatch" error page). Earlier this test fired the
	// tampering GET in a goroutine and only asserted the outer ctx
	// timeout fired — which would also fire even if the handler had
	// happily delivered the bogus code. Synchronous + status assertion
	// pins the actual CSRF-rejection path.
	tamperingBrowser := func(rawURL string) error {
		u, _ := url.Parse(rawURL)
		q := u.Query()
		redirect := q.Get("redirect_uri")
		bogus, _ := url.Parse(redirect)
		bq := bogus.Query()
		bq.Set("code", "anything")
		bq.Set("state", "wrong-state")
		bogus.RawQuery = bq.Encode()
		resp, err := http.Get(bogus.String())
		if err != nil {
			t.Fatalf("tampering GET: %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("forged callback: got HTTP %d, want 400", resp.StatusCode)
		}
		if !strings.Contains(string(body), "State mismatch") {
			t.Fatalf("forged callback body: want 'State mismatch', got %q", string(body))
		}
		return nil
	}

	// Once the handler has dropped the bogus callback, the flow has
	// nothing pending and we expect ctx to time out. The error we
	// surface here means: handler rejected the forgery AND no real
	// callback came through to override it.
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	_, err := Login(ctx, LoginOptions{
		ServerURL:     srv.URL,
		AllowInsecure: true,
		OpenBrowser:   tamperingBrowser,
		Stdout:        io.Discard,
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected ctx.DeadlineExceeded after forged-state rejection, got %v", err)
	}
}

func TestPkce_ChallengeMatchesS256(t *testing.T) {
	verifier, challenge, err := newPkce()
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(verifier))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	if challenge != want {
		t.Fatalf("challenge: got %q, want %q (S256 of verifier)", challenge, want)
	}
	// Verifier should be at least 43 chars per RFC 7636 §4.1.
	if len(verifier) < 43 {
		t.Errorf("verifier length %d, want >= 43 per RFC 7636", len(verifier))
	}
}

func TestCanonicalServer_StripsTrailingSlashAndQuery(t *testing.T) {
	got, err := canonicalServer("HTTPS://APP.SHELLWATCH.AI/?foo=bar#baz", false)
	if err != nil {
		t.Fatal(err)
	}
	want := "https://app.shellwatch.ai"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
