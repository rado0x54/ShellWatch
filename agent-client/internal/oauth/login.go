// Package oauth implements the loopback PKCE flow shellwatch-agent uses to
// obtain an `agent`-scoped API key from a ShellWatch instance.
//
// Wire shape mirrors RFC 6749 + RFC 7636. shellwatch-agent is a public
// client — there's no client secret. Authentication of the user happens on
// the ShellWatch side (passkey login + step-up). The issued token is a
// long-lived `sw_…` API key, not a short-lived OAuth access token; calling
// "OAuth" here is a UX choice (loopback redirect, browser-based consent),
// not a delegated-auth claim.
package oauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// ClientID matches the OAuth shim's STUB_CLIENT_ID. The server doesn't
// verify it strictly (DCR is ceremonial), but sending the right one keeps
// the consent screen's "Client ID" row honest.
const ClientID = "sw-client"

// LoginTimeout caps how long the loopback listener waits for the user to
// approve in the browser. Five minutes is generous enough for passkey
// step-up while bounded enough that a forgotten tab eventually frees the
// port.
const LoginTimeout = 5 * time.Minute

// LoginOptions controls a single login flow.
type LoginOptions struct {
	// ServerURL is the ShellWatch instance to authenticate against. Must
	// include scheme + host (e.g. "https://app.shellwatch.ai").
	ServerURL string
	// Scope is the OAuth scope to request. For shellwatch-agent it's always
	// "agent"; left configurable for future tooling that might need "mcp".
	Scope string
	// AllowInsecure lets the caller use http:// for local dev. Refuses
	// otherwise — sending an API key over plaintext is a footgun.
	AllowInsecure bool
	// OpenBrowser opens a URL in the user's default browser. Substituted in
	// tests; defaults to the OS-native opener.
	OpenBrowser func(url string) error
	// Stdout receives progress messages ("Opening …", "Waiting …"). nil →
	// io.Discard, useful for tests that drive the flow programmatically.
	Stdout io.Writer
}

// Result is what a successful login returns. The caller is responsible for
// persisting AccessToken via the credstore.
type Result struct {
	// AccessToken is the API key the server issued. Long-lived; revocation
	// happens in Settings → API Keys.
	AccessToken string
	// TokenType is always "Bearer" for our shim, but echoed here so callers
	// can match upstream OAuth client expectations.
	TokenType string
	// ServerURL canonicalized (trailing slash trimmed, scheme/host lowercased).
	// Use this as the credstore key, not whatever the user typed on the CLI.
	ServerURL string
}

// Login runs the loopback PKCE flow end-to-end. Blocks until the browser
// callback fires, the timeout elapses, or ctx is cancelled.
func Login(ctx context.Context, opts LoginOptions) (*Result, error) {
	if opts.ServerURL == "" {
		return nil, errors.New("server URL is required")
	}
	if opts.Scope == "" {
		opts.Scope = "agent"
	}
	if opts.OpenBrowser == nil {
		opts.OpenBrowser = OpenBrowser
	}
	stdout := opts.Stdout
	if stdout == nil {
		stdout = io.Discard
	}

	serverURL, err := canonicalServer(opts.ServerURL, opts.AllowInsecure)
	if err != nil {
		return nil, err
	}

	verifier, challenge, err := newPkce()
	if err != nil {
		return nil, fmt.Errorf("generate PKCE: %w", err)
	}
	state, err := randomString(16)
	if err != nil {
		return nil, fmt.Errorf("generate state: %w", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("bind loopback listener: %w", err)
	}
	defer listener.Close()
	addr := listener.Addr().(*net.TCPAddr)
	redirectURI := fmt.Sprintf("http://127.0.0.1:%d/callback", addr.Port)

	authorizeURL := buildAuthorizeURL(serverURL, redirectURI, opts.Scope, state, challenge)

	// Buffered so the handler can deliver a result without blocking on the
	// flow goroutine that hasn't started reading yet.
	resultCh := make(chan callbackResult, 1)
	server := &http.Server{
		Handler:           callbackHandler(state, resultCh),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = server.Serve(listener) }()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	fmt.Fprintf(stdout, "Opening browser to authorize this device:\n  %s\n\n", authorizeURL)
	fmt.Fprintf(stdout, "Waiting for approval (Ctrl-C to cancel)...\n")
	if err := opts.OpenBrowser(authorizeURL); err != nil {
		// Browser open failed — print the URL and let the user paste it manually.
		fmt.Fprintf(stdout, "\nCouldn't open browser automatically (%v).\n", err)
		fmt.Fprintf(stdout, "Open this URL manually: %s\n\n", authorizeURL)
	}

	timeout := time.NewTimer(LoginTimeout)
	defer timeout.Stop()
	var cb callbackResult
	select {
	case cb = <-resultCh:
	case <-timeout.C:
		return nil, fmt.Errorf("timed out after %s waiting for browser approval", LoginTimeout)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if cb.err != nil {
		return nil, cb.err
	}

	token, tokenType, err := exchangeCode(ctx, serverURL, redirectURI, cb.code, verifier)
	if err != nil {
		return nil, fmt.Errorf("exchange authorization code: %w", err)
	}

	return &Result{AccessToken: token, TokenType: tokenType, ServerURL: serverURL}, nil
}

func buildAuthorizeURL(server, redirect, scope, state, challenge string) string {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", ClientID)
	q.Set("redirect_uri", redirect)
	q.Set("scope", scope)
	q.Set("state", state)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	return server + "/oauth/authorize?" + q.Encode()
}

type callbackResult struct {
	code string
	err  error
}

// callbackHandler answers the one-shot redirect from /oauth/authorize. It
// validates state (CSRF), shoves the code (or error) into resultCh, and
// renders a small "you can close this tab" page.
func callbackHandler(state string, resultCh chan<- callbackResult) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		gotState := q.Get("state")
		if gotState != state {
			writeCallbackPage(w, false, "State mismatch — possible CSRF, ignoring this callback.")
			// Don't deliver to resultCh: a stale request shouldn't cancel a real one.
			return
		}
		if errCode := q.Get("error"); errCode != "" {
			desc := q.Get("error_description")
			writeCallbackPage(w, false, fmt.Sprintf("Authorization failed: %s — %s", errCode, desc))
			resultCh <- callbackResult{err: fmt.Errorf("%s: %s", errCode, desc)}
			return
		}
		code := q.Get("code")
		if code == "" {
			writeCallbackPage(w, false, "No authorization code returned.")
			resultCh <- callbackResult{err: errors.New("authorize callback missing 'code' param")}
			return
		}
		writeCallbackPage(w, true, "")
		resultCh <- callbackResult{code: code}
	})
	// Anything else: 404. Browsers sometimes prefetch /favicon.ico etc.;
	// don't let those poison the result channel.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	return mux
}

// callbackPageTemplate is the single HTML shell used for both the success
// and error responses. Style tokens mirror `src/oauth/render.ts` so the
// loopback page reads as part of ShellWatch instead of a generic browser
// dialog. Self-contained — the agent doesn't serve static assets, so
// fonts are pulled from Google Fonts (same as the server-side authorize
// page) and the brand is the wordmark only (no SVG logo).
//
// Placeholders: %s status accent var, %s page title, %s heading,
//
//	%s body paragraph (already HTML-escaped).
const callbackPageTemplate = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>ShellWatch — %s</title>
<link rel="preconnect" href="https://fonts.googleapis.com" />
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Geist:wght@400;500;600;700&family=Geist+Mono:wght@400;500;600&display=swap" />
<style>
  :root {
    --surface-dim: #0e0e0e;
    --surface-container-low: #131313;
    --primary: #69f6b8;
    --primary-dark: #06b77f;
    --error: #ff5a5a;
    --on-surface: #f2f2f2;
    --on-surface-variant: #adaaaa;
    --font-display: "Geist", system-ui, sans-serif;
    --font-mono: "Geist Mono", ui-monospace, monospace;
  }
  *, *::before, *::after { box-sizing: border-box; border-radius: 0 !important; }
  html, body { height: 100%%; margin: 0; }
  body {
    font-family: var(--font-display);
    background: var(--surface-dim);
    color: var(--on-surface);
    line-height: 1.5;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 2rem 1rem;
    -webkit-font-smoothing: antialiased;
  }
  .card {
    background: var(--surface-container-low);
    padding: 2.4rem;
    width: 100%%;
    max-width: 460px;
    border-left: 2px solid %s;
    box-shadow: 0 0 32px rgba(0, 0, 0, 0.4);
  }
  .wordmark {
    font-family: var(--font-display);
    font-size: 1.1rem;
    font-weight: 600;
    letter-spacing: 0.02em;
    text-transform: uppercase;
    margin-bottom: 1.6rem;
  }
  .wordmark .shell { color: var(--primary-dark); }
  .wordmark .watch { color: #f0efea; }
  h1 {
    font-family: var(--font-display);
    font-size: 1.5rem;
    font-weight: 600;
    letter-spacing: -0.02em;
    margin: 0 0 0.6rem;
    color: %s;
  }
  p { margin: 0; color: var(--on-surface-variant); font-size: 0.95rem; }
  .hint {
    font-family: var(--font-mono);
    font-size: 0.75rem;
    color: var(--on-surface-variant);
    margin-top: 1.4rem;
    text-transform: uppercase;
    letter-spacing: 0.14em;
  }
</style>
</head>
<body>
<div class="card">
  <div class="wordmark"><span class="shell">SHELL</span><span class="watch">WATCH</span></div>
  <h1>%s</h1>
  <p>%s</p>
  <div class="hint">You can close this tab</div>
</div>
</body>
</html>`

func writeCallbackPage(w http.ResponseWriter, ok bool, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	var (
		title, heading, body, accent string
	)
	if ok {
		title = "Authorized"
		heading = "Authorized"
		body = "This device is now authorized. Return to your terminal — the agent has the token."
		accent = "var(--primary)"
	} else {
		title = "Error"
		heading = "Authorization failed"
		body = htmlEscape(message)
		accent = "var(--error)"
		w.WriteHeader(http.StatusBadRequest)
	}
	fmt.Fprintf(w, callbackPageTemplate, title, accent, accent, heading, body)
}

// exchangeCode redeems the authorization code at /oauth/token for an API key.
func exchangeCode(ctx context.Context, server, redirectURI, code, verifier string) (string, string, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("code_verifier", verifier)
	form.Set("client_id", ClientID)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, server+"/oauth/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode != http.StatusOK {
		// Surface the OAuth error fields if the server gave us JSON; fall
		// back to body text otherwise so debugging isn't blind.
		var oauthErr struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		if json.Unmarshal(body, &oauthErr) == nil && oauthErr.Error != "" {
			return "", "", fmt.Errorf("token endpoint returned %s: %s", oauthErr.Error, oauthErr.ErrorDescription)
		}
		return "", "", fmt.Errorf("token endpoint returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var tok struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return "", "", fmt.Errorf("parse token response: %w", err)
	}
	if tok.AccessToken == "" {
		return "", "", errors.New("token response missing access_token")
	}
	return tok.AccessToken, tok.TokenType, nil
}

// newPkce returns (verifier, S256 challenge). Verifier is 32 random bytes
// base64url-encoded — exactly 43 chars, which is RFC 7636 §4.1's minimum.
func newPkce() (verifier, challenge string, err error) {
	verifier, err = randomString(32)
	if err != nil {
		return "", "", err
	}
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge, nil
}

func randomString(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// canonicalServer mirrors credstore.CanonicalizeServerURL but also enforces
// HTTPS unless the caller opts into insecure mode (local dev only).
func canonicalServer(raw string, allowInsecure bool) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid server URL: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("server URL must include scheme and host")
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" && !allowInsecure {
		return "", fmt.Errorf("server URL must use https:// (got %s://); pass --insecure to override for local dev", scheme)
	}
	if scheme != "https" && scheme != "http" {
		return "", fmt.Errorf("server URL scheme must be http or https (got %s)", scheme)
	}
	u.Scheme = scheme
	u.Host = strings.ToLower(u.Host)
	u.Path = strings.TrimRight(u.Path, "/")
	u.Fragment = ""
	u.RawQuery = ""
	return u.String(), nil
}

// OpenBrowser launches a URL in the user's default browser. Pure best-effort
// — failure paths (no GUI, headless server) are surfaced to the caller so
// it can fall back to printing the URL.
func OpenBrowser(rawURL string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", rawURL).Start()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", rawURL).Start()
	default:
		return exec.Command("xdg-open", rawURL).Start()
	}
}

func htmlEscape(s string) string {
	r := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&quot;",
		"'", "&#39;",
	)
	return r.Replace(s)
}
