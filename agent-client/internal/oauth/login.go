// SPDX-License-Identifier: MIT
// Package oauth implements how shellwatch-agent authenticates to a ShellWatch
// instance (#217): a loopback authorization_code + PKCE flow (RFC 6749 + 7636 +
// 8252), identical to how an MCP client onboards. The agent registers a public
// client via ShellWatch's mediated DCR, opens the browser for the user to log
// in with a passkey + consent, and exchanges the code for an `agent`-scoped
// access token + (rotating) refresh token. The token carries the user's
// identity; the client is account-agnostic.
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

// LoginTimeout caps how long the loopback listener waits for browser approval.
const LoginTimeout = 5 * time.Minute

// LoginOptions controls a single login flow.
type LoginOptions struct {
	// ServerURL is the ShellWatch instance (scheme + host).
	ServerURL string
	// Scope to request (resource scope; `offline` is added automatically so a
	// refresh token is issued). For shellwatch-agent it's "agent".
	Scope string
	// AllowInsecure permits http:// for local dev.
	AllowInsecure bool
	// OpenBrowser opens a URL; substituted in tests. Defaults to the OS opener.
	OpenBrowser func(url string) error
	// Stdout receives progress messages. nil → io.Discard.
	Stdout io.Writer
}

// Result is what a successful login returns. The caller persists ClientID +
// RefreshToken (the daemon mints access tokens from them).
type Result struct {
	ServerURL    string
	ClientID     string
	RefreshToken string
}

// Login runs the loopback authorization_code + PKCE flow end-to-end.
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

	server, err := canonicalServer(opts.ServerURL, opts.AllowInsecure)
	if err != nil {
		return nil, err
	}
	httpClient := &http.Client{Timeout: 15 * time.Second}
	eps, err := Discover(ctx, httpClient, server)
	if err != nil {
		return nil, fmt.Errorf("discover endpoints: %w", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("bind loopback listener: %w", err)
	}
	defer listener.Close()
	addr := listener.Addr().(*net.TCPAddr)
	redirectURI := fmt.Sprintf("http://127.0.0.1:%d/callback", addr.Port)

	// `offline` → refresh token. The mediated DCR endpoint also adds it to the
	// client's allowed scope, so the authorize request below can request it.
	requestScope := strings.TrimSpace(opts.Scope) + " offline"

	clientID, err := registerClient(ctx, httpClient, eps.Registration, redirectURI, requestScope)
	if err != nil {
		return nil, fmt.Errorf("register client (DCR): %w", err)
	}

	verifier, challenge, err := newPkce()
	if err != nil {
		return nil, fmt.Errorf("generate PKCE: %w", err)
	}
	state, err := randomString(16)
	if err != nil {
		return nil, fmt.Errorf("generate state: %w", err)
	}

	resultCh := make(chan callbackResult, 1)
	srv := &http.Server{Handler: callbackHandler(state, resultCh), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(listener) }()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	authorizeURL := buildAuthorizeURL(eps.Authorization, clientID, redirectURI, requestScope, state, challenge)
	fmt.Fprintf(stdout, "Opening browser to authorize this device:\n  %s\n\n", authorizeURL)
	fmt.Fprintf(stdout, "Waiting for approval (Ctrl-C to cancel)...\n")
	if err := opts.OpenBrowser(authorizeURL); err != nil {
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

	tok, err := postToken(ctx, httpClient, eps.Token, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {cb.code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {verifier},
		"client_id":     {clientID},
	})
	if err != nil {
		return nil, fmt.Errorf("exchange authorization code: %w", err)
	}
	if tok.RefreshToken == "" {
		return nil, errors.New("token response had no refresh_token (offline scope not granted?)")
	}
	return &Result{ServerURL: server, ClientID: clientID, RefreshToken: tok.RefreshToken}, nil
}

// registerClient performs mediated DCR for a public loopback client.
func registerClient(ctx context.Context, client *http.Client, registrationEndpoint, redirectURI, scope string) (string, error) {
	payload := map[string]any{
		"client_name":                "shellwatch-agent",
		"redirect_uris":              []string{redirectURI},
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"scope":                      scope,
		"token_endpoint_auth_method": "none",
	}
	buf, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, registrationEndpoint, strings.NewReader(string(buf)))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("registration returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out struct {
		ClientID string `json:"client_id"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("parse registration response: %w", err)
	}
	if out.ClientID == "" {
		return "", errors.New("registration response missing client_id")
	}
	return out.ClientID, nil
}

func buildAuthorizeURL(authEndpoint, clientID, redirect, scope, state, challenge string) string {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirect)
	q.Set("scope", scope)
	q.Set("state", state)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	return authEndpoint + "?" + q.Encode()
}

type callbackResult struct {
	code string
	err  error
}

// callbackHandler answers the one-shot redirect from the authorization endpoint.
func callbackHandler(state string, resultCh chan<- callbackResult) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("state") != state {
			writeCallbackPage(w, false, "State mismatch — possible CSRF, ignoring this callback.")
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
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) { http.NotFound(w, nil) })
	return mux
}

const callbackPageTemplate = `<!doctype html>
<html lang="en"><head><meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>ShellWatch — %s</title>
<style>
  :root { color-scheme: dark; }
  body { font-family: ui-sans-serif, system-ui, sans-serif; background: #0b0d12; color: #e6e8ee;
    display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }
  .card { background: #141821; border: 1px solid #232a36; border-left: 2px solid %s;
    padding: 2.4rem; max-width: 460px; width: 90%%; box-shadow: 0 0 32px rgba(0,0,0,.4); }
  h1 { font-size: 1.4rem; margin: 0 0 .6rem; color: %s; }
  p { margin: 0; color: #9aa3b2; }
  .hint { margin-top: 1.4rem; font-size: .75rem; text-transform: uppercase; letter-spacing: .14em; color: #6b7280; }
</style></head>
<body><div class="card"><h1>%s</h1><p>%s</p><div class="hint">You can close this tab</div></div></body></html>`

func writeCallbackPage(w http.ResponseWriter, ok bool, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	title, heading, body, accent := "Authorized", "Authorized",
		"This device is now authorized. Return to your terminal — the agent has the token.", "#69f6b8"
	if !ok {
		title, heading, body, accent = "Error", "Authorization failed", htmlEscape(message), "#ff5a5a"
		w.WriteHeader(http.StatusBadRequest)
	}
	fmt.Fprintf(w, callbackPageTemplate, title, accent, accent, heading, body)
}

func newPkce() (verifier, challenge string, err error) {
	verifier, err = randomString(32)
	if err != nil {
		return "", "", err
	}
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

func randomString(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// canonicalServer normalizes a server URL and enforces HTTPS unless insecure.
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
		return "", fmt.Errorf("server URL must use https:// (got %s://); pass --insecure for local dev", scheme)
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

// OpenBrowser launches a URL in the user's default browser (best-effort).
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
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;").Replace(s)
}
