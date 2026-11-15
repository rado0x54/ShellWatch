// SPDX-License-Identifier: MIT
// Token sourcing for shellwatch-agent (#217). The agent authenticates exactly
// like an MCP client: a loopback authorization_code + PKCE flow (see login.go)
// where the user logs in with a passkey. That yields a user-delegated,
// `agent`-scoped access token plus a (rotating) refresh token. At runtime the
// daemon mints fresh access tokens from the stored refresh token and persists
// each rotation.
package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// StoredCreds is what the credstore holds per server: the client id the token
// was issued to, the authorization server (issuer) that issued it, and the
// latest refresh token.
//
// Issuer is empty for credentials stored before #256 (DCR-era logins). Those
// keep working unbound until the next `login` records one.
type StoredCreds struct {
	Issuer       string `json:"issuer,omitempty"`
	ClientID     string `json:"client_id"`
	RefreshToken string `json:"refresh_token"`
}

func (c StoredCreds) Encode() (string, error) {
	b, err := json.Marshal(c)
	return string(b), err
}

// DecodeCreds parses a credstore value. ok=false for legacy/raw values so the
// caller can treat them as a static bearer token.
func DecodeCreds(s string) (StoredCreds, bool) {
	var c StoredCreds
	if json.Unmarshal([]byte(s), &c) == nil && c.ClientID != "" && c.RefreshToken != "" {
		return c, true
	}
	return StoredCreds{}, false
}

// Tokener yields a bearer token for the /agent-proxy WebSocket.
type Tokener interface {
	Token() (string, error)
}

// StaticToken is a fixed bearer — a token passed via --token / SHELLWATCH_TOKEN.
type StaticToken string

func (s StaticToken) Token() (string, error) {
	if s == "" {
		return "", errors.New("empty token")
	}
	return string(s), nil
}

const tokenRefreshSkew = 60 * time.Second

// ErrIssuerChanged means the server now advertises a different authorization
// server than the one the stored credentials were issued by.
var ErrIssuerChanged = errors.New("authorization server changed since login")

// RefreshTokenSource mints + caches access tokens from a stored refresh token
// (refresh_token grant), persisting each rotated refresh token via onRotate.
type RefreshTokenSource struct {
	serverURL     string
	issuer        string
	clientID      string
	refreshToken  string
	allowInsecure bool
	onRotate      func(refreshToken string)
	httpClient    *http.Client

	mu     sync.Mutex
	cached string
	expiry time.Time
}

// RefreshTokenSourceParams configures NewRefreshTokenSource.
type RefreshTokenSourceParams struct {
	ServerURL string
	// Creds are the stored credentials. A non-empty Creds.Issuer must equal
	// the issuer the server advertises, or Token fails with ErrIssuerChanged.
	Creds         StoredCreds
	AllowInsecure bool
	// OnRotate persists each rotated refresh token.
	OnRotate func(refreshToken string)
}

func NewRefreshTokenSource(p RefreshTokenSourceParams) *RefreshTokenSource {
	return &RefreshTokenSource{
		serverURL:     p.ServerURL,
		issuer:        p.Creds.Issuer,
		clientID:      p.Creds.ClientID,
		refreshToken:  p.Creds.RefreshToken,
		allowInsecure: p.AllowInsecure,
		onRotate:      p.OnRotate,
		httpClient:    &http.Client{Timeout: 15 * time.Second},
	}
}

func (s *RefreshTokenSource) Token() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cached != "" && time.Until(s.expiry) > tokenRefreshSkew {
		return s.cached, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	eps, err := Discover(ctx, s.httpClient, s.serverURL)
	if err != nil {
		return "", fmt.Errorf("discover endpoints: %w", err)
	}
	// Never present a refresh token to an authorization server other than the
	// one that issued it.
	if s.issuer != "" && eps.Issuer != s.issuer {
		return "", fmt.Errorf("%w (was %s, now %s): run `shellwatch-agent login --server %s` again",
			ErrIssuerChanged, s.issuer, eps.Issuer, s.serverURL)
	}
	tok, err := postToken(ctx, s.httpClient, eps.Token, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {s.refreshToken},
		"client_id":     {s.clientID},
	})
	if err != nil {
		return "", err
	}
	if tok.RefreshToken != "" && tok.RefreshToken != s.refreshToken {
		s.refreshToken = tok.RefreshToken
		if s.onRotate != nil {
			s.onRotate(tok.RefreshToken)
		}
	}
	s.cached = tok.AccessToken
	expiresIn := tok.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = 300
	}
	s.expiry = time.Now().Add(time.Duration(expiresIn) * time.Second)
	return s.cached, nil
}

// Endpoints is the subset of ShellWatch's OAuth discovery doc the agent uses.
type Endpoints struct {
	Issuer        string `json:"issuer"`
	Authorization string `json:"authorization_endpoint"`
	Token         string `json:"token_endpoint"`
	// Registration is only used by `login --dcr`.
	Registration string `json:"registration_endpoint"`
	// ClientIDMetadataDocumentSupported is the CIMD draft's §6 flag; the agent
	// does not fall back to DCR without it unless `login --dcr` is given.
	ClientIDMetadataDocumentSupported bool `json:"client_id_metadata_document_supported"`
}

// Discover reads ShellWatch's authorization-server metadata.
func Discover(ctx context.Context, client *http.Client, serverURL string) (Endpoints, error) {
	var eps Endpoints
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, serverURL+"/.well-known/oauth-authorization-server", nil)
	if err != nil {
		return eps, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return eps, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode != http.StatusOK {
		return eps, fmt.Errorf("discovery returned HTTP %d", resp.StatusCode)
	}
	if err := json.Unmarshal(body, &eps); err != nil {
		return eps, fmt.Errorf("parse discovery doc: %w", err)
	}
	if eps.Issuer == "" || eps.Authorization == "" || eps.Token == "" {
		return eps, errors.New("discovery doc missing issuer/authorization/token endpoint")
	}
	return eps, nil
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
}

// postToken POSTs a form to a token endpoint and parses the OAuth token response.
func postToken(ctx context.Context, client *http.Client, tokenEndpoint string, form url.Values) (tokenResponse, error) {
	var out tokenResponse
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return out, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode != http.StatusOK {
		var oauthErr struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		if json.Unmarshal(body, &oauthErr) == nil && oauthErr.Error != "" {
			return out, fmt.Errorf("token endpoint returned %s: %s", oauthErr.Error, oauthErr.ErrorDescription)
		}
		return out, fmt.Errorf("token endpoint returned HTTP %d", resp.StatusCode)
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return out, fmt.Errorf("parse token response: %w", err)
	}
	if out.AccessToken == "" {
		return out, errors.New("token response missing access_token")
	}
	return out, nil
}
