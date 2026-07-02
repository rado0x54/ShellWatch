// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Hydra provider JSON endpoints + mediated DCR (port of src/hydra/routes.ts).
// Slice 3 covers the login provider's options/verify JSON endpoints (the
// webauthn-login-verify golden) and the /api/hydra/register DCR policy. The
// GET HTML landing pages (login/consent/logout) are HTML/redirect flows, not
// schema-documented (docs/api/README.md), and land with render.ts later.
package hydra

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/rado0x54/shellwatch/internal/webauthn"
)

// rememberFor is REMEMBER_FOR: 30 days.
const rememberFor = 60 * 60 * 24 * 30

// ProviderParams wires the login provider + DCR.
type ProviderParams struct {
	Admin    Admin
	WebAuthn *webauthn.Deps
	// DCR policy.
	AllowedScopes       []string
	RedirectURIPatterns []string
	AgentProxyEnabled   bool
	// Clock injected so the DCR client_id_issued_at is testable (Date.now()).
	Now func() time.Time
}

// MountProviders registers the login-provider JSON endpoints and mediated DCR.
func MountProviders(r chi.Router, p ProviderParams) {
	patterns := make([]*regexp.Regexp, 0, len(p.RedirectURIPatterns))
	for _, src := range p.RedirectURIPatterns {
		if re, err := regexp.Compile(src); err == nil {
			patterns = append(patterns, re)
		}
	}
	allowed := map[string]bool{}
	for _, s := range p.AllowedScopes {
		if s == "agent" && !p.AgentProxyEnabled {
			continue
		}
		allowed[s] = true
	}
	now := p.Now
	if now == nil {
		now = time.Now
	}

	r.Post("/api/hydra/login/options", func(w http.ResponseWriter, r *http.Request) {
		opts, ok, err := p.WebAuthn.LoginOptions(r.Context())
		if err != nil {
			writeJSONStatus(w, 500, map[string]string{"error": "internal error"})
			return
		}
		if !ok {
			writeJSONStatus(w, 200, map[string]string{"error": "no_passkeys"})
			return
		}
		writeJSONStatus(w, 200, opts)
	})

	r.Post("/api/hydra/login/verify", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			LoginChallenge string          `json:"login_challenge"`
			ChallengeID    string          `json:"challengeId"`
			Credential     json.RawMessage `json:"credential"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.LoginChallenge == "" {
			writeJSONStatus(w, 400, map[string]string{"error": "missing login_challenge"})
			return
		}
		var assertion struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(body.Credential, &assertion)

		res := p.WebAuthn.VerifyLogin(r.Context(), body.ChallengeID, assertion.ID, body.Credential)
		if res.Error != "" {
			writeJSONStatus(w, res.Status, map[string]string{"error": res.Error})
			return
		}
		redirect, err := p.Admin.AcceptLoginRequest(r.Context(), body.LoginChallenge, AcceptLogin{
			Subject:     res.AccountID,
			Remember:    true,
			RememberFor: rememberFor,
			Context:     map[string]any{"freshLogin": true},
		})
		if err != nil {
			// A stale challenge after a burned assertion is a clean restart,
			// not a 500 (guarded-admin behavior in routes.ts).
			writeJSONStatus(w, 400, map[string]string{"error": "login_flow_expired"})
			return
		}
		writeJSONStatus(w, 200, map[string]string{"redirectTo": redirect.RedirectTo})
	})

	r.Post("/api/hydra/register", func(w http.ResponseWriter, r *http.Request) {
		p.handleDCR(w, r, patterns, allowed, now)
	})
}

func (p ProviderParams) handleDCR(w http.ResponseWriter, r *http.Request, patterns []*regexp.Regexp, allowed map[string]bool, now func() time.Time) {
	var body struct {
		RedirectURIs []string `json:"redirect_uris"`
		Scope        string   `json:"scope"`
		ClientName   string   `json:"client_name"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)

	if len(body.RedirectURIs) == 0 {
		writeDCRErr(w, 400, "invalid_redirect_uri", "redirect_uris is required")
		return
	}
	for _, uri := range body.RedirectURIs {
		if !matchAny(patterns, uri) {
			writeDCRErr(w, 400, "invalid_redirect_uri", "redirect_uri not allowed by policy: "+uri)
			return
		}
	}

	requested := []string{"mcp"}
	if s := strings.TrimSpace(body.Scope); s != "" {
		requested = strings.Fields(s)
	}
	granted := make([]string, 0, len(requested))
	for _, s := range requested {
		if allowed[s] {
			granted = append(granted, s)
		}
	}
	if len(granted) == 0 {
		writeDCRErr(w, 400, "invalid_scope", "scope must be a subset of: "+strings.Join(keys(allowed), " "))
		return
	}

	clientName := body.ClientName
	if clientName == "" {
		clientName = "MCP Client"
	}
	clientScope := strings.Join(append(granted, "offline_access"), " ")
	created, err := p.Admin.CreateClient(r.Context(), OAuth2Client{
		ClientName:              clientName,
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		Scope:                   clientScope,
		RedirectURIs:            body.RedirectURIs,
		TokenEndpointAuthMethod: "none",
	})
	if err != nil {
		writeDCRErr(w, 502, "server_error", "client registration failed")
		return
	}
	redirectURIs := created.RedirectURIs
	if len(redirectURIs) == 0 {
		redirectURIs = body.RedirectURIs
	}
	scope := created.Scope
	if scope == "" {
		scope = clientScope
	}
	writeJSONStatus(w, 201, map[string]any{
		"client_id":                  created.ClientID,
		"client_id_issued_at":        now().Unix(),
		"token_endpoint_auth_method": "none",
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"redirect_uris":              redirectURIs,
		"scope":                      scope,
		"client_name":                clientName,
	})
}

func matchAny(patterns []*regexp.Regexp, s string) bool {
	for _, re := range patterns {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func writeJSONStatus(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeDCRErr(w http.ResponseWriter, status int, code, desc string) {
	writeJSONStatus(w, status, map[string]string{"error": code, "error_description": desc})
}
