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
	// SPAClientID is the first-party client that auto-consents.
	SPAClientID string
	// SelfRegistrationEnabled + HasPasskeys drive the login page's create-account link.
	SelfRegistrationEnabled bool
	HasPasskeys             func() bool
	// DCR policy.
	AllowedScopes       []string
	RedirectURIPatterns []string
	AgentProxyEnabled   bool
	// Clock injected so the DCR client_id_issued_at is testable (Date.now()).
	Now func() time.Time
}

// mountProviderPages registers the server-rendered GET login/consent/logout
// pages (port of the HTML providers in routes.ts). The passkey ceremony they
// render POSTs to the /options + /verify JSON endpoints.
func mountProviderPages(r chi.Router, p ProviderParams) {
	r.Get("/api/hydra/login", func(w http.ResponseWriter, r *http.Request) {
		challenge := r.URL.Query().Get("login_challenge")
		if challenge == "" {
			writeHTML(w, 400, renderErrorPage("missing_login_challenge", ""))
			return
		}
		lr, err := p.Admin.GetLoginRequest(r.Context(), challenge)
		if err != nil {
			writeHTML(w, 400, renderErrorPage("invalid_login_challenge", ""))
			return
		}
		if lr.Skip {
			// Remembered session — accept without a passkey; mark NOT fresh.
			redir, err := p.Admin.AcceptLoginRequest(r.Context(), challenge, AcceptLogin{
				Subject: lr.Subject, Context: map[string]any{"freshLogin": false},
			})
			if err != nil {
				writeHTML(w, 400, renderErrorPage("login_flow_expired", ""))
				return
			}
			http.Redirect(w, r, redir.RedirectTo, http.StatusFound)
			return
		}
		passkeysExist := p.HasPasskeys == nil || p.HasPasskeys()
		canRegister := !passkeysExist || p.SelfRegistrationEnabled
		desc := "Authenticate with your passkey to continue."
		if !passkeysExist {
			desc = "No passkeys yet — create an account to get started."
		}
		registerURL := ""
		if canRegister {
			registerURL = "/register"
		}
		writeHTML(w, 200, renderPasskeyPage(ceremonyParams{
			Title: "Sign in · ShellWatch", Description: desc,
			OptionsURL: "/api/hydra/login/options", VerifyURL: "/api/hydra/login/verify",
			Extra:      map[string]string{"login_challenge": challenge},
			ShowButton: passkeysExist, RegisterURL: registerURL,
		}))
	})

	r.Get("/api/hydra/consent", func(w http.ResponseWriter, r *http.Request) {
		challenge := r.URL.Query().Get("consent_challenge")
		if challenge == "" {
			writeHTML(w, 400, renderErrorPage("missing_consent_challenge", ""))
			return
		}
		cr, err := p.Admin.GetConsentRequest(r.Context(), challenge)
		if err != nil {
			writeHTML(w, 400, renderErrorPage("invalid_consent_challenge", ""))
			return
		}
		// First-party SPA (and remembered sessions) auto-accept — no second passkey.
		if cr.Client.ClientID == p.SPAClientID || cr.Skip {
			redir, err := p.Admin.AcceptConsentRequest(r.Context(), challenge, AcceptConsent{
				GrantScope: cr.RequestedScope, GrantAccessTokenAudience: cr.RequestedAccessTokenAudience,
			})
			if err != nil {
				writeHTML(w, 400, renderErrorPage("consent_flow_expired", ""))
				return
			}
			http.Redirect(w, r, redir.RedirectTo, http.StatusFound)
			return
		}
		// Third-party: passkey step-up unless the login was fresh (then approve).
		clientName := cr.Client.ClientName
		if clientName == "" {
			clientName = cr.Client.ClientID
		}
		fresh := cr.Context["freshLogin"] == true
		if fresh {
			writeHTML(w, 200, renderApprovePage(approveParams{
				Title: "Authorize · ShellWatch", ApproveURL: "/api/hydra/consent/approve",
				Extra:      map[string]string{"consent_challenge": challenge},
				ClientName: clientName, Scopes: cr.RequestedScope,
			}))
			return
		}
		writeHTML(w, 200, renderPasskeyPage(ceremonyParams{
			Title:      "Authorize · ShellWatch",
			OptionsURL: "/api/hydra/consent/options", VerifyURL: "/api/hydra/consent/verify",
			Extra:      map[string]string{"consent_challenge": challenge},
			ShowButton: true, ClientName: clientName, Scopes: cr.RequestedScope,
		}))
	})
}

func writeHTML(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
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

	mountProviderPages(r, p)
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
