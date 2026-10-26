// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Hydra provider JSON endpoints + mediated DCR (port of src/hydra/routes.ts).
// Slice 3 covers the login provider's options/verify JSON endpoints (the
// webauthn-login-verify golden) and the /api/hydra/register DCR policy. The
// GET HTML landing pages (login/consent/logout) are HTML/redirect flows, not
// schema-documented (docs/api/README.md), and land with render.ts later.
package hydra

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/rado0x54/shellwatch/internal/apierr"
	"github.com/rado0x54/shellwatch/internal/clock"
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
	// OnEvent records the registration in the non-account-scoped client log
	// (see clientevents.go). nil drops events.
	OnEvent ClientEventSink
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
		// A URL client_id (CIMD) never takes the silent path: its metadata
		// document can change at any time, so the human re-approves every
		// authorization and sees who they are approving.
		//
		// This refuses `skip`, NOT `remember`. The grant is still remembered on
		// accept, because the remembered consent session is what lists the
		// client under Settings -> Authorized clients and makes it revocable;
		// dropping that would hide CIMD clients from the one screen where a
		// user can cut them off.
		identity := p.cimdIdentity(r.Context(), cr.Client)

		// First-party SPA (and remembered sessions) auto-accept — no second
		// passkey. remember/remember_for keep the SPA client in "Authorized
		// clients" and renew remembered skips (routes.ts:360-370, M13).
		if cr.Client.ClientID == p.SPAClientID || (cr.Skip && identity == nil) {
			redir, err := p.Admin.AcceptConsentRequest(r.Context(), challenge, AcceptConsent{
				GrantScope: cr.RequestedScope, GrantAccessTokenAudience: cr.RequestedAccessTokenAudience,
				Remember: true, RememberFor: rememberFor,
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
		if clientName == "" && identity == nil {
			// DCR clients without a name fall back to their opaque id; a CIMD
			// client already shows its hostname, so repeating the URL adds
			// nothing.
			clientName = cr.Client.ClientID
		}
		fresh := cr.Context["freshLogin"] == true
		if fresh {
			writeHTML(w, 200, renderApprovePage(approveParams{
				Title: "Authorize · ShellWatch", ApproveURL: "/api/hydra/consent/approve",
				Extra:      map[string]string{"consent_challenge": challenge},
				ClientName: clientName, Scopes: cr.RequestedScope, Identity: identity,
			}))
			return
		}
		writeHTML(w, 200, renderPasskeyPage(ceremonyParams{
			Title:      "Authorize · ShellWatch",
			OptionsURL: "/api/hydra/consent/options", VerifyURL: "/api/hydra/consent/verify",
			Extra:      map[string]string{"consent_challenge": challenge},
			ShowButton: true, ClientName: clientName, Scopes: cr.RequestedScope,
			Identity: identity,
		}))
	})
}

func mountLogoutError(r chi.Router, p ProviderParams) {
	// Logout is forgiving: land on "/" on a missing/stale challenge, and reject
	// an unhinted (CSRF) logout that Hydra can't attribute to a client.
	r.Get("/api/hydra/logout", func(w http.ResponseWriter, r *http.Request) {
		challenge := r.URL.Query().Get("logout_challenge")
		if challenge == "" {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		lr, err := p.Admin.GetLogoutRequest(r.Context(), challenge)
		if err != nil {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		if lr.Client == nil || lr.Client.ClientID == "" {
			_ = p.Admin.RejectLogoutRequest(r.Context(), challenge)
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		redir, err := p.Admin.AcceptLogoutRequest(r.Context(), challenge)
		if err != nil {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		http.Redirect(w, r, redir.RedirectTo, http.StatusFound)
	})

	// Hydra error landing page (post_logout / flow errors surface here).
	r.Get("/api/hydra/error", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		errMsg := q.Get("error")
		if errMsg == "" {
			errMsg = "error"
		}
		writeHTML(w, 200, renderErrorPage(errMsg, q.Get("error_description")))
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
			apierr.Write(w, 500, "internal error")
			return
		}
		if !ok {
			apierr.Write(w, 200, "no_passkeys")
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
			apierr.Write(w, 400, "missing login_challenge")
			return
		}
		var assertion struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(body.Credential, &assertion)

		res := p.WebAuthn.VerifyLogin(r.Context(), body.ChallengeID, assertion.ID, body.Credential)
		if res.Error != "" {
			apierr.Write(w, res.Status, res.Error)
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
			apierr.Write(w, 400, "login_flow_expired")
			return
		}
		writeJSONStatus(w, 200, map[string]string{"redirectTo": redirect.RedirectTo})
	})

	r.Post("/api/hydra/register", func(w http.ResponseWriter, r *http.Request) {
		p.handleDCR(w, r, patterns, allowed, now)
	})

	// Third-party consent JSON endpoints (account-bound passkey step-up, or the
	// fresh-login approve shortcut). The first-party SPA auto-consents via the
	// GET page and never reaches these.
	r.Post("/api/hydra/consent/options", p.consentOptions)
	r.Post("/api/hydra/consent/verify", p.consentVerify)
	r.Post("/api/hydra/consent/approve", p.consentApprove)

	mountProviderPages(r, p)
	mountLogoutError(r, p)
}

// cimdIdentity builds the consent-page identity for a URL client_id, or nil
// when the client is not CIMD-shaped (the SPA, every DCR client).
//
// Detection is on the client_id's shape rather than on
// metadata.shellwatch.origin, so an operator-created client that happens to use
// a URL id gets the same hostname-first treatment — for a URL identity that is
// the right thing to show either way.
func (p ProviderParams) cimdIdentity(ctx context.Context, c OAuth2Client) *clientIdentity {
	if !IsClientIDURL(c.ClientID) {
		return nil
	}
	id := &clientIdentity{Host: hostOf(c.ClientID)}
	if h := hostOf(c.ClientURI); h != "" && h != id.Host {
		id.ClientURIHost = h
	}
	meta := c.Metadata
	if meta == nil && p.Admin != nil {
		// Hydra's consent request may not echo the client's metadata object;
		// read the client when it is missing, so the "recently changed" hint
		// does not silently disappear.
		if full, err := p.Admin.GetClient(ctx, c.ClientID); err == nil && full != nil {
			meta = full.Metadata
			if id.ClientURIHost == "" {
				if h := hostOf(full.ClientURI); h != "" && h != id.Host {
					id.ClientURIHost = h
				}
			}
		}
	}
	sw, _ := meta["shellwatch"].(map[string]any)
	if sw == nil {
		return id
	}
	// fetched_at only moves when ShellWatch creates or updates the client — a
	// cache hit on an unchanged document writes nothing — so a recent value
	// means "new or just changed", which is what the hint claims.
	raw, _ := sw["fetched_at"].(string)
	if t, err := time.Parse(clock.ISOMillis, raw); err == nil && p.nowTime().Sub(t) < time.Hour {
		id.Recent = true
	}
	return id
}

// nowTime is ProviderParams.Now with the time.Now default applied.
func (p ProviderParams) nowTime() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

func (p ProviderParams) consentOptions(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ConsentChallenge string `json:"consent_challenge"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body.ConsentChallenge == "" {
		apierr.Write(w, 400, "missing consent_challenge")
		return
	}
	cr, err := p.Admin.GetConsentRequest(r.Context(), body.ConsentChallenge)
	if err != nil {
		apierr.Write(w, 400, "invalid consent_challenge")
		return
	}
	opts, ok, err := p.WebAuthn.ConsentOptions(r.Context(), cr.Subject)
	if err != nil {
		apierr.Write(w, 500, "internal error")
		return
	}
	if !ok {
		apierr.Write(w, 200, "no_passkeys")
		return
	}
	writeJSONStatus(w, 200, opts)
}

func (p ProviderParams) consentVerify(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ConsentChallenge string          `json:"consent_challenge"`
		ChallengeID      string          `json:"challengeId"`
		Credential       json.RawMessage `json:"credential"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body.ConsentChallenge == "" {
		apierr.Write(w, 400, "missing consent_challenge")
		return
	}
	cr, err := p.Admin.GetConsentRequest(r.Context(), body.ConsentChallenge)
	if err != nil {
		apierr.Write(w, 400, "invalid consent_challenge")
		return
	}
	var assertion struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(body.Credential, &assertion)
	res := p.WebAuthn.VerifyConsent(r.Context(), body.ChallengeID, assertion.ID, body.Credential, cr.Subject)
	if res.Error != "" {
		apierr.Write(w, res.Status, res.Error)
		return
	}
	p.acceptConsentAndRedirect(w, r, body.ConsentChallenge, cr)
}

func (p ProviderParams) consentApprove(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ConsentChallenge string `json:"consent_challenge"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body.ConsentChallenge == "" {
		apierr.Write(w, 400, "missing consent_challenge")
		return
	}
	cr, err := p.Admin.GetConsentRequest(r.Context(), body.ConsentChallenge)
	if err != nil {
		apierr.Write(w, 400, "invalid consent_challenge")
		return
	}
	// The no-passkey approve shortcut is only valid when THIS flow's login was a
	// fresh passkey ceremony (stamped into the login context).
	if cr.Context["freshLogin"] != true {
		apierr.Write(w, 400, "passkey_required")
		return
	}
	p.acceptConsentAndRedirect(w, r, body.ConsentChallenge, cr)
}

func (p ProviderParams) acceptConsentAndRedirect(w http.ResponseWriter, r *http.Request, challenge string, cr ConsentRequest) {
	redirect, err := p.Admin.AcceptConsentRequest(r.Context(), challenge, AcceptConsent{
		GrantScope: cr.RequestedScope, GrantAccessTokenAudience: cr.RequestedAccessTokenAudience,
		Remember: true, RememberFor: rememberFor,
	})
	if err != nil {
		apierr.Write(w, 400, "consent_flow_expired")
		return
	}
	writeJSONStatus(w, 200, map[string]string{"redirectTo": redirect.RedirectTo})
}

func (p ProviderParams) handleDCR(w http.ResponseWriter, r *http.Request, patterns []*regexp.Regexp, allowed map[string]bool, now func() time.Time) {
	var body struct {
		RedirectURIs []string `json:"redirect_uris"`
		Scope        string   `json:"scope"`
		ClientName   string   `json:"client_name"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)

	if len(body.RedirectURIs) == 0 {
		apierr.WriteOAuth(w, 400, "invalid_redirect_uri", "redirect_uris is required")
		return
	}
	for _, uri := range body.RedirectURIs {
		if !matchAny(patterns, uri) {
			apierr.WriteOAuth(w, 400, "invalid_redirect_uri", "redirect_uri not allowed by policy: "+uri)
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
		apierr.WriteOAuth(w, 400, "invalid_scope", "scope must be a subset of: "+strings.Join(keys(allowed), " "))
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
		// Stamp the origin so an admin reading Hydra's client list can tell a
		// DCR client from a CIMD one (clients registered before this landed
		// have an empty metadata object and read as origin unknown).
		Metadata: map[string]any{
			"shellwatch": map[string]any{"origin": ClientOriginDCR},
		},
	})
	if err != nil {
		if p.OnEvent != nil {
			p.OnEvent(r, ClientEvent{
				Origin: ClientOriginDCR, Event: ClientEventRejected,
				ClientName: clientName, RedirectURIs: body.RedirectURIs,
				Scope: clientScope, Reason: "server_error: client registration failed",
			})
		}
		apierr.WriteOAuth(w, 502, "server_error", "client registration failed")
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
	if p.OnEvent != nil {
		p.OnEvent(r, ClientEvent{
			ClientID: created.ClientID, Origin: ClientOriginDCR,
			Event: ClientEventRegistered, ClientName: clientName,
			AuthMethod: "none", RedirectURIs: redirectURIs, Scope: scope,
		})
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

// writeJSONStatus renders success payloads; error envelopes go through
// internal/apierr.
func writeJSONStatus(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
