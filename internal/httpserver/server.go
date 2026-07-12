// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Package httpserver assembles the chi router: middleware stack (bearer
// gate, IP allowlist for /mcp), the stateless meta endpoints, discovery
// docs, and SPA static serving. The hand-written REST handlers
// (internal/rest, marshaling internal/api model types) mount here.
package httpserver

import (
	"encoding/json"
	"io"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/rado0x54/shellwatch/internal/clock"

	"github.com/rado0x54/shellwatch/internal/agentproxy"
	"github.com/rado0x54/shellwatch/internal/auth"
	"github.com/rado0x54/shellwatch/internal/buildinfo"
	"github.com/rado0x54/shellwatch/internal/config"
	"github.com/rado0x54/shellwatch/internal/hydra"
	"github.com/rado0x54/shellwatch/internal/mcp"
	"github.com/rado0x54/shellwatch/internal/ratelimit"
	"github.com/rado0x54/shellwatch/internal/realip"
	"github.com/rado0x54/shellwatch/internal/rest"
	"github.com/rado0x54/shellwatch/internal/webauthn"
	"github.com/rado0x54/shellwatch/internal/ws"
)

type Params struct {
	Config  *config.Config
	Resolve auth.Resolver
	// TouchLastUsed records authenticated activity (nil-able in tests).
	TouchLastUsed func(accountID string)
	StaticFS      fs.FS
	BuildInfo     buildinfo.Info
	// WebAuthn mounts the ceremony routes (nil-able: omitted in the
	// slice-1 discovery-only tests).
	WebAuthn *webauthn.Deps
	// HydraAdmin enables the login provider + mediated DCR (nil-able).
	HydraAdmin hydra.Admin
	// HasPasskeys reports whether any passkey exists (drives the login page's
	// create-account link). nil -> assume passkeys exist.
	HasPasskeys func() bool
	// Endpoints mounts the endpoint CRUD routes (nil-able).
	Endpoints *rest.Endpoints
	// Sessions mounts the session routes (nil-able).
	Sessions *rest.Sessions
	// WSHub mounts the /ws terminal WebSocket (nil-able).
	WSHub *ws.Hub
	// MCP mounts the /mcp streamable-HTTP surface (nil-able).
	MCP *mcp.Deps
	// Actions mounts the pending-action resolve/deny routes (nil-able).
	Actions *rest.Actions
	// AgentProxy mounts /agent-proxy (nil-able; also gated on proxyEnabled).
	AgentProxy *agentproxy.Deps
	// Audit mounts the audit read routes (nil-able).
	Audit *rest.Audit
	// Accounts, Credentials, Keys, AuthSessions, Push mount the account/auth
	// self-service + admin REST surfaces (nil-able).
	Accounts     *rest.Accounts
	Credentials  *rest.Credentials
	Keys         *rest.Keys
	AuthSessions *rest.AuthSessions
	Push         *rest.Push
}

// New builds the router. ExternalURL is read from Config at request time so
// test harnesses can pin it after boot (same trick as the Node helpers).
func New(p Params) http.Handler {
	externalURL := func() string { return p.Config.Server.ExternalURL }
	agentProxy := p.Config.AgentSocket.ProxyEnabled

	r := chi.NewRouter()
	// Outermost: log every request (method/path/status/duration) so 4xx/5xx are
	// visible in stdout / the log file, not just the response body.
	r.Use(requestLogger(clock.Real{}))
	// server.trustProxy: resolve the effective client IP once; every consumer
	// (audit sourceIp, /mcp allowlist, rate limits) reads it from the context.
	r.Use(realip.New(p.Config.Server.TrustProxy).Middleware)
	// CORS before the bearer gate so cross-origin preflights don't 401.
	r.Use(corsMiddleware)
	// Rate limits on the unauthenticated surfaces, before the gate (they're
	// exempt from it) — port of the per-route @fastify/rate-limit configs.
	r.Use(ratelimit.Middleware(rateLimitRules(p.Config)))
	r.Use(auth.Gate(auth.GateParams{
		Resolve:           p.Resolve,
		ExternalURL:       externalURL,
		AgentProxyEnabled: agentProxy,
		TouchLastUsed:     p.TouchLastUsed,
	}))

	// Stateless meta endpoints (health.json golden; /api/version).
	r.Get("/health", jsonHandler(map[string]string{"status": "ok"}))
	r.Get("/api/version", jsonHandler(p.BuildInfo))

	// Browser bootstrap config (JS, not JSON): the SPA reads window.__OAUTH__
	// etc. from here to start its PKCE flow (port of app.ts /config.js).
	r.Get("/config.js", configJS(p.Config, p.BuildInfo))

	hydra.MountDiscovery(r, hydra.DiscoveryParams{
		ExternalURL:       externalURL,
		HydraPublicURL:    p.Config.Hydra.PublicURL,
		AgentProxyEnabled: agentProxy,
	})

	if p.WebAuthn != nil {
		p.WebAuthn.Mount(r)
	}

	if p.HydraAdmin != nil && p.WebAuthn != nil {
		hydra.MountProviders(r, hydra.ProviderParams{
			Admin:                   p.HydraAdmin,
			WebAuthn:                p.WebAuthn,
			SPAClientID:             p.Config.Hydra.Spa.ClientID,
			SelfRegistrationEnabled: p.Config.Security.SelfRegistrationEnabled,
			HasPasskeys:             p.HasPasskeys,
			AllowedScopes:           p.Config.Hydra.Dcr.AllowedScopes,
			RedirectURIPatterns:     p.Config.Hydra.Dcr.RedirectURIPatterns,
			AgentProxyEnabled:       agentProxy,
		})
	}

	if p.Endpoints != nil {
		p.Endpoints.Mount(r)
	}
	if p.Sessions != nil {
		p.Sessions.Mount(r)
	}
	if p.Actions != nil {
		p.Actions.Mount(r)
	}
	if p.Audit != nil {
		p.Audit.Mount(r)
	}
	if p.Accounts != nil {
		p.Accounts.Mount(r)
	}
	if p.Credentials != nil {
		p.Credentials.Mount(r)
	}
	if p.Keys != nil {
		p.Keys.Mount(r)
	}
	if p.AuthSessions != nil {
		p.AuthSessions.Mount(r)
	}
	if p.Push != nil {
		p.Push.Mount(r)
	}
	if p.WSHub != nil {
		r.Get("/ws", p.WSHub.Handler())
	}
	if p.MCP != nil {
		// /mcp is gated by scope AND a CIDR allowlist (auth model), defaulting
		// to localhost.
		ipGate := auth.NewIPChecker(p.Config.Security.AllowedNetworks).Middleware
		mcpHandler := ipGate(p.MCP.Handler())
		r.Handle("/mcp", mcpHandler)
		r.Handle("/mcp/*", mcpHandler)
	}
	if p.AgentProxy != nil && agentProxy {
		r.Get("/agent-proxy", p.AgentProxy.Handler())
	}

	// SPA: exact static files, fallback to index.html for client routes.
	r.NotFound(spaHandler(p.StaticFS))
	return r
}

// rateLimitRules maps security.rateLimit onto the exact routes Node limits
// (self-register, invites, hydra provider options/verify, step-up, DCR). Each
// route gets its own counter, mirroring per-route @fastify/rate-limit stores.
func rateLimitRules(cfg *config.Config) []ratelimit.Rule {
	rl := cfg.Security.RateLimit
	clk := clock.Real{}
	mk := func(rule config.RateLimitRule) func() *ratelimit.Limiter {
		return func() *ratelimit.Limiter {
			return ratelimit.New(rule.Max, time.Duration(rule.WindowMinutes)*time.Minute, clk)
		}
	}
	selfReg := mk(rl.SelfRegister)
	passkeyReg := mk(rl.PasskeyRegister)
	loginOpts := mk(rl.LoginOptions)
	loginVerify := mk(rl.LoginVerify)
	dcr := func() *ratelimit.Limiter { return ratelimit.New(10, 15*time.Minute, clk) }

	return []ratelimit.Rule{
		// selfRegister bucket (self-register.ts).
		{Method: "POST", Path: "/api/auth/register/options", Limiter: selfReg()},
		{Method: "POST", Path: "/api/auth/register", Limiter: selfReg()},
		// passkeyRegister bucket (registration.ts + invite.ts).
		{Method: "POST", Path: "/api/webauthn/register/options", Limiter: passkeyReg()},
		{Method: "POST", Path: "/api/webauthn/register", Limiter: passkeyReg()},
		{Method: "POST", Path: "/api/webauthn/invite", Limiter: passkeyReg()},
		{Method: "POST", Path: "/api/passkey-invite/register/options", Limiter: passkeyReg()},
		{Method: "POST", Path: "/api/passkey-invite/register", Limiter: passkeyReg()},
		{Method: "GET", Path: "/api/passkey-invite/", Prefix: true, Limiter: passkeyReg()},
		// loginOptions bucket (hydra provider pages/options, routes.ts).
		{Method: "GET", Path: "/api/hydra/login", Limiter: loginOpts()},
		{Method: "POST", Path: "/api/hydra/login/options", Limiter: loginOpts()},
		{Method: "GET", Path: "/api/hydra/consent", Limiter: loginOpts()},
		{Method: "POST", Path: "/api/hydra/consent/options", Limiter: loginOpts()},
		{Method: "POST", Path: "/api/hydra/consent/approve", Limiter: loginOpts()},
		{Method: "GET", Path: "/api/hydra/logout", Limiter: loginOpts()},
		// loginVerify bucket (assertion crypto: login/consent verify, step-up).
		{Method: "POST", Path: "/api/hydra/login/verify", Limiter: loginVerify()},
		{Method: "POST", Path: "/api/hydra/consent/verify", Limiter: loginVerify()},
		{Method: "POST", Path: "/api/webauthn/stepup/options", Limiter: loginVerify()},
		{Method: "POST", Path: "/api/webauthn/stepup/verify", Limiter: loginVerify()},
		// Mediated DCR: fixed 10/15min (routes.ts:186).
		{Method: "POST", Path: "/api/hydra/register", Limiter: dcr()},
	}
}

func jsonHandler(v any) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(v)
	}
}

// configJS emits the browser bootstrap: window.__OAUTH__ (PKCE issuer/client/
// redirect/scope), self-registration flag, VAPID key, and build info.
func configJS(cfg *config.Config, info buildinfo.Info) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		ext := strings.TrimRight(cfg.Server.ExternalURL, "/")
		redirect := cfg.Hydra.Spa.RedirectURI
		if redirect == "" {
			redirect = ext + "/auth/callback"
		}
		// Ordered struct (not a map) so the emitted JS object key order matches
		// the Node bootstrap byte-for-byte (issuer, clientId, redirectUri, scope).
		oauth := struct {
			Issuer      string `json:"issuer"`
			ClientID    string `json:"clientId"`
			RedirectURI string `json:"redirectUri"`
			Scope       string `json:"scope"`
		}{
			Issuer:      strings.TrimRight(cfg.Hydra.PublicURL, "/"),
			ClientID:    cfg.Hydra.Spa.ClientID,
			RedirectURI: redirect,
			Scope:       "openid offline_access " + auth.UIScope,
		}
		var vapid any
		if cfg.Vapid != nil {
			vapid = cfg.Vapid.PublicKey
		}
		j := func(v any) string { b, _ := json.Marshal(v); return string(b) }

		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		_, _ = w.Write([]byte(
			"window.__SELF_REGISTRATION_ENABLED__=" + j(cfg.Security.SelfRegistrationEnabled) + ";" +
				"window.__VAPID_PUBLIC_KEY__=" + j(vapid) + ";" +
				"window.__BUILD_INFO__=" + j(info) + ";" +
				"window.__OAUTH__=" + j(oauth) + ";",
		))
	}
}

// spaHandler serves files from the client build; unknown non-API paths fall
// back to index.html (adapter-static SPA routing, mirroring @fastify/static
// + setNotFoundHandler in the Node backend).
func spaHandler(staticFS fs.FS) http.HandlerFunc {
	fileServer := http.FileServerFS(staticFS)
	return func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/")
		if path != "" {
			if f, err := staticFS.Open(path); err == nil {
				f.Close()
				fileServer.ServeHTTP(w, r)
				return
			}
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"Not found"}`))
			return
		}
		index, err := staticFS.Open("index.html")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		defer index.Close()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if data, err := io.ReadAll(index); err == nil {
			_, _ = w.Write(data)
		}
	}
}
