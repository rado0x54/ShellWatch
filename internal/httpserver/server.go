// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Package httpserver assembles the chi router: middleware stack (bearer
// gate, IP allowlist for /mcp), the stateless meta endpoints, discovery
// docs, and SPA static serving. The hand-written REST handlers
// (internal/rest, marshaling internal/api model types) mount here.
package httpserver

import (
	"crypto/x509"
	"encoding/json"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
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
	// Clock drives the CIMD document cache's TTLs. nil -> clock.Real.
	Clock clock.Clock
	// ClientLog records DCR/CIMD registration events in the
	// non-account-scoped client log (satisfied by *audit.OAuthClients).
	// nil drops them.
	ClientLog ClientLogRecorder
	// CimdRootCAs is the trust store for CIMD document fetches; nil uses the
	// platform default. The composition root builds it from
	// hydra.cimd.extraCaBundlePath via hydra.LoadExtraRoots, which keeps the
	// system roots — so this must never be a bare private CA.
	CimdRootCAs *x509.CertPool
	// CimdFetcher overrides the document fetcher the CIMD front door uses.
	// nil -> built from hydra.cimd. Tests inject one that trusts a local
	// httptest CA; a deployment behind a private CA can do the same.
	CimdFetcher *hydra.Fetcher
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

	clk := p.Clock
	if clk == nil {
		clk = clock.Real{}
	}
	onClientEvent := clientEventSink(p.ClientLog)
	// hydra.cimd.enabled defaults to TRUE, and an unset pointer must mean the
	// default for any Config — not just one the loader filled in.
	cimdEnabled := p.Config.Hydra.Cimd.Enabled == nil || *p.Config.Hydra.Cimd.Enabled
	hydra.MountDiscovery(r, hydra.DiscoveryParams{
		ExternalURL:       externalURL,
		HydraPublicURL:    p.Config.Hydra.PublicURL,
		AgentProxyEnabled: agentProxy,
		CimdEnabled:       cimdEnabled,
	})

	// Dev single-origin mode (#243): forward Hydra's public surface so one
	// origin serves app + OAuth, as the production reverse proxy does. The
	// config loader validated the URL.
	if up := p.Config.Hydra.DevProxyUpstream; up != "" {
		if u, err := url.Parse(up); err == nil {
			hydra.MountDevProxy(r, u)
		}
	}

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
			OnEvent:                 onClientEvent,
		})

	}

	if p.HydraAdmin != nil {
		// The CIMD authorization front door. It is mounted whether or not CIMD
		// is enabled: with the resolver nil it is a pure passthrough to Hydra,
		// so a client that cached the endpoint from discovery keeps working
		// after CIMD is turned off.
		var cimd *hydra.CIMDResolver
		if cimdEnabled {
			c := p.Config.Hydra.Cimd
			fetcher := p.CimdFetcher
			if fetcher == nil {
				fetcher = hydra.NewFetcher(hydra.FetcherParams{
					AllowLoopback: c.AllowLoopbackDocuments,
					AllowedHosts:  c.AllowedHosts,
					BlockedHosts:  c.BlockedHosts,
					CacheMin:      time.Duration(c.CacheMinSeconds) * time.Second,
					CacheMax:      time.Duration(c.CacheMaxSeconds) * time.Second,
					RootCAs:       p.CimdRootCAs,
					Clock:         clk,
				})
			}
			cimd = hydra.NewCIMDResolver(hydra.CIMDResolverParams{
				Admin:   p.HydraAdmin,
				Fetcher: fetcher,
				Policy: hydra.NewClientPolicy(
					p.Config.Hydra.Dcr.RedirectURIPatterns,
					p.Config.Hydra.Dcr.AllowedScopes,
					agentProxy,
				),
				Clock: clk,
			})
			if c.AllowLoopbackDocuments {
				slog.Warn("hydra.cimd.allowLoopbackDocuments is enabled — DEV/TEST ONLY; " +
					"draft-ietf-oauth-client-id-metadata-document-02 §8.6 forbids it in production")
			}
		}
		hydra.MountFrontDoor(r, hydra.FrontDoorParams{
			Resolver:          cimd,
			HydraAuthorizeURL: strings.TrimRight(p.Config.Hydra.PublicURL, "/") + "/oauth2/auth",
			OnEvent:           onClientEvent,
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
	// The CIMD front door triggers an outbound document fetch on a cache miss,
	// so it needs a ceiling — but it is also a user-facing redirect in a normal
	// login, so the bucket is far wider than DCR's.
	cimdAuthorize := func() *ratelimit.Limiter { return ratelimit.New(60, 15*time.Minute, clk) }

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
		// CIMD authorization front door: fixed 60/15min.
		{Method: "GET", Path: "/api/hydra/authorize", Limiter: cimdAuthorize()},
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
//
// Caching: embedded files carry a zero modtime, so the file server can never
// answer If-Modified-Since — without explicit headers every reload would
// re-download the full bundle. SvelteKit content-hashes everything under
// _app/immutable/, so those are cached forever; every other static path
// (index.html, service-worker.js, favicon, manifest) must revalidate so a new
// deploy is picked up immediately.
func spaHandler(staticFS fs.FS) http.HandlerFunc {
	fileServer := http.FileServerFS(staticFS)
	return func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/")
		if path != "" {
			if f, err := staticFS.Open(path); err == nil {
				info, statErr := f.Stat()
				f.Close()
				// Only real files are served statically. A directory would
				// get the file server's auto-generated listing — and
				// /_app/immutable/ would cache that listing for a year — so
				// directories fall through to the SPA fallback (what the
				// Node server answered for them).
				if statErr == nil && !info.IsDir() {
					w.Header().Set("Cache-Control", staticCacheControl(path))
					fileServer.ServeHTTP(w, r)
					return
				}
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
		w.Header().Set("Cache-Control", "no-cache")
		if data, err := io.ReadAll(index); err == nil {
			_, _ = w.Write(data)
		}
	}
}

// staticCacheControl picks the Cache-Control for a client-build file: the
// content-hashed bundle is immutable, everything else revalidates on each use.
func staticCacheControl(path string) string {
	if strings.HasPrefix(path, "_app/immutable/") {
		return "public, max-age=31536000, immutable"
	}
	return "no-cache"
}
