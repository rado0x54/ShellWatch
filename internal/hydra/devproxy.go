// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Dev-only single-origin proxy (hydra.devProxyUpstream): ShellWatch forwards
// Hydra's public surface so app and OAuth authority share ONE origin, exactly
// like the production reverse proxy (docs/deployment.md) — which is what
// strict OAuth discovery needs: 2026-07-28-era MCP clients enforce RFC 8414
// §3.3 (the authorization-server metadata's issuer must equal the origin it
// was fetched from), and the split :3000/:4444 dev layout cannot satisfy that.
// The proxied set mirrors the production Caddyfile; the RFC 9728/8414
// discovery docs are NOT proxied — those are ShellWatch's own (discovery.go).
package hydra

import (
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/go-chi/chi/v5"
)

// MountDevProxy forwards Hydra's public endpoints to upstream (the real Hydra
// listener). Everything here is public by design — the bearer gate does not
// guard these paths.
func MountDevProxy(r chi.Router, upstream *url.URL) {
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(upstream)
			pr.SetXForwarded()
		},
		ErrorHandler: func(w http.ResponseWriter, req *http.Request, err error) {
			slog.Warn("hydra dev proxy: upstream unreachable", "path", req.URL.Path, "upstream", upstream.String(), "err", err)
			w.WriteHeader(http.StatusBadGateway)
		},
	}
	for _, path := range []string{
		"/oauth2/*",
		"/userinfo",
		"/.well-known/jwks.json",
		"/.well-known/openid-configuration",
	} {
		r.Handle(path, proxy)
	}
	slog.Info("hydra dev proxy enabled: forwarding /oauth2/*, /userinfo and the OIDC discovery docs", "upstream", upstream.String())
}
