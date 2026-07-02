// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Package httpserver assembles the chi router: middleware stack (bearer
// gate, IP allowlist for /mcp), the stateless meta endpoints, discovery
// docs, and SPA static serving. Handlers implementing the generated
// api.StrictServerInterface mount here as later Phase 2-5 slices land.
package httpserver

import (
	"encoding/json"
	"io"
	"io/fs"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/rado0x54/shellwatch/internal/auth"
	"github.com/rado0x54/shellwatch/internal/buildinfo"
	"github.com/rado0x54/shellwatch/internal/config"
	"github.com/rado0x54/shellwatch/internal/hydra"
)

type Params struct {
	Config  *config.Config
	Resolve hydra.Resolver
	// TouchLastUsed records authenticated activity (nil-able in tests).
	TouchLastUsed func(accountID string)
	StaticFS      fs.FS
	BuildInfo     buildinfo.Info
}

// New builds the router. ExternalURL is read from Config at request time so
// test harnesses can pin it after boot (same trick as the Node helpers).
func New(p Params) http.Handler {
	externalURL := func() string { return p.Config.Server.ExternalURL }
	agentProxy := p.Config.AgentSocket.ProxyEnabled

	r := chi.NewRouter()
	r.Use(auth.Gate(auth.GateParams{
		Resolve:           p.Resolve,
		ExternalURL:       externalURL,
		AgentProxyEnabled: agentProxy,
		TouchLastUsed:     p.TouchLastUsed,
	}))

	// Stateless meta endpoints (health.json golden; /api/version).
	r.Get("/health", jsonHandler(map[string]string{"status": "ok"}))
	r.Get("/api/version", jsonHandler(p.BuildInfo))

	hydra.MountDiscovery(r, hydra.DiscoveryParams{
		ExternalURL:       externalURL,
		HydraPublicURL:    p.Config.Hydra.PublicURL,
		AgentProxyEnabled: agentProxy,
	})

	// SPA: exact static files, fallback to index.html for client routes.
	r.NotFound(spaHandler(p.StaticFS))
	return r
}

func jsonHandler(v any) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(v)
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
