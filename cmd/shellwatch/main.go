// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// ShellWatch Go backend — Phase 1 skeleton (#210).
//
// Serves the two stateless contract endpoints (GET /health, GET /api/version
// — golden-backed) and the embedded SPA. Config load, SQLite open + goose
// migration run on boot exactly as the Node backend does. Everything else
// (auth plane, terminal core, MCP, agent proxy) arrives in Phases 2-5; the
// Node backend remains the production server until cutover.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/rado0x54/shellwatch/internal/buildinfo"
	"github.com/rado0x54/shellwatch/internal/config"
	"github.com/rado0x54/shellwatch/internal/store"
	"github.com/rado0x54/shellwatch/web"
)

func main() {
	if err := run(); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run() error {
	configPath := flag.String("config", "", "config file path (default: $SHELLWATCH_CONFIG or ./config.yaml)")
	staticDir := flag.String("static-dir", "", "serve the SPA from this directory instead of the embedded build")
	flag.Parse()
	// Positional config path wins, mirroring the Node CLI (`node dist/index.js config.yaml`).
	if flag.NArg() > 0 {
		*configPath = flag.Arg(0)
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}

	db, err := store.Open(os.Getenv("SHELLWATCH_DB"))
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer db.Close()
	if err := store.Migrate(db); err != nil {
		return fmt.Errorf("run migrations: %w", err)
	}

	staticFS, err := staticFilesystem(*staticDir)
	if err != nil {
		return err
	}

	info := buildinfo.Load(mustGetwd())
	r := chi.NewRouter()

	// The two golden-backed stateless endpoints (health.json, /api/version).
	r.Get("/health", jsonHandler(map[string]string{"status": "ok"}))
	r.Get("/api/version", jsonHandler(info))

	// SPA: exact static files, SPA-fallback to index.html for client routes.
	r.NotFound(spaHandler(staticFS))

	addr := fmt.Sprintf(":%d", cfg.Server.Port)
	srv := &http.Server{Addr: addr, Handler: r}

	// Ordered lifecycle: root context cancelled on SIGINT/SIGTERM, then an
	// explicit reverse-order shutdown (docs/go-backend-architecture.md §5.1).
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		slog.Info("shellwatch (go) listening", "addr", addr, "build", info.Display)
		if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

func jsonHandler(v any) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(v)
	}
}

func staticFilesystem(dir string) (fs.FS, error) {
	if dir != "" {
		if _, err := os.Stat(dir); err != nil {
			return nil, fmt.Errorf("-static-dir: %w", err)
		}
		return os.DirFS(dir), nil
	}
	return web.Dist()
}

// spaHandler serves files from the client build; unknown non-API paths fall
// back to index.html (adapter-static SPA routing, as @fastify/static +
// setNotFoundHandler do in the Node backend).
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

func mustGetwd() string {
	wd, err := os.Getwd()
	if err != nil {
		return "."
	}
	return wd
}
