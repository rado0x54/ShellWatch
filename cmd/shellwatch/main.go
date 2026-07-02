// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// ShellWatch Go backend (#210). Composition root: config, store, Hydra
// resolver, HTTP server — wired here and only here
// (docs/go-backend-architecture.md §5.1). Phase 2 in progress: the bearer
// gate + discovery docs are live; providers/ceremonies/DCR land next. The
// Node backend remains the production server until cutover.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rado0x54/shellwatch/internal/buildinfo"
	"github.com/rado0x54/shellwatch/internal/clock"
	"github.com/rado0x54/shellwatch/internal/config"
	"github.com/rado0x54/shellwatch/internal/httpserver"
	"github.com/rado0x54/shellwatch/internal/hydra"
	"github.com/rado0x54/shellwatch/internal/store"
	"github.com/rado0x54/shellwatch/internal/webauthn"
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
	// Positional config path wins, mirroring the Node CLI.
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

	// Root context: cancelled on SIGINT/SIGTERM; janitors hang off it.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	clk := clock.Real{}
	admin := hydra.NewAdminClient(cfg.Hydra.AdminURL, &http.Client{Timeout: 10 * time.Second})
	resolve := hydra.NewResolver(admin,
		time.Duration(*cfg.Hydra.IntrospectionCacheTtlMs)*time.Millisecond, clk)

	// Provision the first-party SPA client (fail fast if Hydra is unreachable,
	// matching the Node boot).
	if err := hydra.EnsureSpaClient(ctx, admin, cfg.Hydra.Spa.ClientID, cfg.Hydra.Spa.RedirectURI); err != nil {
		return fmt.Errorf("provision SPA client: %w", err)
	}

	flusher := store.NewLastUsedFlusher(db, clk)
	go flusher.Run(ctx, time.Minute)

	webauthnDeps := &webauthn.Deps{
		Credentials:    store.NewCredentials(db, clk),
		Challenges:     webauthn.NewChallengeStore(clk),
		StepUp:         webauthn.NewStepUpStore(clk),
		Invites:        webauthn.NewInviteStore(clk),
		RpID:           cfg.Security.RpID,
		TrustedOrigins: cfg.Security.TrustedWebauthnOrigins,
		SelfRegEnabled: cfg.Security.SelfRegistrationEnabled,
	}

	handler := httpserver.New(httpserver.Params{
		Config:        cfg,
		Resolve:       resolve,
		TouchLastUsed: flusher.Touch,
		StaticFS:      staticFS,
		BuildInfo:     buildinfo.Load(mustGetwd()),
		WebAuthn:      webauthnDeps,
		HydraAdmin:    admin,
	})

	addr := fmt.Sprintf(":%d", cfg.Server.Port)
	srv := &http.Server{Addr: addr, Handler: handler}

	errCh := make(chan error, 1)
	go func() {
		slog.Info("shellwatch (go) listening", "addr", addr)
		if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}
	// Ordered shutdown: HTTP first, then the final last-used flush (via
	// flusher.Run's ctx-done path), then the DB (deferred Close).
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
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

func mustGetwd() string {
	wd, err := os.Getwd()
	if err != nil {
		return "."
	}
	return wd
}
