// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// ShellWatch Go backend (#210). Composition root: config, store, Hydra
// resolver, HTTP server — wired here and only here
// (docs/go-backend-architecture.md §5.1). Auth plane (Phase 2) + endpoints
// REST (Phase 3 slice 1) are live; terminal core / SSH / WS follow. The Node
// backend remains the production server until cutover.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
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

	"github.com/rado0x54/shellwatch/internal/agent"
	"github.com/rado0x54/shellwatch/internal/approval"
	"github.com/rado0x54/shellwatch/internal/buildinfo"
	"github.com/rado0x54/shellwatch/internal/clock"
	"github.com/rado0x54/shellwatch/internal/config"
	"github.com/rado0x54/shellwatch/internal/demo"
	"github.com/rado0x54/shellwatch/internal/httpserver"
	"github.com/rado0x54/shellwatch/internal/hydra"
	"github.com/rado0x54/shellwatch/internal/mcp"
	"github.com/rado0x54/shellwatch/internal/rest"
	"github.com/rado0x54/shellwatch/internal/sshx"
	"github.com/rado0x54/shellwatch/internal/store"
	"github.com/rado0x54/shellwatch/internal/terminal"
	"github.com/rado0x54/shellwatch/internal/webauthn"
	"github.com/rado0x54/shellwatch/internal/ws"
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

	endpointStore := store.NewEndpoints(db, clk)
	demoSvc := demo.NewService(cfg.DemoEndpoints)
	// File-key SSH transport (Phase 3 slice 3). The passkey/pending-action
	// signer path is added in Phase 4; today file keys from the key directory
	// authenticate.
	keyDir := sshx.NewKeyDir(cfg.KeyDirectory)
	manager := terminal.NewManager(sshx.NewFileKeyFactory(keyDir), clk, 0)
	wsHub := ws.NewHub(manager)
	defer wsHub.Close()

	// Human-in-the-loop signing machinery (Phase 4 slice 2). The pending-action
	// store + broker + WS channel are the approval path; the webauthn signer
	// (proven end-to-end) wires into the transport factory + agent proxy in
	// slice 3. sign:request/resolved reach browsers via the hub.
	actionStore := approval.NewStore(clk, newUUID)
	go sweepActions(ctx, actionStore)
	signBroker := approval.NewBroker(actionStore,
		func() string { return cfg.Server.ExternalURL },
		&approval.WSChannel{Hub: wsHub})
	_ = signBroker // wired into the transport factory in slice 3

	handler := httpserver.New(httpserver.Params{
		Config:        cfg,
		Resolve:       resolve,
		TouchLastUsed: flusher.Touch,
		StaticFS:      staticFS,
		BuildInfo:     buildinfo.Load(mustGetwd()),
		WebAuthn:      webauthnDeps,
		HydraAdmin:    admin,
		Endpoints: &rest.Endpoints{
			Store:    endpointStore,
			Demo:     demoSvc,
			Sessions: manager,
			NewID:    newUUID,
		},
		Sessions: &rest.Sessions{
			Manager:     manager,
			Endpoints:   endpointStore,
			Demo:        demoSvc,
			MaxSessions: store.NewAccounts(db).MaxSessions,
		},
		WSHub: wsHub,
		MCP: &mcp.Deps{
			AgentDeps: agent.Deps{Manager: manager, Endpoints: endpointStore, Demo: demoSvc},
			Keys:      store.NewSSHKeys(db),
		},
		Actions: &rest.Actions{Store: actionStore},
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
	// Ordered shutdown (§5.1): stop accepting HTTP, close all terminals, then
	// the final last-used flush (via flusher.Run's ctx-done path) and the DB
	// (deferred Close).
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = srv.Shutdown(shutdownCtx)
	manager.Destroy()
	return err
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

func newUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

func mustGetwd() string {
	wd, err := os.Getwd()
	if err != nil {
		return "."
	}
	return wd
}

// sweepActions expires overdue pending actions every 10s (the store janitor).
func sweepActions(ctx context.Context, store *approval.Store) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			store.Sweep()
		}
	}
}
