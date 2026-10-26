// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// ShellWatch server. Composition root: config, store, Hydra resolver, HTTP
// server — wired here and only here (docs/go-backend-architecture.md §5.1).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/rado0x54/shellwatch/internal/agent"
	"github.com/rado0x54/shellwatch/internal/agentproxy"
	"github.com/rado0x54/shellwatch/internal/approval"
	"github.com/rado0x54/shellwatch/internal/audit"
	"github.com/rado0x54/shellwatch/internal/buildinfo"
	"github.com/rado0x54/shellwatch/internal/clock"
	"github.com/rado0x54/shellwatch/internal/config"
	"github.com/rado0x54/shellwatch/internal/demo"
	"github.com/rado0x54/shellwatch/internal/endpointsvc"
	"github.com/rado0x54/shellwatch/internal/hostkeys"
	"github.com/rado0x54/shellwatch/internal/httpserver"
	"github.com/rado0x54/shellwatch/internal/hydra"
	"github.com/rado0x54/shellwatch/internal/ids"
	"github.com/rado0x54/shellwatch/internal/mcp"
	"github.com/rado0x54/shellwatch/internal/notify"
	"github.com/rado0x54/shellwatch/internal/push"
	"github.com/rado0x54/shellwatch/internal/rest"
	"github.com/rado0x54/shellwatch/internal/seed"
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
	healthcheck := flag.Bool("healthcheck", false, "probe the running server's /health and exit (container HEALTHCHECK)")
	flag.Parse()
	// A positional config path wins over the flag and the env var.
	if flag.NArg() > 0 {
		*configPath = flag.Arg(0)
	}

	if *healthcheck {
		return probeHealth(*configPath)
	}

	if err := setupLogging(); err != nil {
		return err
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
	flusherDone := make(chan struct{})
	go func() {
		defer close(flusherDone)
		flusher.Run(ctx, time.Minute)
	}()

	// First-run seeding (admin account + passkeys + endpoints). Fatal on
	// failure like the Node boot (index.ts:43) — continuing without an admin
	// account leaves a fresh deployment silently un-loginable.
	res, err := seed.FromConfig(ctx, db, cfg, newUUID, clk.Now())
	if err != nil {
		return fmt.Errorf("first-run seeding failed: %w", err)
	}
	if res.SeededAdminAccount || res.SeededAdminPasskey {
		slog.Info("seeded from config", "adminAccount", res.SeededAdminAccount, "adminPasskey", res.SeededAdminPasskey)
	}
	// Config-provisioned host-key pins (#241): applied on every boot so a
	// hostKey added to an existing deployment takes effect on restart.
	seed.ApplyHostKeyPins(ctx, store.NewEndpoints(db, clk), db, cfg)
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
	epSvc := &endpointsvc.Service{Endpoints: endpointStore, Demo: demoSvc}
	credStore := store.NewCredentials(db, clk)
	keyDir := sshx.NewKeyDir(cfg.KeyDirectory)
	// Discover file keys into ssh_keys + watch the directory for changes so
	// GET /api/keys lists them and file-key auth finds them.
	go keyDir.Watch(ctx, store.NewSSHKeys(db), func() string {
		return clk.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	})

	// Audit writer built early: the host-key pin store flags pinning approvals
	// through it, and the factory's mismatch hook writes audit rows. Its
	// manager/store subscriptions attach below once those exist.
	auditWriter := audit.NewWriter(db, clk)

	// Host-key pin store (#241): endpoints table for persistent endpoints,
	// demo service for virtual ones; a successful pin flags the approving
	// action in the audit log.
	hostKeySvc := &hostkeys.Service{
		Endpoints: endpointStore,
		Demo:      demoSvc,
		OnPinned:  auditWriter.MarkHostKeyPinned,
	}

	// Notification log (#252): persisted first, pushed to connected tabs
	// second. The hub attaches below once it exists.
	notifSvc := notify.NewService(db, clk)
	notifSvc.NewID = newUUID

	// OAuth client registration log (#242): how each MCP/agent client came to
	// exist in Hydra, via mediated DCR or CIMD. The only audit surface that is
	// not account-scoped — both paths run before any account is identified —
	// so it is admin-only to read (migration 00004).
	oauthClientLog := audit.NewOAuthClients(db, clk)
	oauthClientLog.NewID = newUUID

	// Ordering: build the hub first (needs a manager) but the manager's
	// passkey factory needs the broker which needs the hub's WS channel. Break
	// it with a manager built on a factory closure that reads the broker set
	// just below (all resolved before the first session opens). wsHub and
	// pushChannel resolve lazily the same way for the mismatch hook.
	var signBroker *approval.Broker
	var wsHub *ws.Hub
	var pushChannel *push.Channel
	passkeyFactory := sshx.NewPasskeyFactory(sshx.PasskeyFactoryParams{
		BrokerFunc:      func() sshx.SignBroker { return signBroker },
		Credentials:     credStore,
		FileKeys:        keyDir,
		Keys:            store.NewSSHKeys(db),
		IsAdmin:         store.NewAccounts(db).IsAdmin,
		RpID:            cfg.Security.RpID,
		Origin:          firstOrigin(cfg.Security.TrustedWebauthnOrigins),
		NewConnectionID: newUUID,
		HostKeys:        hostKeySvc,
		// Host-key mismatch (#241): the handshake died before authentication,
		// so no approval toast exists — audit it, publish it to the account's
		// notification log (which pushes notification:new to every tab, #252),
		// and alert every push channel. The returned notification id rides on
		// the connect error so the HTTP failure references the same event.
		OnHostKeyMismatch: func(ev sshx.HostKeyMismatchEvent) string {
			slog.Warn("host key mismatch — connection refused",
				"endpoint", ev.EndpointID, "pinned", ev.PinnedFingerprint, "observed", ev.ObservedFingerprint)
			auditID := auditWriter.RecordHostKeyEvent(audit.HostKeyEvent{
				Type: "host-key-mismatch", Source: "endpoint-auth",
				AccountID: ev.AccountID, EndpointID: ev.EndpointID,
				EndpointLabel: ev.EndpointLabel, EndpointAddress: ev.EndpointAddress,
				Fingerprint: ev.ObservedFingerprint, PriorFingerprint: ev.PinnedFingerprint,
				SourceIP: ev.Trigger.SourceIP, MCPReason: ev.Trigger.Reason,
				MCPClientName: ev.Trigger.MCPClientName, MCPClientVersion: ev.Trigger.MCPClientVer,
			})
			n := notifSvc.Publish(context.Background(), notify.PublishParams{
				AccountID: ev.AccountID,
				Type:      notify.TypeHostKeyMismatch,
				Severity:  notify.SeverityError,
				Title:     fmt.Sprintf("Host key MISMATCH — connection to %q blocked", ev.EndpointLabel),
				Detail: fmt.Sprintf("Endpoint:   %s (%s)\nPresented:  %s (%s)\nPinned:     %s\n\n"+
					"The connection was refused before authentication. If the host key legitimately changed, "+
					"forget the pinned key under Settings → Endpoints → Host key.",
					ev.EndpointLabel, ev.EndpointAddress,
					ev.ObservedFingerprint, ev.ObservedKeyType, ev.PinnedFingerprint),
				Payload: map[string]any{
					"endpointId":          ev.EndpointID,
					"endpointLabel":       ev.EndpointLabel,
					"endpointAddress":     ev.EndpointAddress,
					"keyType":             ev.ObservedKeyType,
					"observedFingerprint": ev.ObservedFingerprint,
					"pinnedFingerprint":   ev.PinnedFingerprint,
					"auditId":             auditID,
				},
			})
			if pushChannel != nil {
				pushChannel.NotifyHostKeyMismatch(push.HostKeyMismatch{
					AccountID: ev.AccountID, EndpointLabel: ev.EndpointLabel,
					EndpointAddress:     ev.EndpointAddress,
					ObservedFingerprint: ev.ObservedFingerprint, PinnedFingerprint: ev.PinnedFingerprint,
				})
			}
			return n.ID
		},
		// Dead terminal connection -> cancel its stranded sign prompts and
		// clear the toasts (#91). signBroker resolves lazily like BrokerFunc.
		OnConnectionEnded: func(connID, reason string) {
			if signBroker == nil {
				return
			}
			if n := signBroker.CancelForConnection(connID, reason); n > 0 {
				slog.Info("cancelled pending sign prompts for dead connection", "connection", connID, "count", n)
			}
		},
	})
	// Every failed connect — UI click or MCP agent — lands in the notification
	// log (#252): the agent-triggered ones have no other human-visible surface.
	// Events a more specific producer already published (host-key mismatch)
	// arrive as NotifiedError and are not double-logged; everything else is
	// published here and tagged the same way, so the HTTP error body carries
	// the notification id and the toast dedupes by identity.
	factory := func(ctx context.Context, fp terminal.FactoryParams) (terminal.Transport, error) {
		transport, err := passkeyFactory(ctx, fp)
		if err != nil {
			var already *sshx.NotifiedError
			if !errors.As(err, &already) {
				addr := fmt.Sprintf("%s@%s:%d", fp.Endpoint.Username, fp.Endpoint.Host, fp.Endpoint.Port)
				source := string(fp.Trigger.Kind)
				if fp.Trigger.MCPClientName != "" {
					source = fmt.Sprintf("%s (%s %s)", source, fp.Trigger.MCPClientName, fp.Trigger.MCPClientVer)
				}
				n := notifSvc.Publish(context.Background(), notify.PublishParams{
					AccountID: fp.Endpoint.AccountID,
					Type:      notify.TypeSessionConnectFailed,
					Severity:  notify.SeverityWarning,
					Title:     fmt.Sprintf("Connection to %q failed", fp.Endpoint.Label),
					Detail: fmt.Sprintf("Endpoint:  %s (%s)\nSource:    %s\nError:     %s",
						fp.Endpoint.Label, addr, source, err.Error()),
					Payload: map[string]any{
						"endpointId":       fp.Endpoint.ID,
						"endpointLabel":    fp.Endpoint.Label,
						"endpointAddress":  addr,
						"trigger":          fp.Trigger.Kind,
						"mcpClientName":    fp.Trigger.MCPClientName,
						"mcpClientVersion": fp.Trigger.MCPClientVer,
						"mcpReason":        fp.Trigger.Reason,
						"sourceIp":         fp.Trigger.SourceIP,
						"error":            err.Error(),
					},
				})
				if n.ID != "" {
					err = &sshx.NotifiedError{NotificationID: n.ID, Err: err}
				}
			}
		}
		return transport, err
	}
	manager := terminal.NewManager(factory, clk, 0)
	// Idle janitor: auto-close sessions idle longer than sessions.idleTimeoutMinutes.
	manager.SetIdleTimeout(cfg.Sessions.IdleTimeout())
	go manager.RunIdleJanitor(ctx, cfg.Sessions.CleanupInterval())
	wsHub = ws.NewHub(manager)
	defer wsHub.Close()
	notifSvc.Hub = wsHub // publishes reach connected tabs from here on

	// Human-in-the-loop signing (Phase 4 slice 2/3): the pending-action store +
	// broker + WS channel are the approval path; the webauthn signer (proven
	// end-to-end) is what the passkey factory above invokes. sign:request /
	// sign:resolved reach browsers via the hub.
	actionStore := approval.NewStore(clk, newUUID)
	go sweepActions(ctx, actionStore)
	pushSubs := store.NewPushSubs(db, clk)
	channels := []approval.Channel{&approval.WSChannel{Hub: wsHub}}
	if cfg.Vapid != nil {
		// Web Push delivery (H7): approval prompts reach subscribed browsers
		// without an open tab (index.ts:78-86).
		pushChannel = push.NewChannel(pushSubs, push.Vapid{
			Subject: cfg.Vapid.Subject, PublicKey: cfg.Vapid.PublicKey, PrivateKey: cfg.Vapid.PrivateKey,
		})
		channels = append(channels, pushChannel)
		slog.Info("web push notifications enabled (VAPID configured)")
	}
	signBroker = approval.NewBroker(actionStore,
		func() string { return cfg.Server.ExternalURL },
		channels...)

	// Audit writers subscribe to the manager + action store (guaranteed hooks).
	auditWriter.AttachManager(manager, manager.GetSession)
	auditWriter.AttachStore(actionStore)

	buildInfo := buildinfo.Load(mustGetwd())
	mcpDeps := &mcp.Deps{
		AgentDeps:      agent.Deps{Manager: manager, Svc: epSvc, Audit: auditWriter},
		Keys:           store.NewSSHKeys(db),
		Version:        buildInfo.Display,
		NotifyDebounce: time.Duration(cfg.Notifications.Mcp.DebounceMs) * time.Millisecond,
		MaxOwned:       store.NewAccounts(db).MaxSessions,
	}

	// Account-deleted teardown (app.ts accountLifecycle "deleted", #217): close
	// the account's live terminal sessions, drop its MCP transports, and revoke
	// its Hydra login/consent sessions so live grants die with the account.
	// Fired by the admin DELETE route and the 90-day inactivity cleanup alike.
	accountDeleted := func(accountID string) {
		if n := manager.CloseAllForAccount(accountID, terminal.CloseAccountDeleted); n > 0 {
			slog.Info("closed sessions for deleted account", "account", accountID, "count", n)
		}
		// Purge retained post-mortem sessions too — a deleted account's
		// terminal output must not stay readable in memory.
		if n := manager.RemoveForAccount(accountID); n > 0 {
			slog.Info("purged retained sessions for deleted account", "account", accountID, "count", n)
		}
		go func() {
			rctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := admin.RevokeLoginSessions(rctx, accountID); err != nil {
				slog.Warn("failed to revoke Hydra login sessions for deleted account", "account", accountID, "err", err)
			}
			if err := admin.RevokeConsentSessions(rctx, accountID, ""); err != nil {
				slog.Warn("failed to revoke Hydra consent sessions for deleted account", "account", accountID, "err", err)
			}
		}()
	}
	go store.RunCleanupJob(ctx, db, clk, func(ids []string) {
		slog.Info("cleaned up inactive accounts", "count", len(ids))
		for _, id := range ids {
			accountDeleted(id)
		}
	})

	handler := httpserver.New(httpserver.Params{
		Config:        cfg,
		Resolve:       resolve,
		TouchLastUsed: flusher.Touch,
		StaticFS:      staticFS,
		BuildInfo:     buildInfo,
		WebAuthn:      webauthnDeps,
		HydraAdmin:    admin,
		HasPasskeys: func() bool {
			has, _ := credStore.HasPasskeys(ctx)
			return has
		},
		Endpoints: &rest.Endpoints{
			Svc:      epSvc,
			Sessions: manager,
			NewID:    newUUID,
			StepUp:   webauthnDeps.StepUp,
			Audit:    auditWriter,
		},
		Sessions: &rest.Sessions{
			Manager:     manager,
			Svc:         epSvc,
			MaxSessions: store.NewAccounts(db).MaxSessions,
		},
		WSHub:     wsHub,
		MCP:       mcpDeps,
		Actions:   &rest.Actions{Store: actionStore},
		ClientLog: oauthClientLog,
		Audit: &rest.Audit{
			Sessions:     audit.NewSessions(db),
			Signings:     audit.NewSignings(db),
			Notify:       notifSvc,
			OAuthClients: oauthClientLog,
			IsAdmin:      store.NewAccounts(db),
		},
		Accounts: &rest.Accounts{
			Store: store.NewAccounts(db), Creds: credStore, Endpoints: endpointStore, Demo: demoSvc,
			Now:       func() string { return clk.Now().UTC().Format("2006-01-02T15:04:05.000Z") },
			OnDeleted: accountDeleted,
		},
		Credentials: &rest.Credentials{
			Store: credStore, Admin: admin, StepUp: webauthnDeps.StepUp,
		},
		Keys: &rest.Keys{
			Store: store.NewSSHKeys(db), Accounts: store.NewAccounts(db),
			Available: keyDir.IsAvailable,
		},
		AuthSessions: &rest.AuthSessions{
			Admin: admin, SPAClientID: cfg.Hydra.Spa.ClientID, StepUp: webauthnDeps.StepUp,
			// Revoking a client's consent also closes its live terminal
			// sessions — the grant was the only thing tying them to the agent.
			CloseClientSessions: func(accountID, clientID string) int {
				n := manager.CloseAllForClient(accountID, clientID, terminal.CloseAgentDisconnect)
				if n > 0 {
					slog.Info("closed MCP sessions for revoked client", "account", accountID, "client", clientID, "count", n)
				}
				return n
			},
		},
		// Push routes mount only when VAPID is configured (Node 404s them
		// otherwise); the endpoint allowlist is the SSRF guard (H8).
		Push: pushDeps(cfg, pushSubs),
		AgentProxy: &agentproxy.Deps{
			Broker:          signBroker,
			Credentials:     credStore,
			FileKeys:        keyDir,
			RpID:            cfg.Security.RpID,
			NewConnectionID: newUUID,
		},
	})

	addr := net.JoinHostPort(bindHost(), strconv.Itoa(cfg.Server.Port))
	srv := &http.Server{Addr: addr, Handler: handler}

	errCh := make(chan error, 1)
	go func() {
		slog.Info("shellwatch listening", "addr", addr, "mcp", "http://"+addr+"/mcp")
		if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		stop()            // cancel the root ctx so the janitors and the flusher exit
		_ = srv.Close()   // sever accepted conns: no in-flight handler may create a session after Destroy
		manager.Destroy() // close open PTYs cleanly + write their session-close audit rows
		<-flusherDone
		flusher.CloseAndFlush(context.Background())
		return err
	case <-ctx.Done():
	}
	// Ordered shutdown (§5.1): stop accepting HTTP and drain; if the drain
	// deadline fires with a handler still running (a long MCP stream),
	// hard-close the remaining connections so the straggler stops producing
	// work. Then close all terminals, join the flusher, and CloseAndFlush:
	// it flushes and marks the flusher closed atomically, so no Touch from
	// any surviving goroutine can land after the final flush — "the flush is
	// the last-used table's last write before db.Close" holds structurally
	// on every branch, not just the clean drain.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = srv.Shutdown(shutdownCtx)
	if err != nil {
		_ = srv.Close()
	}
	manager.Destroy()
	<-flusherDone
	flusher.CloseAndFlush(context.Background())
	return err
}

// setupLogging installs the default slog handler. Controlled by env:
//
//	SHELLWATCH_LOG_LEVEL   debug | info (default) | warn | error
//	SHELLWATCH_LOG_FORMAT  text (default) | json
//	SHELLWATCH_LOG_FILE    path to also append logs to (in addition to stdout)
//
// Logs go to stdout so `pnpm dev` / a terminal shows them; a file sink is added
// for persistent debugging when SHELLWATCH_LOG_FILE is set.
func setupLogging() error {
	level := slog.LevelInfo
	switch strings.ToLower(os.Getenv("SHELLWATCH_LOG_LEVEL")) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}

	var out io.Writer = os.Stdout
	if path := os.Getenv("SHELLWATCH_LOG_FILE"); path != "" {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return fmt.Errorf("open log file: %w", err)
		}
		out = io.MultiWriter(os.Stdout, f)
	}

	opts := &slog.HandlerOptions{Level: level}
	var h slog.Handler = slog.NewTextHandler(out, opts)
	if strings.ToLower(os.Getenv("SHELLWATCH_LOG_FORMAT")) == "json" {
		h = slog.NewJSONHandler(out, opts)
	}
	slog.SetDefault(slog.New(h))
	return nil
}

// bindHost is the listen address: $HOST, default 0.0.0.0 (all interfaces).
func bindHost() string {
	if h := os.Getenv("HOST"); h != "" {
		return h
	}
	return "0.0.0.0"
}

// probeHealth implements `shellwatch -healthcheck`: GET /health on the port
// the config names (loopback) and exit non-zero unless it answers 2xx. The
// runtime image has no shell or curl, so the binary is its own health probe.
func probeHealth(configPath string) error {
	port := 3000
	if cfg, err := config.Load(configPath); err == nil {
		port = cfg.Server.Port
	}
	client := &http.Client{Timeout: 5 * time.Second}
	res, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/health", port))
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return fmt.Errorf("/health returned %s", res.Status)
	}
	return nil
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

func newUUID() string { return ids.NewUUID() }

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

// pushDeps returns the push REST deps, or nil when VAPID is unconfigured
// (Node registers the routes only under config.vapid — index.ts:78-86).
func pushDeps(cfg *config.Config, subs *store.PushSubs) *rest.Push {
	if cfg.Vapid == nil {
		return nil
	}
	return &rest.Push{Store: subs, AllowedEndpoint: push.IsAllowedEndpoint, NewID: newUUID}
}

// firstOrigin returns the first trusted WebAuthn origin (the ceremony origin
// the signer records; the browser overrides it in clientDataJSON).
func firstOrigin(origins []string) string {
	if len(origins) > 0 {
		return origins[0]
	}
	return ""
}
