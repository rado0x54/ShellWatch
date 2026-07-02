// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Route-coverage guard: mechanically assert that every operationId in the
// frozen wire contract (docs/api/openapi.yaml) is mounted by the Go server.
// This is the Go analogue of golden-coverage.test.ts and the systemic fix for
// the "silently missing endpoint" failure mode — a new spec operation with no
// Go route now reddens CI here rather than surfacing in someone's browser.
package httpserver

import (
	"context"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	yaml "github.com/goccy/go-yaml"

	"github.com/rado0x54/shellwatch/internal/agent"
	"github.com/rado0x54/shellwatch/internal/agentproxy"
	"github.com/rado0x54/shellwatch/internal/approval"
	"github.com/rado0x54/shellwatch/internal/audit"
	"github.com/rado0x54/shellwatch/internal/auth"
	"github.com/rado0x54/shellwatch/internal/buildinfo"
	"github.com/rado0x54/shellwatch/internal/clock"
	"github.com/rado0x54/shellwatch/internal/config"
	"github.com/rado0x54/shellwatch/internal/demo"
	"github.com/rado0x54/shellwatch/internal/hydratest"
	"github.com/rado0x54/shellwatch/internal/mcp"
	"github.com/rado0x54/shellwatch/internal/rest"
	"github.com/rado0x54/shellwatch/internal/store"
	"github.com/rado0x54/shellwatch/internal/terminal"
	"github.com/rado0x54/shellwatch/internal/webauthn"
	"github.com/rado0x54/shellwatch/internal/ws"
)

// fullHandler wires every route group (as main.go does) so the walk sees the
// complete mounted surface.
func fullHandler(t *testing.T) chi.Router {
	t.Helper()
	db, err := store.Open("sqlite::memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := store.Migrate(db); err != nil {
		t.Fatal(err)
	}
	clk := clock.Real{}
	cfg := &config.Config{}
	cfg.Server.ExternalURL = externalURL
	cfg.Hydra.PublicURL = "http://localhost:4444"
	cfg.Hydra.Spa.ClientID = "shellwatch-web"
	cfg.AgentSocket.ProxyEnabled = true // mount /agent-proxy

	fake := hydratest.New()
	stepUp := webauthn.NewStepUpStore(clk)
	credStore := store.NewCredentials(db, clk)
	endpointStore := store.NewEndpoints(db, clk)
	demoSvc := demo.NewService(nil)
	manager := terminal.NewManager(func(context.Context, terminal.FactoryParams) (terminal.Transport, error) {
		return terminal.NewMockTransport(), nil
	}, clk, 0)
	hub := ws.NewHub(manager)
	t.Cleanup(hub.Close)
	actionStore := approval.NewStore(clk, func() string { return "id" })
	waDeps := &webauthn.Deps{
		Credentials: credStore, Challenges: webauthn.NewChallengeStore(clk), StepUp: stepUp,
		Invites: webauthn.NewInviteStore(clk), RpID: "localhost",
	}

	h := New(Params{
		Config: cfg, Resolve: auth.Resolver(func(context.Context, string) *auth.Principal { return nil }),
		StaticFS: os.DirFS(t.TempDir()), BuildInfo: buildinfo.Info{},
		WebAuthn: waDeps, HydraAdmin: fake, HasPasskeys: func() bool { return true },
		Endpoints:    &rest.Endpoints{Store: endpointStore, Demo: demoSvc, Sessions: manager, NewID: func() string { return "id" }},
		Sessions:     &rest.Sessions{Manager: manager, Endpoints: endpointStore, Demo: demoSvc, MaxSessions: func(context.Context, string) (int, bool) { return 5, true }},
		WSHub:        hub,
		MCP:          &mcp.Deps{AgentDeps: agent.Deps{Manager: manager, Endpoints: endpointStore, Demo: demoSvc}, Keys: store.NewSSHKeys(db)},
		Actions:      &rest.Actions{Store: actionStore},
		Audit:        &rest.Audit{Sessions: audit.NewSessions(db), Signings: audit.NewSignings(db)},
		AgentProxy:   &agentproxy.Deps{Broker: approval.NewBroker(actionStore, func() string { return externalURL }, &approval.WSChannel{Hub: hub}), Credentials: credStore, FileKeys: nil, RpID: "localhost", NewConnectionID: func() string { return "id" }},
		Accounts:     &rest.Accounts{Store: store.NewAccounts(db), Creds: credStore, Endpoints: endpointStore, Demo: demoSvc, Now: func() string { return "" }},
		Credentials:  &rest.Credentials{Store: credStore, Admin: fake, StepUp: stepUp},
		Keys:         &rest.Keys{Store: store.NewSSHKeys(db), Accounts: store.NewAccounts(db)},
		AuthSessions: &rest.AuthSessions{Admin: fake, SPAClientID: "shellwatch-web", StepUp: stepUp},
		Push:         &rest.Push{Store: store.NewPushSubs(db, clk), NewID: func() string { return "id" }},
	})
	return h.(chi.Router)
}

// pathParamRe normalizes chi's {param} and OpenAPI's {param} to a placeholder.
var pathParamRe = regexp.MustCompile(`\{[^}]+\}`)

func normPath(p string) string {
	p = pathParamRe.ReplaceAllString(p, "{}")
	// chi mounts /mcp and /mcp/* — collapse the wildcard form.
	p = strings.TrimSuffix(p, "/*")
	return p
}

func TestRouteCoverageAgainstSpec(t *testing.T) {
	// Collect mounted (METHOD path) from the Go router.
	mounted := map[string]bool{}
	err := chi.Walk(fullHandler(t), func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		mounted[method+" "+normPath(route)] = true
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// Parse the spec's operations.
	raw, err := os.ReadFile("../../docs/api/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		Paths map[string]map[string]struct {
			OperationID string `yaml:"operationId"`
		} `yaml:"paths"`
	}
	if err := yaml.Unmarshal(raw, &spec); err != nil {
		t.Fatal(err)
	}

	var missing []string
	total := 0
	for path, methods := range spec.Paths {
		for method, op := range methods {
			if op.OperationID == "" {
				continue // not an operation (e.g. parameters block)
			}
			total++
			key := strings.ToUpper(method) + " " + normPath(path)
			if !mounted[key] {
				missing = append(missing, key+" ("+op.OperationID+")")
			}
		}
	}
	// Guard against a vacuous pass if the spec parse silently yields nothing.
	if total < 50 {
		t.Fatalf("only parsed %d spec operations — expected the full ~54; parse likely broke", total)
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("%d spec operation(s) have no mounted Go route:\n  %s",
			len(missing), strings.Join(missing, "\n  "))
	}
}
