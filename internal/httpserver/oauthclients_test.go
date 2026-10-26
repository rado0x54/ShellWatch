// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// OAuth client registration log REST (#242): the fourth audit surface, behind
// Audit -> OAuth clients. Pinned by the audit-oauth-clients* goldens.
//
// It is the only audit route that is not account-scoped — DCR and CIMD both
// run before any account exists — so the admin gate is what these tests care
// about most.
package httpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/rado0x54/shellwatch/internal/audit"
	"github.com/rado0x54/shellwatch/internal/auth"
	"github.com/rado0x54/shellwatch/internal/buildinfo"
	"github.com/rado0x54/shellwatch/internal/clock"
	"github.com/rado0x54/shellwatch/internal/config"
	"github.com/rado0x54/shellwatch/internal/rest"
	"github.com/rado0x54/shellwatch/internal/store"
)

// doJSONAs is doJSON with a chosen bearer token (doJSONStepUp varies the
// step-up header, not the bearer).
func doJSONAs(t *testing.T, ts *httptest.Server, method, path, token string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(method, ts.URL+path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out
}

// fakeAdminCheck answers IsAdmin from a fixed set.
type fakeAdminCheck map[string]bool

func (f fakeAdminCheck) IsAdmin(_ context.Context, accountID string) bool { return f[accountID] }

const nonAdminAccount = "test-account-11111111-1111-1111-1111-111111111111"

func oauthClientsServer(t *testing.T) *httptest.Server {
	t.Helper()
	db, err := store.Open("sqlite::memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := store.Migrate(db); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	clk := clock.NewFake(time.Date(2026, 1, 1, 0, 0, 1, 0, time.UTC))
	log := audit.NewOAuthClients(db, clk)
	n := 0
	log.NewID = func() string { n++; return fmt.Sprintf("ocr_%022d", n) }

	// A DCR registration: Hydra minted the id, there is no metadata document.
	log.Record(ctx, audit.OAuthClientEvent{
		ClientID: "07f85190-7ac1-42d8-8a79-49ce076a8721", Origin: audit.OriginDCR,
		Event: audit.EventRegistered, ClientName: "MCP Inspector", AuthMethod: "none",
		RedirectURIs: []string{"http://localhost:6274/oauth/callback"},
		Scope:        "mcp offline_access", SourceIP: "203.0.113.1",
	})
	clk.Advance(time.Second)
	// A CIMD registration: the client_id IS the document URL.
	log.Record(ctx, audit.OAuthClientEvent{
		ClientID: "https://apps.example.com/.well-known/client.json", Origin: audit.OriginCIMD,
		Event: audit.EventRegistered, ClientName: "Example MCP Client",
		MetadataHost: "apps.example.com", AuthMethod: "none",
		RedirectURIs: []string{"http://127.0.0.1/callback", "http://[::1]/callback"},
		Scope:        "mcp offline_access", SourceIP: "203.0.113.2",
	})
	clk.Advance(time.Second)
	// A CIMD refresh whose document changed its authentication shape.
	log.Record(ctx, audit.OAuthClientEvent{
		ClientID: "https://apps.example.com/.well-known/client.json", Origin: audit.OriginCIMD,
		Event: audit.EventRefreshed, ClientName: "Example MCP Client",
		MetadataHost: "apps.example.com", AuthMethod: "private_key_jwt",
		RedirectURIs: []string{"http://127.0.0.1/callback", "http://[::1]/callback"},
		Scope:        "mcp offline_access", SourceIP: "203.0.113.2",
		Reason: "authentication keys or method changed",
	})
	clk.Advance(time.Second)
	// A rejection: no Hydra client exists for this row at all.
	log.Record(ctx, audit.OAuthClientEvent{
		ClientID: "https://evil.example.net/client.json", Origin: audit.OriginCIMD,
		Event: audit.EventRejected, MetadataHost: "evil.example.net",
		Reason: "invalid_client: client metadata unavailable", SourceIP: "203.0.113.9",
	})

	cfg := &config.Config{}
	cfg.Server.ExternalURL = externalURL
	cfg.Hydra.PublicURL = "http://localhost:4444"
	resolve := auth.Resolver(func(_ context.Context, tok string) *auth.Principal {
		switch tok {
		case "ui":
			return &auth.Principal{AccountID: auditAccount, Scopes: []string{"ui"}}
		case "ui-nonadmin":
			return &auth.Principal{AccountID: nonAdminAccount, Scopes: []string{"ui"}}
		}
		return nil
	})
	handler := New(Params{
		Config: cfg, Resolve: resolve, StaticFS: os.DirFS(t.TempDir()), BuildInfo: buildinfo.Info{},
		Audit: &rest.Audit{
			OAuthClients: log,
			IsAdmin:      fakeAdminCheck{auditAccount: true},
		},
	})
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	return ts
}

func TestAuditOAuthClientsGolden(t *testing.T) {
	ts := oauthClientsServer(t)
	status, page := doJSON(t, ts, "GET", "/api/audit/oauth-clients", "")
	assertBodyGolden(t, "audit-oauth-clients", status, page)
}

// The whole surface is admin-only: these rows are pre-account, so there is no
// account filter standing between a caller and every client on the server.
func TestAuditOAuthClientsForbiddenForNonAdmin(t *testing.T) {
	ts := oauthClientsServer(t)
	status, body := doJSONAs(t, ts, "GET", "/api/audit/oauth-clients", "ui-nonadmin")
	assertBodyGolden(t, "audit-oauth-clients-forbidden", status, body)
	if status != 403 {
		t.Fatalf("status = %d, want 403", status)
	}
	// Nothing may leak alongside the error.
	if _, present := body["rows"]; present {
		t.Error("a forbidden response must not carry rows")
	}
}

func TestAuditOAuthClientsInvalidFilter(t *testing.T) {
	ts := oauthClientsServer(t)
	status, body := doJSON(t, ts, "GET", "/api/audit/oauth-clients?origin=bogus", "")
	assertBodyGolden(t, "audit-oauth-clients-invalid-origin", status, body)

	if s, _ := doJSON(t, ts, "GET", "/api/audit/oauth-clients?event=bogus", ""); s != 400 {
		t.Errorf("invalid event filter: status = %d, want 400", s)
	}
}

func TestAuditOAuthClientsFiltersAndPagination(t *testing.T) {
	ts := oauthClientsServer(t)

	status, page := doJSON(t, ts, "GET", "/api/audit/oauth-clients?origin=cimd", "")
	if status != 200 {
		t.Fatalf("status = %d", status)
	}
	rows, _ := page["rows"].([]any)
	if len(rows) != 3 {
		t.Errorf("origin=cimd rows = %d, want 3", len(rows))
	}

	_, page = doJSON(t, ts, "GET", "/api/audit/oauth-clients?event=rejected", "")
	rows, _ = page["rows"].([]any)
	if len(rows) != 1 {
		t.Errorf("event=rejected rows = %d, want 1", len(rows))
	}

	// The full history of one client_id, newest first.
	_, page = doJSON(t, ts, "GET",
		"/api/audit/oauth-clients?clientId=https%3A%2F%2Fapps.example.com%2F.well-known%2Fclient.json", "")
	rows, _ = page["rows"].([]any)
	if len(rows) != 2 {
		t.Fatalf("clientId rows = %d, want 2", len(rows))
	}
	first, _ := rows[0].(map[string]any)
	if first["event"] != "refreshed" {
		t.Errorf("newest event = %v, want refreshed", first["event"])
	}

	// Paging yields a cursor and never repeats a row.
	_, page = doJSON(t, ts, "GET", "/api/audit/oauth-clients?limit=2", "")
	rows, _ = page["rows"].([]any)
	if len(rows) != 2 || page["nextCursor"] == nil {
		t.Fatalf("limit=2: rows=%d cursor=%v", len(rows), page["nextCursor"])
	}
}
