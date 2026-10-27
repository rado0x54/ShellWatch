// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// The OAuth client registration log (#242): append-only, not account-scoped,
// and deliberately decoupled from Hydra's client lifecycle.
package audit

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/rado0x54/shellwatch/internal/clock"
	"github.com/rado0x54/shellwatch/internal/store"
)

func oauthLogFixture(t *testing.T) (*OAuthClients, *clock.Fake, *sql.DB) {
	t.Helper()
	db, err := store.Open("sqlite::memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := store.Migrate(db); err != nil {
		t.Fatal(err)
	}
	clk := clock.NewFake(time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC))
	o := NewOAuthClients(db, clk)
	seq := 0
	o.NewID = func() string {
		seq++
		return "row_" + string(rune('a'+seq-1))
	}
	return o, clk, db
}

func TestOAuthClientLogRecordsCimdAndDcr(t *testing.T) {
	o, clk, _ := oauthLogFixture(t)
	ctx := context.Background()

	o.Record(ctx, OAuthClientEvent{
		ClientID: "https://apps.example.com/client.json", Origin: OriginCIMD,
		Event: EventRegistered, ClientName: "Example MCP Client",
		MetadataHost: "apps.example.com", AuthMethod: "none",
		RedirectURIs: []string{"http://127.0.0.1/callback"},
		Scope:        "mcp offline_access", SourceIP: "203.0.113.7",
	})
	clk.Advance(time.Second)
	o.Record(ctx, OAuthClientEvent{
		ClientID: "07f85190-7ac1-42d8-8a79-49ce076a8721", Origin: OriginDCR,
		Event: EventRegistered, ClientName: "MCP Inspector", AuthMethod: "none",
		RedirectURIs: []string{"http://localhost:6274/cb"},
		Scope:        "mcp offline_access", SourceIP: "198.51.100.3",
	})

	page, err := o.List(ctx, OAuthClientFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Rows) != 2 {
		t.Fatalf("rows = %d, want 2", len(page.Rows))
	}
	// Newest first.
	if page.Rows[0].Origin != OriginDCR || page.Rows[1].Origin != OriginCIMD {
		t.Fatalf("order = %q,%q; want dcr,cimd (newest first)",
			page.Rows[0].Origin, page.Rows[1].Origin)
	}
	cimd := page.Rows[1]
	if cimd.ClientID != "https://apps.example.com/client.json" {
		t.Errorf("clientId = %q", cimd.ClientID)
	}
	if cimd.MetadataHost == nil || *cimd.MetadataHost != "apps.example.com" {
		t.Errorf("metadataHost = %v", cimd.MetadataHost)
	}
	if len(cimd.RedirectURIs) != 1 || cimd.RedirectURIs[0] != "http://127.0.0.1/callback" {
		t.Errorf("redirectUris = %v", cimd.RedirectURIs)
	}
	if cimd.SourceIP == nil || *cimd.SourceIP != "203.0.113.7" {
		t.Errorf("sourceIp = %v", cimd.SourceIP)
	}
	if cimd.Reason != nil {
		t.Errorf("reason = %v, want nil on a registration", cimd.Reason)
	}
	// DCR has no metadata document, so no host.
	if page.Rows[0].MetadataHost != nil {
		t.Errorf("DCR metadataHost = %v, want nil", page.Rows[0].MetadataHost)
	}
}

// A rejection has no Hydra client at all — that is exactly why the log cannot
// be a registry keyed by client_id.
func TestOAuthClientLogRecordsRejectionsWithNoClient(t *testing.T) {
	o, _, _ := oauthLogFixture(t)
	ctx := context.Background()

	o.Record(ctx, OAuthClientEvent{
		ClientID: "https://evil.example.net/client.json", Origin: OriginCIMD,
		Event: EventRejected, MetadataHost: "evil.example.net",
		Reason: "invalid_client: client metadata unavailable", SourceIP: "203.0.113.9",
	})

	page, err := o.List(ctx, OAuthClientFilter{Event: EventRejected})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(page.Rows))
	}
	r := page.Rows[0]
	if r.Reason == nil || !strings.Contains(*r.Reason, "metadata unavailable") {
		t.Errorf("reason = %v", r.Reason)
	}
	if r.ClientName != nil {
		t.Errorf("clientName = %v, want nil (no document was accepted)", r.ClientName)
	}
	if len(r.RedirectURIs) != 0 {
		t.Errorf("redirectUris = %v, want empty", r.RedirectURIs)
	}
}

// The log holds history, not state: nothing links it to Hydra's clients, so a
// client that no longer exists keeps its trail.
func TestOAuthClientLogKeepsHistoryAfterRefresh(t *testing.T) {
	o, clk, _ := oauthLogFixture(t)
	ctx := context.Background()
	const id = "https://apps.example.com/client.json"

	o.Record(ctx, OAuthClientEvent{
		ClientID: id, Origin: OriginCIMD, Event: EventRegistered,
		ClientName: "Example App", MetadataHost: "apps.example.com",
	})
	clk.Advance(time.Hour)
	o.Record(ctx, OAuthClientEvent{
		ClientID: id, Origin: OriginCIMD, Event: EventRefreshed,
		ClientName: "Example App v2", MetadataHost: "apps.example.com",
		Reason: "authentication keys or method changed",
	})

	page, err := o.List(ctx, OAuthClientFilter{ClientID: id})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Rows) != 2 {
		t.Fatalf("rows = %d, want 2 — a refresh appends, it does not overwrite", len(page.Rows))
	}
	// The old snapshot is preserved verbatim.
	if got := page.Rows[1].ClientName; got == nil || *got != "Example App" {
		t.Errorf("earliest clientName = %v, want the original snapshot", got)
	}
	if got := page.Rows[0].ClientName; got == nil || *got != "Example App v2" {
		t.Errorf("newest clientName = %v", got)
	}
}

func TestOAuthClientLogFilters(t *testing.T) {
	o, clk, _ := oauthLogFixture(t)
	ctx := context.Background()
	for _, ev := range []OAuthClientEvent{
		{ClientID: "a", Origin: OriginCIMD, Event: EventRegistered},
		{ClientID: "b", Origin: OriginDCR, Event: EventRegistered},
		{ClientID: "a", Origin: OriginCIMD, Event: EventRejected},
		{ClientID: "c", Origin: OriginDCR, Event: EventRejected},
	} {
		o.Record(ctx, ev)
		clk.Advance(time.Second)
	}

	tests := []struct {
		name   string
		filter OAuthClientFilter
		want   int
	}{
		{"no filter", OAuthClientFilter{}, 4},
		{"by origin cimd", OAuthClientFilter{Origin: OriginCIMD}, 2},
		{"by origin dcr", OAuthClientFilter{Origin: OriginDCR}, 2},
		{"by event rejected", OAuthClientFilter{Event: EventRejected}, 2},
		{"by client", OAuthClientFilter{ClientID: "a"}, 2},
		{"combined", OAuthClientFilter{ClientID: "a", Event: EventRegistered}, 1},
		{"no match", OAuthClientFilter{ClientID: "zzz"}, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			page, err := o.List(ctx, tc.filter)
			if err != nil {
				t.Fatal(err)
			}
			if len(page.Rows) != tc.want {
				t.Fatalf("rows = %d, want %d", len(page.Rows), tc.want)
			}
		})
	}
}

func TestOAuthClientLogKeysetPagination(t *testing.T) {
	o, clk, _ := oauthLogFixture(t)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		o.Record(ctx, OAuthClientEvent{
			ClientID: "c", Origin: OriginCIMD, Event: EventRegistered,
		})
		clk.Advance(time.Second)
	}

	page, err := o.List(ctx, OAuthClientFilter{Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Rows) != 2 || page.NextCursor == nil {
		t.Fatalf("first page: rows=%d cursor=%v", len(page.Rows), page.NextCursor)
	}
	seen := map[string]bool{}
	total := 0
	cursor := ""
	for {
		p, err := o.List(ctx, OAuthClientFilter{Limit: 2, Cursor: cursor})
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range p.Rows {
			if seen[r.ID] {
				t.Fatalf("row %s returned twice", r.ID)
			}
			seen[r.ID] = true
			total++
		}
		if p.NextCursor == nil {
			break
		}
		cursor = *p.NextCursor
	}
	if total != 5 {
		t.Fatalf("paged %d rows, want 5", total)
	}

	// A garbage cursor must not silently return a wrong page.
	p, err := o.List(ctx, OAuthClientFilter{Cursor: "not-base64!!"})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Rows) != 5 {
		t.Errorf("bad cursor: rows = %d, want the unpaginated page", len(p.Rows))
	}
}

// An empty page must serialize as [] rather than null.
func TestOAuthClientLogEmptyPageIsNonNil(t *testing.T) {
	o, _, _ := oauthLogFixture(t)
	page, err := o.List(context.Background(), OAuthClientFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if page.Rows == nil {
		t.Fatal("rows must be non-nil")
	}
	if len(page.Rows) != 0 || page.NextCursor != nil {
		t.Fatalf("page = %+v", page)
	}
}

// The table carries no account_id: both onboarding paths run before any
// account is identified, so there is nothing to scope a row to.
func TestOAuthClientLogIsNotAccountScoped(t *testing.T) {
	_, _, db := oauthLogFixture(t)
	if _, err := db.Exec(`SELECT account_id FROM oauth_client_registrations LIMIT 1`); err == nil {
		t.Fatal("oauth_client_registrations must not have an account_id column")
	}
	// And no FK to accounts: a row survives with no accounts row present.
	o := NewOAuthClients(db, clock.NewFake(time.Unix(0, 0)))
	o.Record(context.Background(), OAuthClientEvent{
		ClientID: "c", Origin: OriginDCR, Event: EventRegistered,
	})
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM oauth_client_registrations`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("rows = %d, want 1", n)
	}
}
