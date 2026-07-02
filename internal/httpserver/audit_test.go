// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Audit parity (Phase 5): keyset pagination + filter validation reproduce the
// audit-* goldens, seeding the same rows the Node golden suite uses.
package httpserver

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/rado0x54/shellwatch/internal/audit"
	"github.com/rado0x54/shellwatch/internal/auth"
	"github.com/rado0x54/shellwatch/internal/buildinfo"
	"github.com/rado0x54/shellwatch/internal/config"
	"github.com/rado0x54/shellwatch/internal/golden"
	"github.com/rado0x54/shellwatch/internal/rest"
	"github.com/rado0x54/shellwatch/internal/store"
)

const auditAccount = "test-account-00000000-0000-0000-0000-000000000000"

func auditServer(t *testing.T) *httptest.Server {
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
	db.ExecContext(ctx, `INSERT INTO accounts (id,name,created_at,updated_at) VALUES (?,'Audit','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')`, auditAccount)

	// Session-lifecycle rows (ascending created_at, as the Node suite seeds).
	db.ExecContext(ctx, `INSERT INTO audit_session_lifecycle (session_id,account_id,endpoint_id,source,status,created_at,source_ip) VALUES ('sess_000000000001',?,'audit-endpoint-1','ui','open','2026-01-01T00:00:01.000Z','203.0.113.1')`, auditAccount)
	db.ExecContext(ctx, `INSERT INTO audit_session_lifecycle (session_id,account_id,endpoint_id,source,status,created_at,closed_at,duration_ms,mcp_reason,mcp_client_name,close_reason) VALUES ('sess_000000000002',?,'audit-endpoint-2','mcp','closed','2026-01-01T00:00:02.000Z','2026-01-01T00:00:05.000Z',3000,'deploy hotfix','codex','client.mcp')`, auditAccount)
	db.ExecContext(ctx, `INSERT INTO audit_session_lifecycle (session_id,account_id,endpoint_id,source,status,created_at,close_reason) VALUES ('sess_000000000003',?,'audit-endpoint-3','ssh','error','2026-01-01T00:00:03.000Z','transport-error')`, auditAccount)

	// Signing-request rows.
	db.ExecContext(ctx, `INSERT INTO audit_signing_requests (id,account_id,type,source,created_at,resolved_at,outcome,latency_ms,endpoint_label,endpoint_address,credential_id,passkey_label,user_verification) VALUES ('act_0000000000000000000001',?,'webauthn-sign','endpoint-auth','2026-01-01T00:00:01.000Z','2026-01-01T00:00:02.000Z','approved',1200,'Prod Web','ubuntu@web-01:22','cred-abc','YubiKey 5','required')`, auditAccount)
	db.ExecContext(ctx, `INSERT INTO audit_signing_requests (id,account_id,type,source,created_at,resolved_at,outcome,latency_ms,session_id,key_label,key_fingerprint) VALUES ('act_0000000000000000000002',?,'key-approve','agent-forwarding','2026-01-01T00:00:02.000Z','2026-01-01T00:00:03.000Z','denied',800,'sess_000000000002','deploy key','SHA256:AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKK')`, auditAccount)
	db.ExecContext(ctx, `INSERT INTO audit_signing_requests (id,account_id,type,source,created_at,client_hostname,client_os,client_version) VALUES ('act_0000000000000000000003',?,'webauthn-sign','agent-proxy','2026-01-01T00:00:03.000Z','laptop.local','darwin/arm64','1.2.3')`, auditAccount)

	cfg := &config.Config{}
	cfg.Server.ExternalURL = externalURL
	cfg.Hydra.PublicURL = "http://localhost:4444"
	resolve := auth.Resolver(func(_ context.Context, tok string) *auth.Principal {
		if tok == "ui" {
			return &auth.Principal{AccountID: auditAccount, Scopes: []string{"ui"}}
		}
		return nil
	})
	handler := New(Params{
		Config: cfg, Resolve: resolve, StaticFS: os.DirFS(t.TempDir()), BuildInfo: buildinfo.Info{},
		Audit: &rest.Audit{Sessions: audit.NewSessions(db), Signings: audit.NewSignings(db)},
	})
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	return ts
}

func TestAuditGoldens(t *testing.T) {
	ts := auditServer(t)

	// Sessions page 1 (limit 2) -> 2 rows + cursor.
	_, page1 := doJSON(t, ts, "GET", "/api/audit/sessions?limit=2", "")
	assertBodyGolden(t, "audit-sessions-page1", 200, page1)
	cursor, _ := page1["nextCursor"].(string)
	if cursor == "" {
		t.Fatal("page 1 has no cursor")
	}
	// Page 2 via the real cursor -> last row, no cursor.
	_, page2 := doJSON(t, ts, "GET", "/api/audit/sessions?limit=2&cursor="+cursor, "")
	assertBodyGolden(t, "audit-sessions-page2", 200, page2)

	// Signings page 1 (limit 2).
	_, sp1 := doJSON(t, ts, "GET", "/api/audit/signings?limit=2", "")
	assertBodyGolden(t, "audit-signings-page1", 200, sp1)

	// Signing by id.
	_, byID := doJSON(t, ts, "GET", "/api/audit/signings/act_0000000000000000000001", "")
	assertBodyGolden(t, "audit-signings-by-id", 200, byID)

	// Invalid source filter -> 400.
	st, inv := doJSON(t, ts, "GET", "/api/audit/signings?source=invalid", "")
	assertBodyGolden(t, "audit-signings-invalid-source", st, inv)
}

// assertBodyGolden compares a {status, body} envelope (no request/wwwAuth) to a
// golden — the shape the golden-audit suite captures.
func assertBodyGolden(t *testing.T, name string, status int, body map[string]any) {
	t.Helper()
	got := golden.Normalize(map[string]any{"status": float64(status), "body": body}, golden.Options{})
	raw, err := os.ReadFile(filepath.Join(goldensDir, name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var expected any
	_ = json.Unmarshal(raw, &expected)
	if !reflect.DeepEqual(got, expected) {
		a, _ := json.MarshalIndent(expected, "", "  ")
		b, _ := json.MarshalIndent(got, "", "  ")
		t.Errorf("%s mismatch\n--- golden ---\n%s\n--- go ---\n%s", name, a, b)
	}
}
