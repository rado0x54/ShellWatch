// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Notification log REST (#252): the keyset-paginated log behind
// /notifications, pinned by the notifications-list golden.
package httpserver

import (
	"context"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/rado0x54/shellwatch/internal/auth"
	"github.com/rado0x54/shellwatch/internal/buildinfo"
	"github.com/rado0x54/shellwatch/internal/clock"
	"github.com/rado0x54/shellwatch/internal/config"
	"github.com/rado0x54/shellwatch/internal/notify"
	"github.com/rado0x54/shellwatch/internal/rest"
	"github.com/rado0x54/shellwatch/internal/store"
)

func notificationsServer(t *testing.T) *httptest.Server {
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
	db.ExecContext(ctx, `INSERT INTO accounts (id,name,created_at,updated_at) VALUES (?,'Notify','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')`, auditAccount)

	clk := clock.NewFake(time.Date(2026, 1, 1, 0, 0, 1, 0, time.UTC))
	svc := notify.NewService(db, clk)
	n := 0
	svc.NewID = func() string { n++; return []string{"ntf_0000000000000000000001", "ntf_0000000000000000000002"}[n-1] }
	svc.Publish(ctx, notify.PublishParams{
		AccountID: auditAccount, Type: "host-key-mismatch", Severity: "error",
		Title:  `Host key MISMATCH — connection to "Prod Web" blocked`,
		Detail: "Endpoint:   Prod Web (ubuntu@web-01:22)\nPresented:  SHA256:observedobservedobservedobservedobservedobs (ssh-ed25519)\nPinned:     SHA256:pinnedpinnedpinnedpinnedpinnedpinnedpinnedp",
		Payload: map[string]any{
			"endpointId": "audit-endpoint-1", "endpointLabel": "Prod Web",
			"endpointAddress": "ubuntu@web-01:22", "keyType": "ssh-ed25519",
			"observedFingerprint": "SHA256:observedobservedobservedobservedobservedobs",
			"pinnedFingerprint":   "SHA256:pinnedpinnedpinnedpinnedpinnedpinnedpinnedp",
			"auditId":             "act_0000000000000000000009",
		},
	})
	clk.Advance(time.Second)
	svc.Publish(ctx, notify.PublishParams{
		AccountID: auditAccount, Type: "future-kind", Severity: "info",
		Title: "A kind this client version does not know",
	})

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
		Notifications: &rest.Notifications{Svc: svc},
	})
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	return ts
}

func TestNotificationsGolden(t *testing.T) {
	ts := notificationsServer(t)
	_, page := doJSON(t, ts, "GET", "/api/notifications", "")
	assertBodyGolden(t, "notifications-list", 200, page)
}
