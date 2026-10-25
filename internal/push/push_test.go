// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
package push

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	webpush "github.com/SherClockHolmes/webpush-go"

	"github.com/rado0x54/shellwatch/internal/approval"
	"github.com/rado0x54/shellwatch/internal/clock"
	"github.com/rado0x54/shellwatch/internal/store"
)

func TestIsAllowedEndpoint(t *testing.T) {
	allowed := []string{
		"https://fcm.googleapis.com/fcm/send/abc123",
		"https://android.googleapis.com/gcm/send/x",
		"https://updates.push.services.mozilla.com/wpush/v2/token",
		"https://web.push.apple.com/QOTOFC0y",
		"https://db5p.notify.windows.com/w/?token=x",
	}
	for _, e := range allowed {
		if !IsAllowedEndpoint(e) {
			t.Errorf("should allow %s", e)
		}
	}
	denied := []string{
		"http://fcm.googleapis.com/fcm/send/abc123",  // not https
		"https://evil.example.com/collect",           // unknown host
		"https://fcm.googleapis.com.evil.com/x",      // suffix trick
		"https://user:pass@fcm.googleapis.com/x",     // credentials
		"https://notify.windows.com/w",               // bare suffix domain (needs subdomain)
		"not-a-url",                                  //
		"https://internal-service:8080/api/callback", // SSRF target
	}
	for _, e := range denied {
		if IsAllowedEndpoint(e) {
			t.Errorf("should deny %s", e)
		}
	}
}

func pushStore(t *testing.T) *store.PushSubs {
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
	db.ExecContext(ctx, `INSERT INTO accounts (id,name,max_sessions,created_at,updated_at) VALUES ('acc','A',5,'2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')`)
	return store.NewPushSubs(db, clock.Real{})
}

func TestChannelDeliversPayloadAndPrunesExpired(t *testing.T) {
	subs := pushStore(t)
	ctx := context.Background()
	if _, err := subs.Upsert(ctx, "acc", "https://fcm.googleapis.com/send/live", "p", "a", "id1"); err != nil {
		t.Fatal(err)
	}
	if _, err := subs.Upsert(ctx, "acc", "https://fcm.googleapis.com/send/dead", "p", "a", "id2"); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var payloads []string
	ch := NewChannel(subs, Vapid{Subject: "mailto:x@y", PublicKey: "pub", PrivateKey: "priv"})
	ch.send = func(_ context.Context, message []byte, s *webpush.Subscription, _ *webpush.Options) (int, error) {
		mu.Lock()
		defer mu.Unlock()
		payloads = append(payloads, string(message))
		if s.Endpoint == "https://fcm.googleapis.com/send/dead" {
			return 410, nil
		}
		return 201, nil
	}

	action := &approval.Action{
		ID: "act1", AccountID: "acc", Type: approval.TypeWebAuthnSign,
		PasskeyLabel: "My Key", Context: approval.Context{Source: "endpoint-auth"},
	}
	ch.Notify(action, "https://sw.example/sign/act1")

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(payloads)
		mu.Unlock()
		if n == 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(payloads) != 2 {
		t.Fatalf("expected 2 sends, got %d", len(payloads))
	}
	var p map[string]any
	if err := json.Unmarshal([]byte(payloads[0]), &p); err != nil {
		t.Fatal(err)
	}
	if p["title"] != "Passkey Signature Requested" ||
		p["body"] != `Sign with "My Key" for endpoint-auth` ||
		p["actionId"] != "act1" || p["deepLink"] != "/sign/act1" || p["actionType"] != "webauthn-sign" {
		t.Errorf("payload mismatch: %s", payloads[0])
	}

	// The 410 endpoint must be pruned; the live one stays.
	remaining, err := subs.ListForAccount(context.Background(), "acc")
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining) != 1 || remaining[0].Endpoint != "https://fcm.googleapis.com/send/live" {
		t.Fatalf("prune mismatch: %+v", remaining)
	}
}
