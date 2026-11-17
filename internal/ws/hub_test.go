// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
package ws

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/rado0x54/shellwatch/internal/clock"
	"github.com/rado0x54/shellwatch/internal/terminal"
)

// An errored session is listed until the Manager removes it; when retention
// expires it, the browser gets a fresh sessions:changed without it (the
// removal is a list change; no status event follows it).
func TestHubRefreshesListWhenRetainedSessionIsRemoved(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	mock := terminal.NewMockTransport()
	t.Cleanup(func() { _ = mock.Close() })
	mgr := terminal.NewManager(func(context.Context, terminal.FactoryParams) (terminal.Transport, error) {
		return mock, nil
	}, clk, 0)
	hub := NewHub(mgr)
	t.Cleanup(hub.Close)
	s, client := wsPair(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = hub.Serve(ctx, s, "acc") }()

	lists := make(chan []map[string]any, 32)
	go func() {
		for {
			_, raw, err := client.Read(context.Background())
			if err != nil {
				return
			}
			var f struct {
				Type     string           `json:"type"`
				Sessions []map[string]any `json:"sessions"`
			}
			if json.Unmarshal(raw, &f) == nil && f.Type == "sessions:changed" {
				lists <- f.Sessions
			}
		}
	}()
	waitList := func(what string, ok func([]map[string]any) bool) {
		t.Helper()
		timeout := time.After(5 * time.Second)
		for {
			select {
			case l := <-lists:
				if ok(l) {
					return
				}
			case <-timeout:
				t.Fatalf("no sessions:changed %s", what)
			}
		}
	}

	ep := terminal.EndpointRef{ID: "e1", AccountID: "acc", Host: "h", Port: 22, Username: "u"}
	sess, err := mgr.Create(context.Background(), ep, "acc", terminal.Trigger{Kind: terminal.SourceUI})
	if err != nil {
		t.Fatal(err)
	}
	mock.Fail(errors.New("connection reset"))
	waitList("listing the errored session", func(l []map[string]any) bool {
		return len(l) == 1 && l[0]["sessionId"] == sess.SessionID && l[0]["status"] == "error"
	})
	clk.Advance(terminal.EndedRetention)
	mgr.SweepEnded()
	waitList("without the expired session", func(l []map[string]any) bool { return len(l) == 0 })

	// Another account's connection gets nothing for that removal.
	other := newConn(nil, "other")
	hub.add(other)
	t.Cleanup(func() { hub.remove(other) })
	hub.onRemoved(terminal.RemovedEvent{SessionID: "x", AccountID: "acc", Reason: terminal.RemovedExpired})
	if n := len(other.out); n != 0 {
		t.Errorf("another account got %d frames for acc's removal", n)
	}
	// An explicit close already broadcast its status: no extra list.
	hub.onRemoved(terminal.RemovedEvent{SessionID: "y", AccountID: "other", Reason: terminal.RemovedClosed})
	if n := len(other.out); n != 0 {
		t.Errorf("explicit close removal sent %d extra frames", n)
	}
}
