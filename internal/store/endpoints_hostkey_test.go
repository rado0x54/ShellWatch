// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Host-key pin storage (#241): compare-and-set semantics of PinHostKey, the
// atomic pin clear on host/port updates, and the address-match lookup used by
// config provisioning.
package store

import (
	"context"
	"errors"
	"testing"
)

func hostKeyTestDB(t *testing.T) *Endpoints {
	t.Helper()
	db, err := Open("sqlite::memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := Migrate(db); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := db.ExecContext(ctx,
		`INSERT INTO accounts (id, name, created_at, updated_at) VALUES ('acc', 'A', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	eps := NewEndpoints(db, nil)
	if err := eps.Create(ctx, Endpoint{
		ID: "e1", AccountID: "acc", Label: "Box", Host: "h.example", Port: 22,
		Username: "u", UserVerification: "required", AgentForward: true,
	}); err != nil {
		t.Fatal(err)
	}
	return eps
}

func TestPinHostKeyCAS(t *testing.T) {
	eps := hostKeyTestDB(t)
	ctx := context.Background()
	rec := HostKeyRecord{Type: "ssh-ed25519", Key: []byte{1, 2, 3}, Fingerprint: "SHA256:aaa"}

	if err := eps.PinHostKey(ctx, "e1", rec, "cred-1"); err != nil {
		t.Fatalf("first pin: %v", err)
	}
	// Idempotent re-pin of the same fingerprint (two first connections to the
	// same honest host).
	if err := eps.PinHostKey(ctx, "e1", rec, "cred-2"); err != nil {
		t.Fatalf("same-key re-pin must be a no-op: %v", err)
	}
	// A different key loses the CAS.
	err := eps.PinHostKey(ctx, "e1", HostKeyRecord{Type: "ssh-ed25519", Key: []byte{9}, Fingerprint: "SHA256:bbb"}, "cred-3")
	if !errors.Is(err, ErrHostKeyPinned) {
		t.Fatalf("conflicting pin: %v", err)
	}
	// The stored pin is untouched.
	got, err := eps.GetHostKey(ctx, "e1")
	if err != nil || got == nil || got.Fingerprint != "SHA256:aaa" || string(got.Key) != string(rec.Key) {
		t.Fatalf("pin after conflict: %+v err=%v", got, err)
	}
	// Pin metadata on reads.
	ep, _ := eps.GetForAccount(ctx, "e1", "acc")
	if ep.HostKey == nil || ep.HostKey.PinnedBy != "cred-1" || ep.HostKey.Fingerprint != "SHA256:aaa" || ep.HostKey.PinnedAt == "" {
		t.Fatalf("read-side pin: %+v", ep.HostKey)
	}
}

func TestUpdateClearsPinOnAddressChange(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name    string
		mutate  func(*Endpoint)
		cleared bool
	}{
		{"label change keeps the pin", func(e *Endpoint) { e.Label = "Renamed" }, false},
		{"username change keeps the pin", func(e *Endpoint) { e.Username = "other" }, false},
		{"host change clears the pin", func(e *Endpoint) { e.Host = "evil.example" }, true},
		{"port change clears the pin", func(e *Endpoint) { e.Port = 2222 }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			eps := hostKeyTestDB(t)
			if err := eps.PinHostKey(ctx, "e1", HostKeyRecord{Type: "ssh-ed25519", Key: []byte{1}, Fingerprint: "SHA256:aaa"}, "cred-1"); err != nil {
				t.Fatal(err)
			}
			ep, _ := eps.GetForAccount(ctx, "e1", "acc")
			merged := *ep
			tc.mutate(&merged)
			if ok, err := eps.Update(ctx, merged); !ok || err != nil {
				t.Fatalf("update: ok=%v err=%v", ok, err)
			}
			after, _ := eps.GetForAccount(ctx, "e1", "acc")
			if tc.cleared && after.HostKey != nil {
				t.Fatalf("pin should be cleared, still %+v", after.HostKey)
			}
			if !tc.cleared && after.HostKey == nil {
				t.Fatal("pin should survive")
			}
		})
	}
}

func TestClearHostKeyAndAddressLookup(t *testing.T) {
	eps := hostKeyTestDB(t)
	ctx := context.Background()

	// Clear with no pin: reports false (nothing cleared).
	if cleared, err := eps.ClearHostKey(ctx, "e1", "acc"); cleared || err != nil {
		t.Fatalf("clear without pin: %v %v", cleared, err)
	}
	if err := eps.PinHostKey(ctx, "e1", HostKeyRecord{Fingerprint: "SHA256:aaa"}, "manual"); err != nil {
		t.Fatal(err)
	}
	// Foreign account cannot clear.
	if cleared, _ := eps.ClearHostKey(ctx, "e1", "other"); cleared {
		t.Fatal("cross-account clear must not work")
	}
	if cleared, err := eps.ClearHostKey(ctx, "e1", "acc"); !cleared || err != nil {
		t.Fatalf("clear: %v %v", cleared, err)
	}
	if rec, _ := eps.GetHostKey(ctx, "e1"); rec != nil {
		t.Fatalf("pin survived clear: %+v", rec)
	}

	// Address lookup (config provisioning).
	rows, err := eps.ListByAddress(ctx, "acc", "h.example", 22, "u")
	if err != nil || len(rows) != 1 || rows[0].ID != "e1" || rows[0].PinnedFingerprint != "" {
		t.Fatalf("ListByAddress: %+v err=%v", rows, err)
	}
	if rows, _ := eps.ListByAddress(ctx, "acc", "h.example", 2222, "u"); len(rows) != 0 {
		t.Fatalf("port-mismatched address lookup: %+v", rows)
	}
}
