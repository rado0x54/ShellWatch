// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Regression (#241 review): a pin write is bound to the address the key was
// observed at — an approval that waited while the endpoint moved to a new
// host/port must not store the old host's key on the new address.
package store

import (
	"context"
	"errors"
	"testing"
)

func TestPendingApprovalCannotPinKeyAfterAddressChange(t *testing.T) {
	eps := hostKeyTestDB(t)
	ctx := context.Background()
	// A connection has observed h.example's key and is waiting for approval.
	ep, err := eps.GetForAccount(ctx, "e1", "acc")
	if err != nil {
		t.Fatal(err)
	}
	ep.Host = "new.example"
	if ok, err := eps.Update(ctx, *ep); err != nil || !ok {
		t.Fatalf("update endpoint: ok=%v err=%v", ok, err)
	}

	// The approval of the connection to h.example now arrives. The write is
	// bound to the observed address, so it must fail — never trust the new one.
	err = eps.PinHostKey(ctx, PinHostKeyParams{
		ID: "e1", Host: "h.example", Port: 22,
		Record: HostKeyRecord{Fingerprint: "SHA256:old-host"}, PinnedBy: "human",
	})
	if !errors.Is(err, ErrEndpointAddressChanged) {
		t.Fatalf("stale pin must fail with ErrEndpointAddressChanged, got %v", err)
	}
	after, err := eps.GetForAccount(ctx, "e1", "acc")
	if err != nil {
		t.Fatal(err)
	}
	if after.HostKey != nil {
		t.Fatalf("approval for old address pinned %s on %s", after.HostKey.Fingerprint, after.Host)
	}

	// At the endpoint's current address the pin lands normally.
	if err := eps.PinHostKey(ctx, PinHostKeyParams{
		ID: "e1", Host: "new.example", Port: 22,
		Record: HostKeyRecord{Fingerprint: "SHA256:new-host"}, PinnedBy: "human",
	}); err != nil {
		t.Fatalf("pin at the current address: %v", err)
	}
}
