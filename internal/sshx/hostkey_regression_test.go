// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Regression (#241 review): the HostKeyCallback runs again on every SSH key
// exchange with the pin that was looked up before the dial. After the first
// exchange the connection's own observed key is the reference — a server that
// presents a different key on rekey must abort, in particular on a first
// connection whose provisional key an approval pinned in the meantime.
package sshx

import (
	"context"
	"errors"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestRekeyRejectsChangedHostKeyAfterFirstApproval(t *testing.T) {
	state := &HostKeyState{}
	keys := newMemHostKeys()
	callback := hostKeyCallback("e1", nil, state)
	first := newHostKeySigner(t).PublicKey()
	if err := callback("", nil, first); err != nil {
		t.Fatal(err)
	}
	_, observed, _ := state.Snapshot()
	if err := pinAfterApproval(context.Background(), keys, state, "e1", &observed, "human", "a1"); err != nil {
		t.Fatal(err)
	}

	// x/crypto calls the same callback again on subsequent key exchanges: the
	// same key passes, a changed key is a mismatch against the approved one.
	if err := callback("", nil, first); err != nil {
		t.Fatalf("rekey with the approved key: %v", err)
	}
	changed := newHostKeySigner(t).PublicKey()
	err := callback("", nil, changed)
	var mismatch *HostKeyMismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("rekey accepted a different host key after the first key was approved and pinned: %v", err)
	}
	if mismatch.PinnedFingerprint != ssh.FingerprintSHA256(first) ||
		mismatch.ObservedFingerprint != ssh.FingerprintSHA256(changed) {
		t.Fatalf("mismatch fields: %+v", mismatch)
	}
	// The rejected rekey must not corrupt the connection's record: it still
	// names the approved key, still marked pinned.
	if st, obs, pinned := state.Snapshot(); st != HostKeyNew || !pinned || obs.Fingerprint != ssh.FingerprintSHA256(first) {
		t.Fatalf("state after rejected rekey: status=%q pinned=%v observed=%s", st, pinned, obs.Fingerprint)
	}
}

// Same hole without an approval in between: a provisional first-connection key
// must also be sticky across exchanges.
func TestRekeyRejectsChangedProvisionalHostKey(t *testing.T) {
	state := &HostKeyState{}
	callback := hostKeyCallback("e1", nil, state)
	if err := callback("", nil, newHostKeySigner(t).PublicKey()); err != nil {
		t.Fatal(err)
	}
	var mismatch *HostKeyMismatchError
	if err := callback("", nil, newHostKeySigner(t).PublicKey()); !errors.As(err, &mismatch) {
		t.Fatalf("provisional key change on rekey must abort, got %v", err)
	}
}
