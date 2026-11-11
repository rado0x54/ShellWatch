// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Host-key pinning (#241). The host key arrives during key exchange — before
// any authentication — so the trust decision rides along with the human
// approval the signers already collect: an unpinned endpoint records the
// observed key as provisional ("new"), the approval that authorizes the sign
// also pins it (compare-and-set), and Connect fails closed if a provisional
// key ever reaches an established session without a pin. A key that differs
// from the pin aborts the handshake before authentication, always.
package sshx

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"sync"

	"golang.org/x/crypto/ssh"

	"github.com/rado0x54/shellwatch/internal/terminal"
)

// ObservedHostKey is the host key one connection saw during key exchange.
type ObservedHostKey struct {
	Type        string // SSH wire key type, e.g. "ssh-ed25519"
	Key         []byte // raw SSH wire public key (ssh.PublicKey.Marshal)
	Fingerprint string // SHA256:... (ssh.FingerprintSHA256)
}

// PinnedHostKey is a stored pin. Key is nil for fingerprint-only pins (a
// manual pin from a bare SHA256: fingerprint); those compare on fingerprint
// and cannot drive HostKeyAlgorithms selection.
type PinnedHostKey struct {
	Type        string
	Key         []byte
	Fingerprint string
}

// PinRequest is one approval-driven pin write. Host/Port are the address the
// observing connection dialed: the store must refuse the write when the
// endpoint's address changed while the approval was pending — a key observed
// at the old address must never become the new address's pin. PinnedBy names
// who approved (credential id, "file-key:<label>", "manual", "config",
// "demo"); ActionID names the approval action for the audit trail ("" when
// none).
type PinRequest struct {
	EndpointID string
	Host       string
	Port       int64
	Observed   ObservedHostKey
	PinnedBy   string
	ActionID   string
}

// HostKeys is the pin store sshx depends on (implemented over the endpoints
// table + the in-memory demo pins). A nil HostKeys on ConnectParams is a
// programming error, never an open-door fallback.
type HostKeys interface {
	// Lookup returns the pin for an endpoint id (nil when unpinned).
	Lookup(ctx context.Context, endpointID string) (*PinnedHostKey, error)
	// Pin persists req.Observed as the endpoint's pin, compare-and-set: it
	// must never overwrite a different existing pin, and never pin onto an
	// endpoint whose address no longer matches req.Host/req.Port (return an
	// error instead — the connection then aborts).
	Pin(ctx context.Context, req PinRequest) error
}

// HostKeyStatus is the per-connection pin state the approval UI renders.
type HostKeyStatus string

const (
	// HostKeyUnseen: key exchange has not presented a host key yet.
	HostKeyUnseen HostKeyStatus = ""
	// HostKeyNew: no pin existed; the observed key is provisional until a
	// human approval pins it.
	HostKeyNew HostKeyStatus = "new"
	// HostKeyKnown: the observed key matched the stored pin.
	HostKeyKnown HostKeyStatus = "known"
)

// HostKeyState is the per-connection host-key record shared between the
// HostKeyCallback (writer) and the signers + fail-closed check (readers).
type HostKeyState struct {
	mu       sync.Mutex
	status   HostKeyStatus
	observed ObservedHostKey
	pinned   bool
	dialHost string
	dialPort int64
}

func (s *HostKeyState) observe(status HostKeyStatus, key ObservedHostKey) {
	s.mu.Lock()
	s.status, s.observed = status, key
	s.mu.Unlock()
}

// setDialAddress records the host/port this connection dials; the
// approval-driven pin write is bound to it (the store refuses a pin for an
// endpoint that moved to a different address while the approval was pending).
func (s *HostKeyState) setDialAddress(host string, port int64) {
	s.mu.Lock()
	s.dialHost, s.dialPort = host, port
	s.mu.Unlock()
}

func (s *HostKeyState) dialAddress() (string, int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dialHost, s.dialPort
}

// MarkPinned records that an approval pinned this connection's provisional
// key — later signs on the same connection render as "known".
func (s *HostKeyState) MarkPinned() {
	s.mu.Lock()
	s.pinned = true
	s.mu.Unlock()
}

// Snapshot returns the current state.
func (s *HostKeyState) Snapshot() (HostKeyStatus, ObservedHostKey, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status, s.observed, s.pinned
}

// HostKeyMismatchError aborts a handshake whose server presented a key that
// differs from the pin. It carries both fingerprints for the audit entry and
// the out-of-band notification; recovery is only via the settings UI.
type HostKeyMismatchError struct {
	EndpointID          string
	ObservedKeyType     string
	ObservedFingerprint string
	PinnedFingerprint   string
}

// HostKeyMismatchEvent is the account-facing notification payload a factory
// emits when a dial aborted on a host-key mismatch: no pending action exists
// (the handshake died before authentication), so audit + WS + push are the
// only surfaces that tell the human.
type HostKeyMismatchEvent struct {
	AccountID           string
	EndpointID          string
	EndpointLabel       string
	EndpointAddress     string
	ObservedKeyType     string
	ObservedFingerprint string
	PinnedFingerprint   string
	Trigger             terminal.Trigger
}

// NotifiedError marks an error whose event was already published to the
// account's notification log (#252). HTTP surfaces include the id in the
// error body so the client dedupes against the pushed notification by
// identity instead of matching message text; it changes nothing about the
// error message itself (MCP and logs see the plain chain).
type NotifiedError struct {
	NotificationID string
	Err            error
}

func (e *NotifiedError) Error() string { return e.Err.Error() }
func (e *NotifiedError) Unwrap() error { return e.Err }

func (e *HostKeyMismatchError) Error() string {
	return fmt.Sprintf("host key mismatch: the server presented %s (%s) but %s is pinned for this endpoint; "+
		"connection refused before authentication. If the host key legitimately changed, a human must forget "+
		"the pinned key in Settings -> Endpoints.",
		e.ObservedFingerprint, e.ObservedKeyType, e.PinnedFingerprint)
}

// hostKeyAlgorithmsFor returns the HostKeyAlgorithms list matching a full-key
// pin, so a server with several host keys offers the pinned one (what
// x/crypto's knownhosts.HostKeyAlgorithms does). Fingerprint-only pins return
// nil: the algorithm is unknown, so the server's preference order stands.
func hostKeyAlgorithmsFor(pin *PinnedHostKey) []string {
	if pin == nil || len(pin.Key) == 0 {
		return nil
	}
	key, err := ssh.ParsePublicKey(pin.Key)
	if err != nil {
		return nil
	}
	// An RSA host key signs with the SHA-2 algorithm names; every other type's
	// signature algorithm equals its key type.
	if key.Type() == ssh.KeyAlgoRSA {
		return []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA}
	}
	return []string{key.Type()}
}

// hostKeyCallback verifies the presented key against pin (nil = unpinned) and
// records the outcome in state. Unpinned endpoints record the key as
// provisional and let the handshake continue — the approval during
// authentication is the trust decision, and Connect fails closed if it never
// happens. A mismatch aborts the handshake before any authentication.
func hostKeyCallback(endpointID string, pin *PinnedHostKey, state *HostKeyState) ssh.HostKeyCallback {
	return func(_ string, _ net.Addr, key ssh.PublicKey) error {
		observed := ObservedHostKey{
			Type:        key.Type(),
			Key:         key.Marshal(),
			Fingerprint: ssh.FingerprintSHA256(key),
		}
		// Rekeying runs this callback again on the same connection, and pin is
		// the lookup from before the dial — stale by then. After the first
		// exchange the connection's own observed key is the reference: any
		// mid-connection change aborts, in particular on a first connection
		// whose provisional key an approval pinned in the meantime.
		if st, prev, _ := state.Snapshot(); st != HostKeyUnseen {
			if !bytes.Equal(prev.Key, observed.Key) {
				return &HostKeyMismatchError{
					EndpointID:          endpointID,
					ObservedKeyType:     observed.Type,
					ObservedFingerprint: observed.Fingerprint,
					PinnedFingerprint:   prev.Fingerprint,
				}
			}
			return nil
		}
		if pin == nil {
			state.observe(HostKeyNew, observed)
			return nil
		}
		match := pin.Fingerprint == observed.Fingerprint
		if len(pin.Key) > 0 {
			match = bytes.Equal(pin.Key, observed.Key)
		}
		if !match {
			return &HostKeyMismatchError{
				EndpointID:          endpointID,
				ObservedKeyType:     observed.Type,
				ObservedFingerprint: observed.Fingerprint,
				PinnedFingerprint:   pin.Fingerprint,
			}
		}
		state.observe(HostKeyKnown, observed)
		return nil
	}
}
