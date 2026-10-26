// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Host-key pinning behavior (#241) against the in-process gliderlabs server:
// pin-on-first-approval, known-host silence, pre-auth mismatch abort,
// deny-leaves-no-pin, fail-closed on approval-less auth, CAS conflicts, and
// HostKeyAlgorithms selection from the pin.
package sshx

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"

	gliderssh "github.com/gliderlabs/ssh"
	"golang.org/x/crypto/ssh"

	"github.com/rado0x54/shellwatch/internal/approval"
	"github.com/rado0x54/shellwatch/internal/clock"
)

// autoBroker is a real approval store + broker whose pending actions resolve
// (or deny) automatically, recording each action's host-key context.
type autoBroker struct {
	*approval.Broker
	store *approval.Store

	mu       sync.Mutex
	contexts []approval.Context
}

func newAutoBroker(t *testing.T, approve bool) *autoBroker {
	t.Helper()
	n := 0
	store := approval.NewStore(clock.Real{}, func() string { n++; return "act-" + strings.Repeat("x", n) })
	ab := &autoBroker{store: store}
	ab.Broker = approval.NewBroker(store, func() string { return "https://sw.test" })
	store.OnCreated(func(a *approval.Action) {
		ab.mu.Lock()
		ab.contexts = append(ab.contexts, a.Context)
		ab.mu.Unlock()
		id := a.ID
		typ := a.Type
		go func() {
			if !approve {
				store.Deny(id)
				return
			}
			if typ == approval.TypeKeyApprove {
				store.ResolveKey(id)
			}
		}()
	})
	return ab
}

func (ab *autoBroker) actionContexts() []approval.Context {
	ab.mu.Lock()
	defer ab.mu.Unlock()
	return append([]approval.Context(nil), ab.contexts...)
}

// fileKeySignersFor builds the approval-gated file-key signer set wired to
// the shared host-key state, as the passkey factory does.
func fileKeySignersFor(t *testing.T, broker SignBroker, hostKeys HostKeys, state *HostKeyState) []ssh.Signer {
	t.Helper()
	kd := writeTestKeyDir(t)
	raw, err := kd.Signers()
	if err != nil || len(raw) != 1 {
		t.Fatalf("signers: %d %v", len(raw), err)
	}
	return []ssh.Signer{newApprovedFileKeySigner(&approvedFileKeySigner{
		signer: raw[0], broker: broker, accountID: "acc", label: "test key",
		connectionID: "conn-1", actionCtx: approval.Context{Source: "endpoint-auth", TriggerKind: "ui"},
		ctx: context.Background(), endpointID: "e1", hostKeys: hostKeys, hostState: state,
	})}
}

func connectOnce(t *testing.T, host string, port int, hostKeys HostKeys, broker SignBroker) error {
	t.Helper()
	state := &HostKeyState{}
	tr, err := Connect(context.Background(), ConnectParams{
		Host: host, Port: port, Username: "u", EndpointID: "e1",
		HostKeys: hostKeys, HostKeyState: state,
		Signers: fileKeySignersFor(t, broker, hostKeys, state),
	})
	if err == nil {
		tr.Close()
	}
	return err
}

func TestFirstConnectionPinsOnApproval(t *testing.T) {
	host, port, hostPub := startEchoServer(t)
	hostKeys := newMemHostKeys()
	broker := newAutoBroker(t, true)

	if err := connectOnce(t, host, port, hostKeys, broker); err != nil {
		t.Fatalf("first connection: %v", err)
	}
	pin, _ := hostKeys.Lookup(context.Background(), "e1")
	if pin == nil || pin.Fingerprint != ssh.FingerprintSHA256(hostPub) {
		t.Fatalf("approval did not pin the observed key: %+v", pin)
	}
	if hostKeys.byWhom["e1"] != "file-key:test key" {
		t.Errorf("pinnedBy = %q", hostKeys.byWhom["e1"])
	}
	ctxs := broker.actionContexts()
	if len(ctxs) != 1 || ctxs[0].HostKey == nil || ctxs[0].HostKey.Status != "new" ||
		ctxs[0].HostKey.Fingerprint != ssh.FingerprintSHA256(hostPub) {
		t.Fatalf("first approval must carry hostKey status=new: %+v", ctxs)
	}

	// Second connection to the same key: silent on the pin front — the
	// approval renders it as a known host.
	if err := connectOnce(t, host, port, hostKeys, broker); err != nil {
		t.Fatalf("second connection: %v", err)
	}
	ctxs = broker.actionContexts()
	if len(ctxs) != 2 || ctxs[1].HostKey == nil || ctxs[1].HostKey.Status != "known" {
		t.Fatalf("second approval must carry hostKey status=known: %+v", ctxs)
	}
}

func TestMismatchAbortsBeforeAuth(t *testing.T) {
	host, port, _ := startEchoServer(t)
	hostKeys := newMemHostKeys()
	// Pin a DIFFERENT key for the endpoint.
	hostKeys.prePin("e1", newHostKeySigner(t).PublicKey())
	broker := newAutoBroker(t, true)

	err := connectOnce(t, host, port, hostKeys, broker)
	var mismatch *HostKeyMismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("expected HostKeyMismatchError, got %v", err)
	}
	if mismatch.EndpointID != "e1" || mismatch.PinnedFingerprint == mismatch.ObservedFingerprint {
		t.Fatalf("mismatch fields: %+v", mismatch)
	}
	// Automatic denial: the handshake died in key exchange — no pending
	// action was ever created, nothing to approve.
	if n := len(broker.actionContexts()); n != 0 {
		t.Fatalf("mismatch must not create pending actions, got %d", n)
	}
}

func TestDenyOrExpiryLeavesNoPin(t *testing.T) {
	host, port, _ := startEchoServer(t)
	hostKeys := newMemHostKeys()
	broker := newAutoBroker(t, false) // denies every action

	err := connectOnce(t, host, port, hostKeys, broker)
	if err == nil {
		t.Fatal("denied connection must fail")
	}
	if !strings.Contains(err.Error(), "not trusted yet") {
		t.Errorf("denial on an unpinned endpoint should say the host key is not trusted: %v", err)
	}
	if pin, _ := hostKeys.Lookup(context.Background(), "e1"); pin != nil {
		t.Fatalf("deny must not pin, got %+v", pin)
	}
}

// A server that accepts auth without any approval-gated signer (gliderlabs
// with no auth handlers accepts anonymous/none auth) must still not yield a
// session on a provisionally accepted key: fail closed.
func TestFailClosedWithoutApproval(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hostSigner := newHostKeySigner(t)
	srv := &gliderssh.Server{Handler: func(s gliderssh.Session) {
		s.Pty()
		io.WriteString(s, "ready\n")
		io.Copy(io.Discard, s)
	}}
	srv.AddHostKey(hostSigner)
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close(); ln.Close() })
	port := ln.Addr().(*net.TCPAddr).Port

	hostKeys := newMemHostKeys()
	_, err = Connect(context.Background(), ConnectParams{
		Host: "127.0.0.1", Port: port, Username: "u", EndpointID: "e1", HostKeys: hostKeys,
	})
	if err == nil || !strings.Contains(err.Error(), "no approval pinned it") {
		t.Fatalf("expected fail-closed abort, got %v", err)
	}
	if pin, _ := hostKeys.Lookup(context.Background(), "e1"); pin != nil {
		t.Fatalf("fail-closed path must not pin, got %+v", pin)
	}

	// With a pre-provisioned pin the same server connects fine.
	hostKeys.prePin("e1", hostSigner.PublicKey())
	tr, err := Connect(context.Background(), ConnectParams{
		Host: "127.0.0.1", Port: port, Username: "u", EndpointID: "e1", HostKeys: hostKeys,
	})
	if err != nil {
		t.Fatalf("pinned connect: %v", err)
	}
	tr.Close()
}

// Two concurrent first connections where a different key wins the CAS race:
// the losing approval must abort its connection, never ride along.
func TestConflictingPinAbortsApproval(t *testing.T) {
	hostKeys := newMemHostKeys()
	state := &HostKeyState{}
	observed := ObservedHostKey{Type: "ssh-ed25519", Key: []byte{1}, Fingerprint: "SHA256:observed"}
	state.observe(HostKeyNew, observed)

	// Another connection pinned a DIFFERENT key between our observation and
	// our approval.
	hostKeys.prePin("e1", newHostKeySigner(t).PublicKey())

	_, provisional := withHostKeyContext(approval.Context{Source: "endpoint-auth"}, state)
	if provisional == nil {
		t.Fatal("expected a provisional key")
	}
	err := pinAfterApproval(context.Background(), hostKeys, state, "e1", provisional, "cred-1", "act-1")
	if err == nil || !strings.Contains(err.Error(), "host key pin failed") {
		t.Fatalf("conflicting CAS must fail the approval, got %v", err)
	}
	if _, _, pinned := state.Snapshot(); pinned {
		t.Fatal("state must not be marked pinned after a CAS conflict")
	}
}

// With several host keys on the server, the pin drives HostKeyAlgorithms so
// the server offers the pinned key instead of its own preference.
func TestHostKeyAlgorithmsFollowThePin(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaSigner, _ := ssh.NewSignerFromKey(rsaKey)
	edSigner := newHostKeySigner(t)
	srv := &gliderssh.Server{Handler: func(s gliderssh.Session) {
		s.Pty()
		io.WriteString(s, "ready\n")
		io.Copy(io.Discard, s)
	}}
	// ed25519 first: the server's own preference differs from the pin.
	srv.AddHostKey(edSigner)
	srv.AddHostKey(rsaSigner)
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close(); ln.Close() })
	port := ln.Addr().(*net.TCPAddr).Port

	hostKeys := newMemHostKeys()
	hostKeys.prePin("e1", rsaSigner.PublicKey())
	tr, err := Connect(context.Background(), ConnectParams{
		Host: "127.0.0.1", Port: port, Username: "u", EndpointID: "e1", HostKeys: hostKeys,
	})
	if err != nil {
		t.Fatalf("connect with RSA pin against multi-key server: %v", err)
	}
	tr.Close()

	// Fingerprint-only pins can't steer the algorithm; unit-check the helper.
	if algos := hostKeyAlgorithmsFor(&PinnedHostKey{Fingerprint: "SHA256:x"}); algos != nil {
		t.Errorf("fingerprint-only pin must not set HostKeyAlgorithms: %v", algos)
	}
	if algos := hostKeyAlgorithmsFor(&PinnedHostKey{Type: rsaSigner.PublicKey().Type(), Key: rsaSigner.PublicKey().Marshal(), Fingerprint: "SHA256:x"}); len(algos) != 3 || algos[0] != ssh.KeyAlgoRSASHA512 {
		t.Errorf("rsa pin algorithms: %v", algos)
	}
}
