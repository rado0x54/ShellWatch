// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// None-auth refusal (#311): a server that accepts SSH "none" authentication
// completes the handshake before any signer is asked, so no human approved
// the connection. Connect must refuse it — pinned or not — before any channel
// is opened, and the factory must report it exactly once.
package sshx

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	gliderssh "github.com/gliderlabs/ssh"
	"golang.org/x/crypto/ssh"

	"github.com/rado0x54/shellwatch/internal/approval"
	"github.com/rado0x54/shellwatch/internal/clock"
	"github.com/rado0x54/shellwatch/internal/terminal"
)

// startNoneAuthServer starts a gliderlabs server with no auth handlers, which
// makes it accept "none". channels counts every channel open that reaches it.
func startNoneAuthServer(t *testing.T) (port int, hostPub ssh.PublicKey, channels *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hostSigner := newHostKeySigner(t)
	channels = &atomic.Int32{}
	srv := &gliderssh.Server{
		Handler: func(s gliderssh.Session) {
			s.Pty()
			io.WriteString(s, "ready\n")
			io.Copy(io.Discard, s)
		},
		ChannelHandlers: map[string]gliderssh.ChannelHandler{
			"session": func(srv *gliderssh.Server, conn *ssh.ServerConn, newChan ssh.NewChannel, ctx gliderssh.Context) {
				channels.Add(1)
				gliderssh.DefaultSessionHandler(srv, conn, newChan, ctx)
			},
		},
	}
	srv.AddHostKey(hostSigner)
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close(); ln.Close() })
	return ln.Addr().(*net.TCPAddr).Port, hostSigner.PublicKey(), channels
}

func assertRefusal(t *testing.T, err error, hostPub ssh.PublicKey) {
	t.Helper()
	var unauth *UnauthenticatedEndpointError
	if !errors.As(err, &unauth) {
		t.Fatalf("expected UnauthenticatedEndpointError, got %v", err)
	}
	if !strings.Contains(err.Error(), "the endpoint accepted the connection without authentication; ShellWatch refuses such connections") {
		t.Errorf("refusal wording: %v", err)
	}
	if strings.Contains(err.Error(), authFailedMessage) {
		t.Errorf("refusal must not use the auth-failure wording: %v", err)
	}
	if strings.Contains(err.Error(), "no approval pinned it") {
		t.Errorf("refusal must run before the provisional-key backstop: %v", err)
	}
	if unauth.EndpointID != "e1" || unauth.HostKeyFingerprint != ssh.FingerprintSHA256(hostPub) {
		t.Errorf("refusal fields: %+v", unauth)
	}
}

func TestNoneAuthRefused(t *testing.T) {
	for _, pinned := range []bool{true, false} {
		name := "unpinned"
		if pinned {
			name = "pinned"
		}
		t.Run(name, func(t *testing.T) {
			port, hostPub, channels := startNoneAuthServer(t)
			hostKeys := newMemHostKeys()
			if pinned {
				hostKeys.prePin("e1", hostPub)
			}
			broker := newAutoBroker(t, true) // would approve anything it was asked
			err := connectOnce(t, "127.0.0.1", port, hostKeys, broker)
			assertRefusal(t, err, hostPub)

			if n := len(broker.actionContexts()); n != 0 {
				t.Errorf("no sign request may be raised, got %d", n)
			}
			if n := channels.Load(); n != 0 {
				t.Errorf("no channel may reach the server, got %d", n)
			}
			pin, _ := hostKeys.Lookup(context.Background(), "e1")
			if pinned && (pin == nil || pin.Fingerprint != ssh.FingerprintSHA256(hostPub)) {
				t.Errorf("existing pin changed: %+v", pin)
			}
			if !pinned && pin != nil {
				t.Errorf("an unpinned host must stay unpinned, got %+v", pin)
			}
		})
	}
}

// noneAuthFactory is the production factory with an approval-gated file key,
// recording the out-of-band hooks.
type noneAuthFactory struct {
	mu         sync.Mutex
	unauth     []UnauthenticatedEndpointEvent
	mismatches int
	ended      int
	notifID    string
	actions    atomic.Int32
}

func (f *noneAuthFactory) build(t *testing.T, hostKeys HostKeys) terminal.TransportFactory {
	t.Helper()
	actionStore := approval.NewStore(clock.Real{}, newUUIDForTest())
	actionStore.OnCreated(func(a *approval.Action) {
		f.actions.Add(1)
		go actionStore.ResolveKey(a.ID)
	})
	params, _ := fileKeyParams(t, true, actionStore)
	params.HostKeys = hostKeys
	params.OnUnauthenticatedEndpoint = func(ev UnauthenticatedEndpointEvent) string {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.unauth = append(f.unauth, ev)
		return f.notifID
	}
	params.OnHostKeyMismatch = func(HostKeyMismatchEvent) string {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.mismatches++
		return "ntf-mismatch"
	}
	params.OnConnectionEnded = func(string, string) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.ended++
	}
	return NewPasskeyFactory(params)
}

func TestNoneAuthFactoryNotifiesOnce(t *testing.T) {
	triggers := []terminal.Trigger{
		{Kind: terminal.SourceUI, SourceIP: "203.0.113.7"},
		{Kind: terminal.SourceMCP, MCPClientName: "codex", MCPClientVer: "1.2.3"},
	}
	for _, trig := range triggers {
		t.Run(string(trig.Kind), func(t *testing.T) {
			port, hostPub, channels := startNoneAuthServer(t)
			hostKeys := newMemHostKeys()
			hostKeys.prePin("e1", hostPub)
			f := &noneAuthFactory{notifID: "ntf-1"}
			mgr := terminal.NewManager(f.build(t, hostKeys), clock.Real{}, 0)
			ep := terminal.EndpointRef{ID: "e1", AccountID: "acc", Label: "Open Box", Host: "127.0.0.1", Port: port, Username: "deploy"}

			sess, err := mgr.Create(context.Background(), ep, "acc", trig)
			if err == nil {
				mgr.Close(sess.SessionID, terminal.CloseClientUI)
				t.Fatal("a none-auth endpoint must yield no session")
			}
			assertRefusal(t, err, hostPub)
			var notified *NotifiedError
			if !errors.As(err, &notified) || notified.NotificationID != "ntf-1" {
				t.Fatalf("refusal must carry the notification id, got %v", err)
			}
			if len(mgr.ListForAccount("acc")) != 0 {
				t.Errorf("failed creation must not stay in the session list")
			}

			f.mu.Lock()
			defer f.mu.Unlock()
			if len(f.unauth) != 1 || f.mismatches != 0 {
				t.Fatalf("hooks: unauth=%d mismatch=%d, want exactly one unauth", len(f.unauth), f.mismatches)
			}
			ev := f.unauth[0]
			if ev.AccountID != "acc" || ev.EndpointID != "e1" || ev.EndpointLabel != "Open Box" ||
				ev.EndpointAddress != "deploy@127.0.0.1:"+strconv.Itoa(port) || ev.RemoteUser != "deploy" ||
				ev.HostKeyFingerprint != ssh.FingerprintSHA256(hostPub) || ev.Trigger != trig {
				t.Errorf("event: %+v", ev)
			}
			if f.ended != 1 {
				t.Errorf("OnConnectionEnded calls = %d, want 1", f.ended)
			}
			if n := f.actions.Load(); n != 0 {
				t.Errorf("no sign request may be raised, got %d", n)
			}
			if n := channels.Load(); n != 0 {
				t.Errorf("no channel may reach the server, got %d", n)
			}
		})
	}
}

// The refusal does not depend on the bookkeeping: with no notification
// persisted the error is still the distinct refusal, without an id.
func TestNoneAuthRefusedWithoutNotification(t *testing.T) {
	port, hostPub, _ := startNoneAuthServer(t)
	hostKeys := newMemHostKeys()
	hostKeys.prePin("e1", hostPub)
	f := &noneAuthFactory{notifID: ""} // publish failed
	factory := f.build(t, hostKeys)
	fp := terminal.FactoryParams{
		Endpoint: terminal.EndpointRef{ID: "e1", AccountID: "acc", Host: "127.0.0.1", Port: port, Username: "u"},
		Trigger:  terminal.Trigger{Kind: terminal.SourceUI},
	}
	tr, err := factory(context.Background(), fp)
	if err == nil {
		tr.Close()
		t.Fatal("expected refusal")
	}
	assertRefusal(t, err, hostPub)
	var notified *NotifiedError
	if errors.As(err, &notified) {
		t.Fatalf("no notification id may be returned when none was persisted: %+v", notified)
	}
}

// A host-key mismatch on a none-accepting server fails before
// authentication: only the mismatch warning, never the none-auth refusal.
func TestNoneAuthServerWithMismatchReportsOnlyMismatch(t *testing.T) {
	port, _, _ := startNoneAuthServer(t)
	hostKeys := newMemHostKeys()
	hostKeys.prePin("e1", newHostKeySigner(t).PublicKey())
	f := &noneAuthFactory{notifID: "ntf-1"}
	_, err := f.build(t, hostKeys)(context.Background(), terminal.FactoryParams{
		Endpoint: terminal.EndpointRef{ID: "e1", AccountID: "acc", Host: "127.0.0.1", Port: port, Username: "u"},
		Trigger:  terminal.Trigger{Kind: terminal.SourceUI},
	})
	var mismatch *HostKeyMismatchError
	var unauth *UnauthenticatedEndpointError
	if !errors.As(err, &mismatch) || errors.As(err, &unauth) {
		t.Fatalf("expected only a host-key mismatch, got %v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.mismatches != 1 || len(f.unauth) != 0 {
		t.Fatalf("hooks: mismatch=%d unauth=%d", f.mismatches, len(f.unauth))
	}
}

// A normal authentication failure (no key accepted) keeps today's error and
// never becomes a none-auth refusal.
func TestAuthFailureIsNotANoneAuthRefusal(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hostSigner := newHostKeySigner(t)
	srv := &gliderssh.Server{
		Handler:          func(gliderssh.Session) {},
		PublicKeyHandler: func(gliderssh.Context, gliderssh.PublicKey) bool { return false },
	}
	srv.AddHostKey(hostSigner)
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close(); ln.Close() })

	hostKeys := newMemHostKeys()
	hostKeys.prePin("e1", hostSigner.PublicKey())
	f := &noneAuthFactory{notifID: "ntf-1"}
	_, err = f.build(t, hostKeys)(context.Background(), terminal.FactoryParams{
		Endpoint: terminal.EndpointRef{ID: "e1", AccountID: "acc", Host: "127.0.0.1",
			Port: ln.Addr().(*net.TCPAddr).Port, Username: "u"},
		Trigger: terminal.Trigger{Kind: terminal.SourceUI},
	})
	var unauth *UnauthenticatedEndpointError
	if err == nil || errors.As(err, &unauth) || !strings.Contains(err.Error(), authFailedMessage) {
		t.Fatalf("expected the plain auth failure, got %v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.unauth) != 0 {
		t.Fatalf("auth failure must not fire the none-auth hook")
	}
}

// signatureProduced is sticky and independent of lastErr: a rejection then a
// success reads as signed while still remembering the rejection; a success
// then a rejection stays signed.
func TestKeyAuthSignatureFlagIsSticky(t *testing.T) {
	denied := errors.New("denied")
	k := newKeyAuth(context.Background(), nil)
	if k.signatureProduced() {
		t.Fatal("fresh keyAuth must not report a signature")
	}
	k.record(denied)
	if k.signatureProduced() {
		t.Fatal("a rejection is not a signature")
	}
	k.record(nil)
	if !k.signatureProduced() || !errors.Is(k.lastErr, denied) {
		t.Fatalf("after success: signed=%v lastErr=%v", k.signatureProduced(), k.lastErr)
	}
	k.record(errors.New("later"))
	if !k.signatureProduced() {
		t.Fatal("the flag is never cleared")
	}
}

// Both Sign and SignWithAlgorithm report success through the wrapper.
func TestRecordingSignerTracksBothSignPaths(t *testing.T) {
	signer := newTestSigner(t) // ed25519: an AlgorithmSigner

	k := newKeyAuth(context.Background(), nil)
	w := wrapRecording(signer, k.record)
	if _, err := w.Sign(nil, []byte("data")); err != nil {
		t.Fatal(err)
	}
	if !k.signatureProduced() {
		t.Fatal("Sign success not recorded")
	}

	k = newKeyAuth(context.Background(), nil)
	as, ok := wrapRecording(signer, k.record).(ssh.AlgorithmSigner)
	if !ok {
		t.Fatal("wrapper dropped the AlgorithmSigner capability")
	}
	if _, err := as.SignWithAlgorithm(nil, []byte("data"), ssh.KeyAlgoED25519); err != nil {
		t.Fatal(err)
	}
	if !k.signatureProduced() {
		t.Fatal("SignWithAlgorithm success not recorded")
	}
}
