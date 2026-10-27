// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Handshake liveness (#257). ssh.NewClientConn takes no context and
// x/crypto applies no deadline of its own — ClientConfig.Timeout covers only
// the TCP dial — so a peer that accepts TCP and then says nothing used to
// block connection setup forever, and cancelling the setup context could not
// interrupt it.
package sshx

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/rado0x54/shellwatch/internal/clock"
	"github.com/rado0x54/shellwatch/internal/terminal"
)

// shortenHandshakeTimeout makes the deadline observable in a test.
func shortenHandshakeTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	prev := connectionTimeout
	connectionTimeout = d
	t.Cleanup(func() { connectionTimeout = prev })
}

// startSilentListener accepts TCP and then never writes — no SSH version
// banner, no key exchange — holding the connection open.
func startSilentListener(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// Hold it open and say nothing. Closed when the test's listener
			// cleanup runs, or when the client gives up.
			go func() { <-t.Context().Done(); _ = conn.Close() }()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestStalledHandshakeFailsWithinTheDeadline(t *testing.T) {
	shortenHandshakeTimeout(t, 300*time.Millisecond)
	port := startSilentListener(t)

	start := time.Now()
	_, err := Connect(context.Background(), ConnectParams{
		Host: "127.0.0.1", Port: port, Username: "u", EndpointID: "e1",
		HostKeys: newMemHostKeys(), Signers: []ssh.Signer{newTestSigner(t)},
	})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("a peer that never speaks SSH must not yield a session")
	}
	// The point of the test: it returns at all, and promptly.
	if elapsed > 10*time.Second {
		t.Fatalf("handshake took %v — the deadline did not apply", elapsed)
	}
	t.Logf("stalled handshake failed after %v: %v", elapsed, err)
}

// Cancelling setup must interrupt the handshake, which only closing the socket
// can do. This is what terminal.Manager's Close path relies on: it cancels
// setupCtx and expects the factory to return so the session can be finalized
// and removed instead of staying parked in `closing`.
func TestCancellingSetupUnblocksAStalledHandshake(t *testing.T) {
	// Long enough that the deadline cannot be what frees us.
	shortenHandshakeTimeout(t, 30*time.Second)
	port := startSilentListener(t)

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)

	start := time.Now()
	_, err := Connect(ctx, ConnectParams{
		Host: "127.0.0.1", Port: port, Username: "u", EndpointID: "e1",
		HostKeys: newMemHostKeys(), Signers: []ssh.Signer{newTestSigner(t)},
	})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("a cancelled setup must not yield a session")
	}
	if elapsed > 5*time.Second {
		t.Fatalf("cancellation took %v to take effect — the socket was not closed", elapsed)
	}
	t.Logf("cancelled handshake returned after %v: %v", elapsed, err)
}

// The deadline bounds SETUP only. An established session is long-lived and
// idles by design — a terminal with nobody typing — so a deadline left on the
// socket would tear it down mid-life. This is the easy way to get the fix
// wrong, so it is pinned.
func TestEstablishedSessionOutlivesTheHandshakeDeadline(t *testing.T) {
	const deadline = 250 * time.Millisecond
	shortenHandshakeTimeout(t, deadline)
	host, port, hostPub := startEchoServer(t)
	kd := writeTestKeyDir(t)

	hostKeys := newMemHostKeys()
	hostKeys.prePin("e1", hostPub)
	mgr := terminal.NewManager(NewFileKeyFactory(kd, hostKeys), clock.Real{}, 0)
	t.Cleanup(mgr.Destroy)

	ep := terminal.EndpointRef{ID: "e1", AccountID: "acc", Host: host, Port: port, Username: "u"}
	sess, err := mgr.Create(context.Background(), ep, "acc", terminal.Trigger{Kind: terminal.SourceUI})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	waitForOutput(t, mgr, sess.SessionID, "ready")

	// Idle well past the handshake deadline, then prove the session still
	// carries I/O in both directions.
	time.Sleep(4 * deadline)
	if err := mgr.SendKeys(sess.SessionID, []string{"text:still-alive", "enter"}); err != nil {
		t.Fatalf("send after idling past the handshake deadline: %v", err)
	}
	waitForOutput(t, mgr, sess.SessionID, "still-alive")

	if s := mgr.GetSession(sess.SessionID); s == nil || s.Status != terminal.StatusOpen {
		t.Fatalf("session is no longer open after idling past the deadline: %+v", s)
	}
}

// A slow human approving one key must not trip the deadline, and a host may
// offer several keys — so the window is per auth round, not per handshake.
func TestApprovalSlowerThanTheDeadlineStillAuthenticates(t *testing.T) {
	const window = 400 * time.Millisecond
	shortenHandshakeTimeout(t, window)
	port, log, hostPub := startLoggingServer(t)
	_ = hostPub

	accepted := newTestSigner(t)
	// Two keys denied slowly, then one that works: three auth rounds, each
	// taking most of the window, so the total far exceeds a single one.
	slow := func() ssh.Signer {
		return &rejectingSigner{
			pub: newTestSigner(t).PublicKey(),
			err: errors.New("denied"),
			onSign: func() {
				time.Sleep(window * 3 / 4)
			},
		}
	}
	hostKeys := newMemHostKeys()
	hostKeys.prePin("e1", hostPub)

	start := time.Now()
	tr, err := Connect(context.Background(), ConnectParams{
		Host: "127.0.0.1", Port: port, Username: "u", EndpointID: "e1",
		HostKeys: hostKeys, Signers: []ssh.Signer{slow(), slow(), accepted},
	})
	if err != nil {
		t.Fatalf("auth that outlasted one deadline window failed after %v: %v", time.Since(start), err)
	}
	t.Cleanup(func() { _ = tr.Close() })
	if took := time.Since(start); took < window {
		t.Errorf("auth took %v, expected it to exceed one %v window", took, window)
	}
	if log == nil {
		t.Fatal("no auth log")
	}
}
