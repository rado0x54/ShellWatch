// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// SSH transport integration (Phase 3 slice 3): drive the real x/crypto/ssh
// transport against an in-process gliderlabs/ssh echo server (the Go analog
// of the Node ssh2.Server test harness), through the TerminalManager.
package sshx

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	gliderssh "github.com/gliderlabs/ssh"
	"golang.org/x/crypto/ssh"

	"github.com/rado0x54/shellwatch/internal/clock"
	"github.com/rado0x54/shellwatch/internal/terminal"
)

// startEchoServer starts an in-process SSH server whose "shell" echoes input
// back line by line, with a PTY. Returns its address and a stop func.
func startEchoServer(t *testing.T) (host string, port int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &gliderssh.Server{
		Handler: func(s gliderssh.Session) {
			_, _, isPty := s.Pty()
			if !isPty {
				io.WriteString(s, "no pty\n")
				return
			}
			io.WriteString(s, "ready\n")
			buf := make([]byte, 1024)
			for {
				n, err := s.Read(buf)
				if n > 0 {
					s.Write(buf[:n]) // echo
				}
				if err != nil {
					return
				}
			}
		},
		PublicKeyHandler: func(gliderssh.Context, gliderssh.PublicKey) bool { return true },
	}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close(); ln.Close() })
	addr := ln.Addr().(*net.TCPAddr)
	return "127.0.0.1", addr.Port
}

// writeTestKey writes a throwaway ed25519... use ECDSA P-256 (broad support)
// PEM key into dir and returns the KeyDir.
func writeTestKeyDir(t *testing.T) *KeyDir {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(filepath.Join(dir, "test.pem"), pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return NewKeyDir(dir)
}

func TestSSHTransportEndToEnd(t *testing.T) {
	host, port := startEchoServer(t)
	kd := writeTestKeyDir(t)

	// Sanity: the key parses into a signer.
	signers, err := kd.Signers()
	if err != nil || len(signers) != 1 {
		t.Fatalf("signers: %d %v", len(signers), err)
	}
	if signers[0].PublicKey().Type() == "" {
		t.Fatal("bad signer")
	}

	factory := NewFileKeyFactory(kd)
	mgr := terminal.NewManager(factory, clock.Real{}, 0)

	ep := terminal.EndpointRef{ID: "e1", AccountID: "acc", Host: host, Port: port, Username: "u"}
	sess, err := mgr.Create(context.Background(), ep, "acc", terminal.Trigger{Kind: terminal.SourceUI})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// The server greets with "ready" (the PTY may translate the newline).
	waitForOutput(t, mgr, sess.SessionID, "ready")

	// Input is echoed back.
	if err := mgr.SendKeys(sess.SessionID, []string{"text:hello", "enter"}); err != nil {
		t.Fatal(err)
	}
	waitForOutput(t, mgr, sess.SessionID, "hello")

	// Resize is accepted.
	if err := mgr.Resize(sess.SessionID, 120, 40); err != nil {
		t.Errorf("resize: %v", err)
	}

	// Close tears down and the session leaves the registry.
	mgr.Close(sess.SessionID, terminal.CloseClientUI)
	deadline := time.Now().Add(2 * time.Second)
	for mgr.GetSession(sess.SessionID) != nil {
		if time.Now().After(deadline) {
			t.Fatal("session not removed after close")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestServerHangupClosesSession proves a remote disconnect ends the session.
func TestServerHangupClosesSession(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &gliderssh.Server{
		Handler: func(s gliderssh.Session) {
			s.Pty()
			io.WriteString(s, "bye\n")
			// return immediately -> server closes the channel
		},
		PublicKeyHandler: func(gliderssh.Context, gliderssh.PublicKey) bool { return true },
	}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close(); ln.Close() })
	addr := ln.Addr().(*net.TCPAddr)

	kd := writeTestKeyDir(t)
	mgr := terminal.NewManager(NewFileKeyFactory(kd), clock.Real{}, 0)
	var lastStatus terminal.Status
	mgr.SubscribeStatus(func(e terminal.StatusEvent) { lastStatus = e.Status })

	ep := terminal.EndpointRef{ID: "e1", AccountID: "acc", Host: "127.0.0.1", Port: addr.Port, Username: "u"}
	sess, err := mgr.Create(context.Background(), ep, "acc", terminal.Trigger{Kind: terminal.SourceUI})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for mgr.GetSession(sess.SessionID) != nil {
		if time.Now().After(deadline) {
			t.Fatal("session not closed on server hangup")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if lastStatus != terminal.StatusClosed {
		t.Errorf("final status: %v", lastStatus)
	}
}

func waitForOutput(t *testing.T, mgr *terminal.Manager, sessionID, want string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		r, _ := mgr.ReadOutput(sessionID, 0, 4096)
		if containsSub(string(r.Data), want) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	r, _ := mgr.ReadOutput(sessionID, 0, 4096)
	t.Fatalf("did not see %q in output; got %q", want, r.Data)
}

func containsSub(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(haystack); i++ {
			if haystack[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}

// keep the ssh import used even if the signer sanity check changes.
var _ = ssh.PublicKeys
