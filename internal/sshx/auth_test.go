// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Per-key auth (auth.go): a denied key must not abort the handshake, must
// fall through to the next key, and must never put a signed attempt on the
// wire (parity finding L10 — the old skip-signature trick burned one of
// sshd's MaxAuthTries per denial and showed up in remote auth logs).
package sshx

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"

	gliderssh "github.com/gliderlabs/ssh"
	"golang.org/x/crypto/ssh"

	"github.com/rado0x54/shellwatch/internal/approval"
)

// authLog records every authentication attempt the in-process server sees.
// x/crypto's server logs signed publickey attempts and "none", but NOT the
// accepted key queries that precede signing — so any publickey entry here is
// a signature that actually reached the server.
type authLog struct {
	mu      sync.Mutex
	entries []struct {
		method string
		err    error
	}
}

func (l *authLog) publickeyAttempts() (total, failed int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, e := range l.entries {
		if e.method == "publickey" {
			total++
			if e.err != nil {
				failed++
			}
		}
	}
	return
}

// startLoggingServer accepts any public key and records auth attempts.
func startLoggingServer(t *testing.T) (port int, log *authLog) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	log = &authLog{}
	srv := &gliderssh.Server{
		Handler: func(s gliderssh.Session) {
			s.Pty()
			io.WriteString(s, "ready\n")
			io.Copy(io.Discard, s)
		},
		PublicKeyHandler: func(gliderssh.Context, gliderssh.PublicKey) bool { return true },
		ServerConfigCallback: func(gliderssh.Context) *ssh.ServerConfig {
			return &ssh.ServerConfig{AuthLogCallback: func(_ ssh.ConnMetadata, method string, err error) {
				log.mu.Lock()
				log.entries = append(log.entries, struct {
					method string
					err    error
				}{method, err})
				log.mu.Unlock()
			}}
		},
	}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close(); ln.Close() })
	return ln.Addr().(*net.TCPAddr).Port, log
}

// rejectingSigner advertises a real public key and rejects every sign with
// err (a human denial / expiry), counting how often it was asked.
type rejectingSigner struct {
	pub    ssh.PublicKey
	err    error
	calls  int
	onSign func()
}

func (r *rejectingSigner) PublicKey() ssh.PublicKey { return r.pub }
func (r *rejectingSigner) Sign(io.Reader, []byte) (*ssh.Signature, error) {
	r.calls++
	if r.onSign != nil {
		r.onSign()
	}
	return nil, r.err
}

func TestDeniedKeyFallsThroughWithoutSignedAttempt(t *testing.T) {
	port, log := startLoggingServer(t)
	denied := &rejectingSigner{pub: newTestSigner(t).PublicKey(), err: approval.ErrDenied}
	good := newTestSigner(t)

	tr, err := Connect(context.Background(), ConnectParams{
		Host: "127.0.0.1", Port: port, Username: "u", Signers: []ssh.Signer{denied, good},
	})
	if err != nil {
		t.Fatalf("connect must succeed via the second key: %v", err)
	}
	defer tr.Close()

	if denied.calls != 1 {
		t.Errorf("denied key asked to sign %d times, want 1 (server accepted its query)", denied.calls)
	}
	total, failed := log.publickeyAttempts()
	if failed != 0 {
		t.Errorf("%d failed signed publickey attempt(s) reached the server — the denial leaked onto the wire", failed)
	}
	if total != 1 {
		t.Errorf("server saw %d signed publickey attempts, want exactly 1 (the good key)", total)
	}
}

func TestAllKeysDeniedReportsTheDenial(t *testing.T) {
	port, _ := startLoggingServer(t)
	a := &rejectingSigner{pub: newTestSigner(t).PublicKey(), err: approval.ErrDenied}
	b := &rejectingSigner{pub: newTestSigner(t).PublicKey(), err: approval.ErrExpired}

	_, err := Connect(context.Background(), ConnectParams{
		Host: "127.0.0.1", Port: port, Username: "u", Signers: []ssh.Signer{a, b},
	})
	if err == nil {
		t.Fatal("connect must fail when every key is rejected")
	}
	if a.calls != 1 || b.calls != 1 {
		t.Errorf("each key must be offered exactly once, got a=%d b=%d", a.calls, b.calls)
	}
	// The human-visible reason (last rejection) is what the 400 body carries,
	// not x/crypto's generic "unable to authenticate".
	if !errors.Is(err, approval.ErrExpired) || !strings.Contains(err.Error(), "SSH handshake to") {
		t.Errorf("error should wrap the last rejection: %v", err)
	}
}

func TestDialContextDeathStopsKeyIteration(t *testing.T) {
	port, _ := startLoggingServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// The first key's prompt is cancelled with the dial context (session
	// create aborted): no further key may be offered.
	first := &rejectingSigner{pub: newTestSigner(t).PublicKey(), err: context.Canceled, onSign: cancel}
	second := &rejectingSigner{pub: newTestSigner(t).PublicKey(), err: approval.ErrDenied}

	_, err := Connect(ctx, ConnectParams{
		Host: "127.0.0.1", Port: port, Username: "u", Signers: []ssh.Signer{first, second},
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation, got %v", err)
	}
	if second.calls != 0 {
		t.Errorf("second key was offered after the dial context died")
	}
}
