// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// The file capability must survive the production transport path (#263): the
// passkey factory wraps every transport in endWatchTransport, which embeds
// only terminal.Transport — without the explicit Unwrap the Manager would see
// no FileTransport on any real session.
package sshx

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"

	gliderssh "github.com/gliderlabs/ssh"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"github.com/rado0x54/shellwatch/internal/approval"
	"github.com/rado0x54/shellwatch/internal/clock"
	"github.com/rado0x54/shellwatch/internal/terminal"
)

// startSFTPServer is startEchoServer plus an sftp subsystem on the local
// filesystem. stall makes the subsystem accept the channel and never answer.
func startSFTPServer(t *testing.T, stall bool) (port int, hostPub ssh.PublicKey) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hostSigner := newHostKeySigner(t)
	srv := &gliderssh.Server{
		Handler: func(s gliderssh.Session) {
			io.WriteString(s, "ready\n")
			io.Copy(io.Discard, s)
		},
		PublicKeyHandler: func(gliderssh.Context, gliderssh.PublicKey) bool { return true },
		SubsystemHandlers: map[string]gliderssh.SubsystemHandler{
			"sftp": func(s gliderssh.Session) {
				if stall {
					<-s.Context().Done()
					return
				}
				if server, err := sftp.NewServer(s); err == nil {
					_ = server.Serve()
					_ = server.Close()
				}
			},
		},
	}
	srv.AddHostKey(hostSigner)
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close(); ln.Close() })
	return ln.Addr().(*net.TCPAddr).Port, hostSigner.PublicKey()
}

func TestPasskeyFactoryTransportExposesFileCapability(t *testing.T) {
	port, hostPub := startSFTPServer(t, false)

	// The production factory with an approval-gated file key; approvals are
	// granted as they are raised.
	actionStore := approval.NewStore(clock.Real{}, newUUIDForTest())
	actionStore.OnCreated(func(a *approval.Action) { go actionStore.ResolveKey(a.ID) })
	params, _ := fileKeyParams(t, true, actionStore)
	hostKeys := newMemHostKeys()
	hostKeys.prePin("e1", hostPub)
	params.HostKeys = hostKeys
	ended := make(chan struct{}, 1)
	params.OnConnectionEnded = func(string, string) {
		select {
		case ended <- struct{}{}:
		default:
		}
	}

	mgr := terminal.NewManager(NewPasskeyFactory(params), clock.Real{}, 0)
	ep := terminal.EndpointRef{ID: "e1", AccountID: "acc", Host: "127.0.0.1", Port: port, Username: "u"}
	sess, err := mgr.Create(context.Background(), ep, "acc", terminal.Trigger{Kind: terminal.SourceMCP})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(func() { mgr.Close(sess.SessionID, terminal.CloseClientMCP) })

	client, err := mgr.OpenSFTP(context.Background(), sess.SessionID)
	if err != nil {
		t.Fatalf("OpenSFTP through the production transport: %v", err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "hello"), []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	entries, err := client.ReadDir(dir)
	if err != nil || len(entries) != 1 || entries[0].Name() != "hello" {
		t.Fatalf("readdir over sftp: %v %v", entries, err)
	}

	// Closing the sftp client closes only its channel: the PTY keeps working,
	// and a second channel can be opened on the same connection.
	if err := client.Close(); err != nil {
		t.Logf("sftp close: %v", err)
	}
	if err := mgr.SendKeys(sess.SessionID, []string{"text:still here", "enter"}); err != nil {
		t.Fatalf("PTY write after closing the sftp channel: %v", err)
	}
	if s := mgr.GetSession(sess.SessionID); s == nil || s.Status != terminal.StatusOpen {
		t.Fatalf("session after closing the sftp channel: %+v", s)
	}
	again, err := mgr.OpenSFTP(context.Background(), sess.SessionID)
	if err != nil {
		t.Fatalf("second sftp channel: %v", err)
	}
	again.Close()
}

// A mock transport has no file capability: the Manager says so explicitly.
func TestOpenSFTPWithoutCapability(t *testing.T) {
	mgr := terminal.NewManager(func(context.Context, terminal.FactoryParams) (terminal.Transport, error) {
		return terminal.NewMockTransport(), nil
	}, clock.Real{}, 0)
	ep := terminal.EndpointRef{ID: "e1", AccountID: "acc"}
	sess, err := mgr.Create(context.Background(), ep, "acc", terminal.Trigger{Kind: terminal.SourceUI})
	if err != nil {
		t.Fatal(err)
	}
	defer mgr.Close(sess.SessionID, terminal.CloseClientUI)
	if _, err := mgr.OpenSFTP(context.Background(), sess.SessionID); err != terminal.ErrNoFileTransport {
		t.Fatalf("mock transport: %v, want ErrNoFileTransport", err)
	}
}

// A subsystem that accepts the channel and never completes the SFTP
// handshake must not park OpenSFTP: cancelling the context tears it down.
func TestOpenSFTPCancelUnblocksStalledHandshake(t *testing.T) {
	port, hostPub := startSFTPServer(t, true)
	hostKeys := newMemHostKeys()
	hostKeys.prePin("e1", hostPub)
	tr, err := Connect(context.Background(), ConnectParams{
		Host: "127.0.0.1", Port: port, Username: "u", EndpointID: "e1",
		HostKeys: hostKeys, Signers: []ssh.Signer{newTestSigner(t)},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		_, err := tr.(terminal.FileTransport).OpenSFTP(ctx)
		errCh <- err
	}()
	cancel()
	if err := <-errCh; err != context.Canceled {
		t.Fatalf("stalled handshake: %v, want context.Canceled", err)
	}
}

func newUUIDForTest() func() string {
	n := 0
	return func() string {
		n++
		return "act-" + string(rune('a'+n))
	}
}
