// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// In-process harness for the transfer suites: a gliderlabs/ssh server with a
// PTY shell and an sftp subsystem serving the local filesystem (pkg/sftp's
// server advertises the posix-rename and hardlink extensions, like OpenSSH),
// dialled through the real sshx transport and the terminal Manager.
package transfer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gliderssh "github.com/gliderlabs/ssh"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"github.com/rado0x54/shellwatch/internal/audit"
	"github.com/rado0x54/shellwatch/internal/clock"
	"github.com/rado0x54/shellwatch/internal/config"
	"github.com/rado0x54/shellwatch/internal/sshx"
	"github.com/rado0x54/shellwatch/internal/store"
	"github.com/rado0x54/shellwatch/internal/terminal"
)

const testAccount = "acc-transfer"

var testCaller = Caller{AccountID: testAccount, ClientID: "client-1", ClientName: "test-agent", ClientVersion: "1.0"}

type fixedPins struct{ pin sshx.PinnedHostKey }

func (f fixedPins) Lookup(context.Context, string) (*sshx.PinnedHostKey, error) {
	p := f.pin
	return &p, nil
}
func (fixedPins) Pin(context.Context, sshx.PinRequest) error { return nil }

// recorder captures terminal:file frames.
type recorder struct {
	mu     sync.Mutex
	events []map[string]any
}

func (r *recorder) SendToSession(_ string, msg any) {
	raw, _ := json.Marshal(msg)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	r.mu.Lock()
	r.events = append(r.events, m)
	r.mu.Unlock()
}

func (r *recorder) forTransfer(id string) []map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []map[string]any
	for _, e := range r.events {
		if e["transferId"] == id {
			out = append(out, e)
		}
	}
	return out
}

type harness struct {
	t      *testing.T
	svc    *Service
	mgr    *terminal.Manager
	audit  *audit.FileTransfers
	rec    *recorder
	http   *httptest.Server
	sessID string
	dir    string // remote scratch directory (absolute)

	failed   chan View     // OnFailed notifications
	stallFTP atomic.Bool   // sftp subsystem accepts the channel and never answers
	stallOps atomic.Bool   // established sftp channels stop answering requests
	conns    chan net.Conn // server-side connections (for hangup)
}

type harnessOpts struct {
	limits config.Transfer
	clk    clock.Clock
}

func newHarness(t *testing.T, o harnessOpts) *harness {
	t.Helper()
	h := &harness{t: t, rec: &recorder{}, dir: t.TempDir(), failed: make(chan View, 16), conns: make(chan net.Conn, 16)}
	if o.clk == nil {
		o.clk = clock.Real{}
	}

	// --- SSH server ---
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, hostPriv, _ := ed25519.GenerateKey(rand.Reader)
	hostSigner, _ := ssh.NewSignerFromKey(hostPriv)
	srv := &gliderssh.Server{
		Handler: func(s gliderssh.Session) {
			io.WriteString(s, "ready\n")
			io.Copy(io.Discard, s) // until the client goes away
		},
		PublicKeyHandler: func(gliderssh.Context, gliderssh.PublicKey) bool { return true },
		SubsystemHandlers: map[string]gliderssh.SubsystemHandler{
			"sftp": func(s gliderssh.Session) {
				if h.stallFTP.Load() {
					<-s.Context().Done()
					return
				}
				server, err := sftp.NewServer(stallableChannel{Session: s, stall: &h.stallOps})
				if err != nil {
					return
				}
				_ = server.Serve()
				_ = server.Close()
			},
		},
		ConnCallback: func(_ gliderssh.Context, c net.Conn) net.Conn {
			select {
			case h.conns <- c:
			default:
			}
			return c
		},
	}
	srv.AddHostKey(hostSigner)
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close(); ln.Close() })

	// --- Manager over the real SSH transport ---
	_, userPriv, _ := ed25519.GenerateKey(rand.Reader)
	userSigner, _ := ssh.NewSignerFromKey(userPriv)
	hostPub := hostSigner.PublicKey()
	pins := fixedPins{pin: sshx.PinnedHostKey{Type: hostPub.Type(), Key: hostPub.Marshal(), Fingerprint: ssh.FingerprintSHA256(hostPub)}}
	addr := ln.Addr().(*net.TCPAddr)
	factory := func(ctx context.Context, p terminal.FactoryParams) (terminal.Transport, error) {
		return sshx.Connect(ctx, sshx.ConnectParams{
			Host: "127.0.0.1", Port: addr.Port, Username: "u", EndpointID: p.Endpoint.ID,
			HostKeys: pins, Signers: []ssh.Signer{userSigner},
		})
	}
	h.mgr = terminal.NewManager(factory, o.clk, 0)
	t.Cleanup(h.mgr.Destroy)

	// --- audit log on a private database ---
	db, err := store.Open("sqlite:" + t.TempDir() + "/audit.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := store.Migrate(db); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO accounts (id,name,created_at,updated_at) VALUES (?,'T','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')`, testAccount); err != nil {
		t.Fatal(err)
	}
	h.audit = audit.NewFileTransfers(db, o.clk)

	h.http = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.svc.Handle(w, r, strings.TrimPrefix(r.URL.Path, "/api/transfers/"))
	}))
	t.Cleanup(h.http.Close)

	h.svc = New(Params{
		Manager: h.mgr, Limits: o.limits, Clock: o.clk, Audit: h.audit, Publisher: h.rec,
		ExternalURL: func() string { return h.http.URL },
		OnFailed:    func(v View) { h.failed <- v },
	})
	t.Cleanup(h.svc.Close)

	h.sessID = h.openSession()
	return h
}

func (h *harness) openSession() string {
	h.t.Helper()
	ep := terminal.EndpointRef{ID: "ep-1", AccountID: testAccount, Host: "127.0.0.1", Username: "u"}
	sess, err := h.mgr.Create(context.Background(), ep, testAccount, terminal.Trigger{
		Kind: terminal.SourceMCP, OwnerClientID: testCaller.ClientID,
	})
	if err != nil {
		h.t.Fatalf("create session: %v", err)
	}
	return sess.SessionID
}

func (h *harness) create(p CreateParams) *Created {
	h.t.Helper()
	if p.SessionID == "" {
		p.SessionID = h.sessID
	}
	c, err := h.svc.Create(context.Background(), testCaller, p)
	if err != nil {
		h.t.Fatalf("create %s %s: %v", p.Direction, p.Path, err)
	}
	return c
}

// put uploads body to a link and returns the HTTP status and decoded body
// (status 0 when the request ended without a response).
func (h *harness) put(url string, body io.Reader) (int, map[string]any) {
	h.t.Helper()
	req, _ := http.NewRequest(http.MethodPut, url, body)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		// Not fatal: put runs on helper goroutines too, and an aborted
		// request may legitimately end without a response.
		h.t.Logf("PUT: %v", err)
		return 0, nil
	}
	defer res.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out
}

func (h *harness) status(id string) View {
	h.t.Helper()
	v, err := h.svc.Status(context.Background(), testCaller, id)
	if err != nil {
		h.t.Fatalf("status %s: %v", id, err)
	}
	return v
}

// waitStatus polls until the transfer satisfies ok.
func (h *harness) waitStatus(id string, ok func(View) bool) View {
	h.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		v := h.status(id)
		if ok(v) {
			return v
		}
		if time.Now().After(deadline) {
			h.t.Fatalf("transfer %s never reached the expected state; last: %+v", id, v)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (h *harness) auditRow(id string) *audit.FileTransferRow {
	h.t.Helper()
	row, err := h.audit.Get(context.Background(), testAccount, id)
	if err != nil || row == nil {
		h.t.Fatalf("audit row %s: %v %v", id, row, err)
	}
	return row
}

// stallableChannel withholds incoming SFTP requests while stall is set: the
// connection stays open, the server simply never sees (or answers) them.
type stallableChannel struct {
	gliderssh.Session
	stall *atomic.Bool
}

func (c stallableChannel) Read(p []byte) (int, error) {
	n, err := c.Session.Read(p)
	if c.stall.Load() {
		<-c.Session.Context().Done()
		return 0, io.EOF
	}
	return n, err
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// gatedBody is an upload body the test releases in two steps, so it can
// inspect the staging area while the transfer is mid-stream.
type gatedBody struct {
	first, rest *bytes.Reader
	gate        chan struct{}
	firstDone   chan struct{}
	once        sync.Once
}

func newGatedBody(data []byte, split int) *gatedBody {
	return &gatedBody{
		first: bytes.NewReader(data[:split]), rest: bytes.NewReader(data[split:]),
		gate: make(chan struct{}), firstDone: make(chan struct{}),
	}
}

func (g *gatedBody) Read(p []byte) (int, error) {
	if g.first.Len() > 0 {
		return g.first.Read(p)
	}
	g.once.Do(func() { close(g.firstDone) })
	<-g.gate
	return g.rest.Read(p)
}

func (g *gatedBody) release() { close(g.gate) }
