// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
package transfer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/pkg/sftp"

	"github.com/rado0x54/shellwatch/internal/clock"
	"github.com/rado0x54/shellwatch/internal/config"
)

func inode(t *testing.T, p string) uint64 {
	t.Helper()
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Sys().(*syscall.Stat_t).Ino
}

func perm(t *testing.T, p string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

// A 10 KB config round-trips through the inline tools; the audit row and the
// terminal:file frame carry the result's transferId; overwrite keeps inode
// and mode.
func TestInlineWriteReadRoundTrip(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	ctx := context.Background()
	file := filepath.Join(h.dir, "app.conf")
	content := strings.Repeat("key = value\n", 850) // ~10 KB

	w, err := h.svc.WriteFile(ctx, testCaller, WriteParams{SessionID: h.sessID, Path: file, Content: content})
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	sum := sha256.Sum256([]byte(content))
	if w.Bytes != int64(len(content)) || w.SHA256 != hex.EncodeToString(sum[:]) {
		t.Errorf("write result: %+v", w)
	}
	if got := perm(t, file); got != 0o644 {
		t.Errorf("new file mode: %o, want 644", got)
	}
	row := h.auditRow(w.TransferID)
	if row.Tier != TierInline || row.Direction != DirectionUpload || row.Status != "completed" ||
		row.Path != file || row.Bytes != w.Bytes || *row.SHA256 != w.SHA256 ||
		*row.ClientID != "client-1" || *row.MCPClientName != "test-agent" || row.SessionID != h.sessID {
		t.Errorf("audit row: %+v", row)
	}
	evs := h.rec.forTransfer(w.TransferID)
	if len(evs) != 1 || evs[0]["type"] != "terminal:file" || evs[0]["status"] != "completed" ||
		evs[0]["tier"] != "inline" || evs[0]["sessionId"] != h.sessID || evs[0]["mcpClientName"] != "test-agent" {
		t.Errorf("events: %+v", evs)
	}

	r, err := h.svc.ReadFile(ctx, testCaller, h.sessID, file, "")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if r.Content != content || r.SHA256 != w.SHA256 || r.Size != w.Bytes || r.ModeOctal != "0644" || r.Encoding != "utf8" {
		t.Errorf("read result mismatch: size=%d mode=%s", r.Size, r.ModeOctal)
	}

	// Without overwrite an existing file is refused and left alone.
	if _, err := h.svc.WriteFile(ctx, testCaller, WriteParams{SessionID: h.sessID, Path: file, Content: "x"}); err == nil ||
		!strings.Contains(err.Error(), "already exists") {
		t.Errorf("exclusive create over existing file: %v", err)
	}

	// Overwrite in place: inode and mode survive.
	if err := os.Chmod(file, 0o640); err != nil {
		t.Fatal(err)
	}
	before := inode(t, file)
	if _, err := h.svc.WriteFile(ctx, testCaller, WriteParams{SessionID: h.sessID, Path: file, Content: "replaced\n", Overwrite: true}); err != nil {
		t.Fatalf("overwrite: %v", err)
	}
	if inode(t, file) != before {
		t.Error("overwrite changed the inode")
	}
	if got := perm(t, file); got != 0o640 {
		t.Errorf("overwrite without mode changed the mode: %o", got)
	}
	if raw, _ := os.ReadFile(file); string(raw) != "replaced\n" {
		t.Errorf("content after overwrite: %q", raw)
	}
	// A supplied mode deliberately overrides preservation.
	m := os.FileMode(0o600)
	if _, err := h.svc.WriteFile(ctx, testCaller, WriteParams{SessionID: h.sessID, Path: file, Content: "again\n", Overwrite: true, Mode: &m}); err != nil {
		t.Fatal(err)
	}
	if got := perm(t, file); got != 0o600 {
		t.Errorf("overwrite with mode: %o, want 600", got)
	}
}

func TestInlineCreateWithMode(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	file := filepath.Join(h.dir, "secret")
	m := os.FileMode(0o600)
	if _, err := h.svc.WriteFile(context.Background(), testCaller, WriteParams{SessionID: h.sessID, Path: file, Content: "s3cret", Mode: &m}); err != nil {
		t.Fatal(err)
	}
	if got := perm(t, file); got != 0o600 {
		t.Errorf("mode: %o", got)
	}
}

func TestInlineBase64AndMalformed(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	ctx := context.Background()
	file := filepath.Join(h.dir, "blob.bin")
	blob := randomBytes(4096)

	if _, err := h.svc.WriteFile(ctx, testCaller, WriteParams{
		SessionID: h.sessID, Path: file, Content: base64.StdEncoding.EncodeToString(blob), Encoding: "base64",
	}); err != nil {
		t.Fatal(err)
	}
	r, err := h.svc.ReadFile(ctx, testCaller, h.sessID, file, "base64")
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := base64.StdEncoding.DecodeString(r.Content); !bytes.Equal(got, blob) {
		t.Error("base64 round trip mismatch")
	}
	// Binary content is not silently mangled into a string.
	if _, err := h.svc.ReadFile(ctx, testCaller, h.sessID, file, "utf8"); err == nil || !strings.Contains(err.Error(), "base64") {
		t.Errorf("utf8 read of binary: %v", err)
	}

	// Malformed base64 fails before the destination is opened.
	if _, err := h.svc.WriteFile(ctx, testCaller, WriteParams{
		SessionID: h.sessID, Path: file, Content: "!!! not base64 !!!", Encoding: "base64", Overwrite: true,
	}); err == nil {
		t.Fatal("malformed base64 accepted")
	}
	if raw, _ := os.ReadFile(file); !bytes.Equal(raw, blob) {
		t.Error("existing file was touched by a rejected write")
	}
}

func TestInlineLimitsAndPathRules(t *testing.T) {
	h := newHarness(t, harnessOpts{limits: config.Transfer{MaxInlineBytes: 1024}})
	ctx := context.Background()
	big := filepath.Join(h.dir, "big")
	if err := os.WriteFile(big, randomBytes(4096), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := h.svc.ReadFile(ctx, testCaller, h.sessID, big, "base64")
	if err == nil || !strings.Contains(err.Error(), "shellwatch_transfer_file") {
		t.Errorf("oversized read: %v", err)
	}
	if _, err := h.svc.WriteFile(ctx, testCaller, WriteParams{SessionID: h.sessID, Path: filepath.Join(h.dir, "w"), Content: strings.Repeat("a", 2000)}); err == nil ||
		!strings.Contains(err.Error(), "shellwatch_transfer_file") {
		t.Errorf("oversized write: %v", err)
	}
	if _, err := os.Stat(filepath.Join(h.dir, "w")); !os.IsNotExist(err) {
		t.Error("oversized write created the destination")
	}

	// Relative paths are refused: the file tools do not follow the shell's cwd.
	if _, err := h.svc.ReadFile(ctx, testCaller, h.sessID, "relative/file", ""); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Errorf("relative path: %v", err)
	}
	// Foreign account -> the uniform error.
	other := Caller{AccountID: "someone-else", ClientID: "client-1"}
	if _, err := h.svc.ReadFile(ctx, other, h.sessID, big, ""); err == nil || err.Error() != "session not found: "+h.sessID {
		t.Errorf("foreign session: %v", err)
	}

	// Symlinks: reads follow them, writes refuse them.
	target := filepath.Join(h.dir, "target")
	link := filepath.Join(h.dir, "link")
	os.WriteFile(target, []byte("via link"), 0o644)
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if r, err := h.svc.ReadFile(ctx, testCaller, h.sessID, link, ""); err != nil || r.Content != "via link" {
		t.Errorf("read through symlink: %+v %v", r, err)
	}
	if _, err := h.svc.WriteFile(ctx, testCaller, WriteParams{SessionID: h.sessID, Path: link, Content: "x", Overwrite: true}); err == nil ||
		!strings.Contains(err.Error(), "symlink") {
		t.Errorf("write to symlink: %v", err)
	}
	// Directories are refused as read sources and write destinations.
	if _, err := h.svc.ReadFile(ctx, testCaller, h.sessID, h.dir, ""); err == nil || !strings.Contains(err.Error(), "directory") {
		t.Errorf("read of a directory: %v", err)
	}
	if _, err := h.svc.WriteFile(ctx, testCaller, WriteParams{SessionID: h.sessID, Path: h.dir, Content: "x", Overwrite: true}); err == nil {
		t.Error("write over a directory accepted")
	}
}

func TestListDir(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	os.WriteFile(filepath.Join(h.dir, "b.txt"), []byte("12345"), 0o600)
	os.Mkdir(filepath.Join(h.dir, "a-dir"), 0o755)
	os.Symlink("b.txt", filepath.Join(h.dir, "c-link"))

	res, err := h.svc.ListDir(context.Background(), testCaller, h.sessID, h.dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Entries) != 3 || res.Truncated || res.TransferID == "" {
		t.Fatalf("entries: %+v", res)
	}
	if e := res.Entries[0]; e.Name != "a-dir" || e.Type != "directory" {
		t.Errorf("entry 0: %+v", e)
	}
	if e := res.Entries[1]; e.Name != "b.txt" || e.Type != "file" || e.Size != 5 || e.ModeOctal != "0600" || e.Mode != 0o600 {
		t.Errorf("entry 1: %+v", e)
	}
	if e := res.Entries[2]; e.Name != "c-link" || e.Type != "symlink" || e.Target != "b.txt" {
		t.Errorf("entry 2: %+v", e)
	}
	if row := h.auditRow(res.TransferID); row.Direction != DirectionList {
		t.Errorf("audit direction: %s", row.Direction)
	}

	capped, err := h.svc.ListDir(context.Background(), testCaller, h.sessID, h.dir, 2)
	if err != nil || len(capped.Entries) != 2 || !capped.Truncated {
		t.Errorf("capped listing: %+v %v", capped, err)
	}
}

// Three concurrent inline calls on one session: two run, the third waits for
// a slot — and all of them share one SFTP channel.
func TestInlineConcurrencyBound(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	release := make(chan struct{})
	var mu sync.Mutex
	running, peak := 0, 0
	clients := map[*sftp.Client]bool{}
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := h.svc.inline(context.Background(), h.sessID, func(c *sftp.Client) error {
				mu.Lock()
				running++
				if running > peak {
					peak = running
				}
				clients[c] = true
				mu.Unlock()
				<-release
				mu.Lock()
				running--
				mu.Unlock()
				return nil
			})
			if err != nil {
				t.Errorf("inline: %v", err)
			}
		}()
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		n := running
		mu.Unlock()
		if n == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("expected 2 running calls, have %d", n)
		}
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond) // the third must still be waiting
	mu.Lock()
	if running != 2 {
		t.Errorf("third call did not wait: running=%d", running)
	}
	mu.Unlock()
	close(release)
	wg.Wait()
	if peak != 2 {
		t.Errorf("peak concurrency %d, want 2", peak)
	}
	if len(clients) != 1 {
		t.Errorf("inline calls used %d SFTP channels, want 1", len(clients))
	}
}

// A stalled SFTP server fails the call after inlineTimeoutSeconds, frees the
// slot, and the next call works on a fresh channel.
func TestInlineTimeoutOnStalledServer(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	h := newHarness(t, harnessOpts{clk: clk})
	h.stallFTP.Store(true)

	errCh := make(chan error, 1)
	go func() {
		_, err := h.svc.ListDir(context.Background(), testCaller, h.sessID, h.dir, 0)
		errCh <- err
	}()
	// Let the call park on the silent subsystem, then fire the bound.
	time.Sleep(100 * time.Millisecond)
	select {
	case err := <-errCh:
		t.Fatalf("call returned before the timeout: %v", err)
	default:
	}
	clk.Advance(31 * time.Second)
	select {
	case err := <-errCh:
		if err == nil || !strings.Contains(err.Error(), "timed out") {
			t.Fatalf("stalled call: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("stalled call did not return after the timeout")
	}

	// The slot was released and the dead channel dropped.
	deadline := time.Now().Add(5 * time.Second)
	for len(h.svc.sessionFS(h.sessID).sem) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("inline slot leaked after timeout")
		}
		time.Sleep(5 * time.Millisecond)
	}
	h.stallFTP.Store(false)
	os.WriteFile(filepath.Join(h.dir, "f"), []byte("x"), 0o644)
	if res, err := h.svc.ListDir(context.Background(), testCaller, h.sessID, h.dir, 0); err != nil || len(res.Entries) != 1 {
		t.Fatalf("call after recovery: %+v %v", res, err)
	}
	// The PTY session itself was never affected.
	if s := h.mgr.GetSession(h.sessID); s == nil || s.Status != "open" {
		t.Errorf("session after stalled file call: %+v", s)
	}
}

// File activity keeps a session alive; minting links and polling status do not.
func TestFileActivityAndIdleSweep(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	h := newHarness(t, harnessOpts{clk: clk})
	h.mgr.SetIdleTimeout(30 * time.Minute)
	ctx := context.Background()
	file := filepath.Join(h.dir, "keepalive")

	// Only inline writes for 50 minutes: the session survives every sweep.
	for i := 0; i < 5; i++ {
		clk.Advance(10 * time.Minute)
		if _, err := h.svc.WriteFile(ctx, testCaller, WriteParams{SessionID: h.sessID, Path: file, Content: "tick", Overwrite: true}); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		h.mgr.SweepIdle()
		if s := h.mgr.GetSession(h.sessID); s == nil || s.Status != "open" {
			t.Fatalf("session swept despite file activity (round %d)", i)
		}
	}

	// Only minted links, status polling and an empty listing: swept.
	empty := filepath.Join(h.dir, "empty")
	os.Mkdir(empty, 0o755)
	for i := 0; i < 4; i++ {
		clk.Advance(10 * time.Minute)
		c := h.create(CreateParams{Direction: DirectionDownload, Path: file})
		h.status(c.TransferID)
		if _, err := h.svc.ListDir(ctx, testCaller, h.sessID, empty, 0); err != nil {
			t.Fatal(err)
		}
		if _, err := h.svc.Cancel(ctx, testCaller, c.TransferID); err != nil {
			t.Fatal(err)
		}
	}
	h.mgr.SweepIdle()
	if s := h.mgr.GetSession(h.sessID); s != nil && s.Status == "open" {
		t.Error("session with only minted links and status polling was not swept")
	}
}
