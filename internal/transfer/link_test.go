// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
package transfer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pkg/sftp"

	"github.com/rado0x54/shellwatch/internal/clock"
	"github.com/rado0x54/shellwatch/internal/config"
	"github.com/rado0x54/shellwatch/internal/terminal"
)

func sha(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// stagingDirs lists leftover staging directories in dir.
func stagingDirs(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			out = append(out, e.Name())
		}
	}
	return out
}

func waitNoStaging(t *testing.T, dir string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for len(stagingDirs(t, dir)) > 0 {
		if time.Now().After(deadline) {
			t.Fatalf("staging directories remain: %v", stagingDirs(t, dir))
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// Upload: staged privately (dir 0700, file 0600 before the first byte),
// committed, staging removed, digest verified, token single-use.
func TestUploadStagesAndCommits(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	dest := filepath.Join(h.dir, "backup.tgz")
	data := randomBytes(6 << 20)
	c := h.create(CreateParams{Direction: DirectionUpload, Path: dest, SHA256: sha(data)})
	if c.Method != "PUT" || !strings.HasPrefix(c.URL, h.http.URL+"/api/transfers/") ||
		!strings.Contains(c.Command, "curl -fsS -T './backup.tgz'") || !strings.Contains(c.Command, c.URL) {
		t.Fatalf("created: %+v", c)
	}
	if v := h.status(c.TransferID); v.Status != StatePending {
		t.Fatalf("status before claim: %s", v.Status)
	}

	body := newGatedBody(data, 1<<20)
	type result struct {
		code int
		body map[string]any
	}
	done := make(chan result, 1)
	go func() {
		code, out := h.put(c.URL, body)
		done <- result{code, out}
	}()

	// Mid-stream: the staging area exists with restrictive permissions and
	// the destination does not.
	<-body.firstDone
	v := h.waitStatus(c.TransferID, func(v View) bool { return v.StagingPath != "" && v.Bytes > 0 })
	if v.Status != StateActive {
		t.Errorf("mid-stream status: %s", v.Status)
	}
	if got := perm(t, v.StagingPath); got != 0o700 {
		t.Errorf("staging directory mode %o, want 700", got)
	}
	if got := perm(t, filepath.Join(v.StagingPath, "data")); got != 0o600 {
		t.Errorf("staged file mode %o, want 600", got)
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Error("destination exists before commit")
	}
	if row := h.auditRow(c.TransferID); row.Status != "active" || row.StagingPath == nil || *row.StagingPath != v.StagingPath {
		t.Errorf("audit row mid-stream: %+v", row)
	}
	if snap := h.svc.Snapshot(h.sessID); len(snap) != 1 || snap[0].(map[string]any)["transferId"] != c.TransferID {
		t.Errorf("attach snapshot mid-transfer: %+v", snap)
	}

	body.release()
	res := <-done
	if res.code != 200 || res.body["status"] != "completed" || res.body["sha256"] != sha(data) {
		t.Fatalf("upload response: %d %+v", res.code, res.body)
	}
	got, err := os.ReadFile(dest)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("destination content mismatch (%v)", err)
	}
	if m := perm(t, dest); m != 0o644 {
		t.Errorf("destination mode %o, want 644", m)
	}
	fin := h.waitStatus(c.TransferID, func(v View) bool { return v.Cleanup != "" })
	if fin.Status != StateCompleted || fin.CommitOutcome != CommitOK || fin.Cleanup != CleanupOK ||
		fin.StagingPath != "" || fin.Bytes != int64(len(data)) || fin.SHA256 != sha(data) {
		t.Errorf("final status: %+v", fin)
	}
	waitNoStaging(t, h.dir)
	if row := h.auditRow(c.TransferID); row.Status != "completed" || *row.CommitOutcome != "ok" || *row.Cleanup != "ok" || row.StagingPath != nil {
		t.Errorf("final audit row: %+v", row)
	}
	evs := h.rec.forTransfer(c.TransferID)
	if evs[0]["status"] != "pending" || evs[len(evs)-1]["status"] != "completed" {
		t.Errorf("event sequence: first %v last %v", evs[0]["status"], evs[len(evs)-1]["status"])
	}
	if len(h.svc.Snapshot(h.sessID)) != 0 {
		t.Error("finished transfer still in the attach snapshot")
	}

	// Single use: the same URL is now the uniform 404.
	if code, _ := h.put(c.URL, bytes.NewReader(data)); code != 404 {
		t.Errorf("second use: %d, want 404", code)
	}
	// A foreign client cannot see the transfer.
	if _, err := h.svc.Status(context.Background(), Caller{AccountID: testAccount, ClientID: "client-2"}, c.TransferID); err == nil {
		t.Error("foreign client read the transfer status")
	}
}

func TestUploadOverwriteAndModes(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	dest := filepath.Join(h.dir, "conf")
	os.WriteFile(dest, []byte("old"), 0o640)
	os.Chmod(dest, 0o640)

	// overwrite=false on an existing destination is refused, original intact.
	c := h.create(CreateParams{Direction: DirectionUpload, Path: dest})
	if code, body := h.put(c.URL, strings.NewReader("new")); code != 409 || body["status"] != "failed" {
		t.Errorf("no-clobber upload: %d %+v", code, body)
	}
	if raw, _ := os.ReadFile(dest); string(raw) != "old" {
		t.Errorf("destination changed by refused upload: %q", raw)
	}

	// overwrite=true replaces atomically and copies the existing mode.
	c = h.create(CreateParams{Direction: DirectionUpload, Path: dest, Overwrite: true})
	if code, body := h.put(c.URL, strings.NewReader("new")); code != 200 {
		t.Fatalf("overwrite upload: %d %+v", code, body)
	}
	if raw, _ := os.ReadFile(dest); string(raw) != "new" {
		t.Errorf("content after overwrite: %q", raw)
	}
	if m := perm(t, dest); m != 0o640 {
		t.Errorf("mode after overwrite: %o, want 640 (copied)", m)
	}
	// An explicit mode wins.
	mode := os.FileMode(0o600)
	c = h.create(CreateParams{Direction: DirectionUpload, Path: dest, Overwrite: true, Mode: &mode})
	if code, _ := h.put(c.URL, strings.NewReader("newer")); code != 200 {
		t.Fatalf("overwrite with mode: %d", code)
	}
	if m := perm(t, dest); m != 0o600 {
		t.Errorf("mode: %o, want 600", m)
	}
	waitNoStaging(t, h.dir)

	// Digest mismatch fails before commit; destination untouched, staging gone.
	c = h.create(CreateParams{Direction: DirectionUpload, Path: dest, Overwrite: true, SHA256: sha([]byte("something else"))})
	if code, body := h.put(c.URL, strings.NewReader("tampered")); code != 422 || !strings.Contains(body["error"].(string), "sha256 mismatch") {
		t.Errorf("digest mismatch: %d %+v", code, body)
	}
	if raw, _ := os.ReadFile(dest); string(raw) != "newer" {
		t.Errorf("destination changed by a digest-mismatched upload: %q", raw)
	}
	waitNoStaging(t, h.dir)
	select {
	case v := <-h.failed:
		_ = v
	case <-time.After(2 * time.Second):
		t.Error("no failure notification for the failed upload")
	}

	// Symlink destinations are refused at the pre-check.
	link := filepath.Join(h.dir, "link")
	os.Symlink(dest, link)
	if _, err := h.svc.Create(context.Background(), testCaller, CreateParams{SessionID: h.sessID, Direction: DirectionUpload, Path: link, Overwrite: true}); err == nil ||
		!strings.Contains(err.Error(), "symlink") {
		t.Errorf("upload to symlink: %v", err)
	}
}

// Two concurrent no-clobber uploads to one path: exactly one wins, the other
// fails at the hardlink commit, nothing is left behind.
func TestConcurrentNoClobberUploads(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	dest := filepath.Join(h.dir, "race")
	a := h.create(CreateParams{Direction: DirectionUpload, Path: dest})
	b := h.create(CreateParams{Direction: DirectionUpload, Path: dest})

	// Hold both at the commit so neither can win the pre-check.
	var gate sync.WaitGroup
	gate.Add(2)
	h.svc.beforeCommit = func(string, *sftp.Client) { gate.Done(); gate.Wait() }

	codes := make(chan int, 2)
	payload := map[string]string{a.URL: "AAAA", b.URL: "BBBB"}
	for url, body := range payload {
		go func() {
			code, _ := h.put(url, strings.NewReader(body))
			codes <- code
		}()
	}
	c1, c2 := <-codes, <-codes
	if !(c1 == 200 && c2 == 409) && !(c1 == 409 && c2 == 200) {
		t.Fatalf("status codes %d/%d, want one 200 and one 409", c1, c2)
	}
	va, vb := h.status(a.TransferID), h.status(b.TransferID)
	loser := va
	if va.Status == StateCompleted {
		loser = vb
	}
	if loser.Status != StateFailed || loser.CommitOutcome != CommitFailed {
		t.Errorf("loser: %+v", loser)
	}
	raw, _ := os.ReadFile(dest)
	if s := string(raw); s != "AAAA" && s != "BBBB" {
		t.Errorf("destination holds %q", s)
	}
	waitNoStaging(t, h.dir)
}

// Cancel racing commit has exactly four outcomes; none leaves a partial file.
func TestCancelCommitRace(t *testing.T) {
	t.Run("cancel before commit wins", func(t *testing.T) {
		h := newHarness(t, harnessOpts{})
		dest := filepath.Join(h.dir, "f")
		c := h.create(CreateParams{Direction: DirectionUpload, Path: dest})
		body := newGatedBody([]byte("partial-then-more"), 7)
		t.Cleanup(body.release)
		code := make(chan int, 1)
		go func() { st, _ := h.put(c.URL, body); code <- st }()
		<-body.firstDone
		h.waitStatus(c.TransferID, func(v View) bool { return v.StagingPath != "" })

		v, err := h.svc.Cancel(context.Background(), testCaller, c.TransferID)
		if err != nil || v.Status != StateCancelled {
			t.Fatalf("cancel: %+v %v", v, err)
		}
		if st := <-code; st != 409 {
			t.Errorf("aborted request status %d", st)
		}
		fin := h.waitStatus(c.TransferID, func(v View) bool { return v.Cleanup != "" })
		if fin.Status != StateCancelled || fin.Cleanup != CleanupOK || fin.CommitOutcome != "" {
			t.Errorf("after cancel: %+v", fin)
		}
		if _, err := os.Stat(dest); !os.IsNotExist(err) {
			t.Error("cancelled upload left a destination")
		}
		waitNoStaging(t, h.dir)
		// The PTY was not touched.
		if s := h.mgr.GetSession(h.sessID); s == nil || s.Status != terminal.StatusOpen {
			t.Error("cancel affected the session")
		}
	})

	t.Run("cancel after commit was issued is ignored", func(t *testing.T) {
		h := newHarness(t, harnessOpts{})
		dest := filepath.Join(h.dir, "f")
		c := h.create(CreateParams{Direction: DirectionUpload, Path: dest})
		h.svc.beforeCommit = func(id string, _ *sftp.Client) {
			v, err := h.svc.Cancel(context.Background(), testCaller, id)
			if err != nil || v.Status != StateCommitting {
				t.Errorf("cancel during commit: %+v %v", v, err)
			}
			if row := h.auditRow(id); row.Status != "committing" {
				t.Errorf("audit row not written ahead of the commit: %s", row.Status)
			}
		}
		if code, body := h.put(c.URL, strings.NewReader("whole")); code != 200 || body["status"] != "completed" {
			t.Fatalf("upload: %d %+v", code, body)
		}
		if raw, _ := os.ReadFile(dest); string(raw) != "whole" {
			t.Errorf("destination: %q", raw)
		}
	})

	t.Run("acknowledged commit failure leaves the destination untouched", func(t *testing.T) {
		h := newHarness(t, harnessOpts{})
		dest := filepath.Join(h.dir, "f")
		c := h.create(CreateParams{Direction: DirectionUpload, Path: dest})
		h.svc.beforeCommit = func(string, *sftp.Client) { os.WriteFile(dest, []byte("someone else"), 0o644) }
		code, body := h.put(c.URL, strings.NewReader("mine"))
		if code != 409 || body["status"] != "failed" || body["commitOutcome"] != "failed" {
			t.Fatalf("upload: %d %+v", code, body)
		}
		if raw, _ := os.ReadFile(dest); string(raw) != "someone else" {
			t.Errorf("destination was clobbered: %q", raw)
		}
		waitNoStaging(t, h.dir)
	})

	t.Run("overwrite commit failure leaves the original in place", func(t *testing.T) {
		h := newHarness(t, harnessOpts{})
		dest := filepath.Join(h.dir, "f")
		os.WriteFile(dest, []byte("original"), 0o644)
		c := h.create(CreateParams{Direction: DirectionUpload, Path: dest, Overwrite: true})
		h.svc.beforeCommit = func(id string, _ *sftp.Client) {
			// Make the rename fail: the staged file disappears under it.
			os.Remove(filepath.Join(h.status(id).StagingPath, "data"))
		}
		code, body := h.put(c.URL, strings.NewReader("replacement"))
		if code != 409 || body["commitOutcome"] != "failed" {
			t.Fatalf("upload: %d %+v", code, body)
		}
		if raw, _ := os.ReadFile(dest); string(raw) != "original" {
			t.Errorf("original not intact: %q", raw)
		}
		waitNoStaging(t, h.dir)
	})

	t.Run("connection lost during commit is unknown", func(t *testing.T) {
		h := newHarness(t, harnessOpts{})
		dest := filepath.Join(h.dir, "f")
		c := h.create(CreateParams{Direction: DirectionUpload, Path: dest})
		h.svc.beforeCommit = func(_ string, client *sftp.Client) { client.Close() }
		code, body := h.put(c.URL, strings.NewReader("mine"))
		if code != 502 || body["status"] != "failed" || body["commitOutcome"] != "unknown" ||
			!strings.Contains(body["error"].(string), "inspect the destination") {
			t.Fatalf("upload: %d %+v", code, body)
		}
		fin := h.waitStatus(c.TransferID, func(v View) bool { return v.Cleanup != "" })
		if fin.Cleanup != CleanupFailed || fin.StagingPath == "" {
			t.Errorf("unknown commit must keep the staging path: %+v", fin)
		}
		row := h.auditRow(c.TransferID)
		if *row.CommitOutcome != "unknown" || *row.Cleanup != "failed" || row.StagingPath == nil {
			t.Errorf("audit row: %+v", row)
		}
		select {
		case v := <-h.failed:
			if v.CommitOutcome != CommitUnknown || v.StagingPath == "" {
				t.Errorf("notification: %+v", v)
			}
		case <-time.After(2 * time.Second):
			t.Error("no notification")
		}
	})
}

// A server that keeps the connection open but never answers the commit must
// not pin the request and its active slot: the commit wait is bounded, and
// the outcome is unknown (the request was sent).
func TestStalledCommitTimesOut(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	h := newHarness(t, harnessOpts{clk: clk, limits: config.Transfer{MaxActivePerAccount: 1, MaxActiveGlobal: 1}})
	dest := filepath.Join(h.dir, "f")
	c := h.create(CreateParams{Direction: DirectionUpload, Path: dest})
	issued := make(chan struct{})
	h.svc.beforeCommit = func(string, *sftp.Client) {
		h.stallOps.Store(true)
		close(issued)
	}
	type result struct {
		code int
		body map[string]any
	}
	done := make(chan result, 1)
	go func() {
		code, body := h.put(c.URL, strings.NewReader("payload"))
		done <- result{code, body}
	}()
	<-issued
	time.Sleep(100 * time.Millisecond) // the commit call is parked on the silent server

	// Nothing else may end a committing transfer: not the idle watchdog…
	clk.Advance(20 * time.Second)
	if _, err := h.svc.Cancel(context.Background(), testCaller, c.TransferID); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-done:
		t.Fatalf("request ended before the commit timeout: %+v", r)
	case <-time.After(100 * time.Millisecond):
	}
	if v := h.status(c.TransferID); v.Status != StateCommitting {
		t.Fatalf("status while the commit is parked: %s", v.Status)
	}

	// …only the commit bound.
	clk.Advance(11 * time.Second)
	select {
	case r := <-done:
		if r.code != 502 || r.body["status"] != "failed" || r.body["commitOutcome"] != "unknown" ||
			!strings.Contains(r.body["error"].(string), "commitTimeoutSeconds") {
			t.Fatalf("response: %+v", r)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("stalled commit still holds the request after commitTimeoutSeconds")
	}
	fin := h.waitStatus(c.TransferID, func(v View) bool { return v.Cleanup != "" })
	if fin.Status != StateFailed || fin.CommitOutcome != CommitUnknown || fin.Cleanup != CleanupFailed || fin.StagingPath == "" {
		t.Errorf("final: %+v", fin)
	}
	// The active slot is free again (limit is 1).
	h.stallOps.Store(false)
	h.svc.beforeCommit = nil
	next := h.create(CreateParams{Direction: DirectionUpload, Path: dest + ".2"})
	if code, body := h.put(next.URL, strings.NewReader("next")); code != 200 {
		t.Errorf("upload after the stalled one: %d %+v", code, body)
	}
}

// Closing the session mid-upload aborts the request promptly and the status
// reads cancelled; other sessions are unaffected.
func TestSessionCloseCancelsActiveUpload(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	other := h.openSession()
	dest := filepath.Join(h.dir, "f")
	c := h.create(CreateParams{Direction: DirectionUpload, Path: dest})
	pending := h.create(CreateParams{Direction: DirectionUpload, Path: dest + ".2"})
	body := newGatedBody(randomBytes(1<<20), 1<<19)
	t.Cleanup(body.release)
	code := make(chan int, 1)
	go func() { st, _ := h.put(c.URL, body); code <- st }()
	<-body.firstDone
	h.waitStatus(c.TransferID, func(v View) bool { return v.StagingPath != "" })

	// Consent revocation path (the same sweep explicit close and account
	// deletion use).
	h.mgr.CloseAllForClient(testAccount, testCaller.ClientID, terminal.CloseAgentDisconnect)

	select {
	case st := <-code:
		if st == 200 {
			t.Error("upload completed despite the session closing")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("request was not aborted when the session closed")
	}
	fin := h.waitStatus(c.TransferID, func(v View) bool { return v.Cleanup != "" })
	if fin.Status != StateCancelled {
		t.Errorf("status: %+v", fin)
	}
	// Cleanup races the connection teardown: either it made it, or the
	// leftover is reported with its path.
	if fin.Cleanup == CleanupFailed && fin.StagingPath == "" {
		t.Errorf("failed cleanup without a staging path: %+v", fin)
	}
	if fin.Cleanup == CleanupOK && len(stagingDirs(t, h.dir)) != 0 {
		t.Error("cleanup reported ok but staging remains")
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Error("cancelled upload left a destination")
	}
	// The unclaimed link died with the session: uniform 404.
	if v := h.status(pending.TransferID); v.Status != StateCancelled {
		t.Errorf("pending link after session close: %s", v.Status)
	}
	if st, _ := h.put(pending.URL, strings.NewReader("x")); st != 404 {
		t.Errorf("link of a closed session: %d", st)
	}
	_ = other // closed too (same client); the point is nothing hung
}

// Remote hangup mid-upload: failed, leftover staging reported, no hang.
func TestRemoteHangupFailsUpload(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	dest := filepath.Join(h.dir, "f")
	c := h.create(CreateParams{Direction: DirectionUpload, Path: dest})
	body := newGatedBody(randomBytes(1<<20), 1<<19)
	code := make(chan int, 1)
	go func() { st, _ := h.put(c.URL, body); code <- st }()
	<-body.firstDone
	staging := h.waitStatus(c.TransferID, func(v View) bool { return v.StagingPath != "" }).StagingPath

	(<-h.conns).Close() // the remote host goes away
	body.release()
	select {
	case st := <-code:
		if st == 200 {
			t.Error("upload completed after hangup")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("upload hung on the dead connection")
	}
	fin := h.waitStatus(c.TransferID, func(v View) bool { return v.Cleanup != "" })
	if fin.Status != StateFailed || fin.Cleanup != CleanupFailed || fin.StagingPath != staging {
		t.Errorf("after hangup: %+v", fin)
	}
	if row := h.auditRow(c.TransferID); row.Status != "failed" || *row.Cleanup != "failed" || *row.StagingPath != staging {
		t.Errorf("audit row: %+v", row)
	}
	evs := h.rec.forTransfer(c.TransferID)
	if last := evs[len(evs)-1]; last["cleanup"] != "failed" || last["stagingPath"] != staging {
		t.Errorf("last event: %+v", last)
	}
	select {
	case <-h.failed:
	case <-time.After(2 * time.Second):
		t.Error("no failure notification")
	}
}

// A stalled upload fails after idleTimeoutSeconds and its staging is removed;
// a link expires after linkTtlSeconds.
func TestIdleTimeoutAndLinkExpiry(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	h := newHarness(t, harnessOpts{clk: clk})
	dest := filepath.Join(h.dir, "f")
	c := h.create(CreateParams{Direction: DirectionUpload, Path: dest})
	body := newGatedBody(randomBytes(1<<16), 1<<15)
	t.Cleanup(body.release)
	code := make(chan int, 1)
	go func() { st, _ := h.put(c.URL, body); code <- st }()
	<-body.firstDone
	h.waitStatus(c.TransferID, func(v View) bool { return v.StagingPath != "" && v.Bytes > 0 })
	time.Sleep(50 * time.Millisecond) // let the watchdog arm its timer

	clk.Advance(61 * time.Second)
	select {
	case st := <-code:
		if st == 200 {
			t.Error("stalled upload completed")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("stalled upload was not aborted")
	}
	// Cleanup needs the (fake) clock only for its timeout; it finishes on its own.
	fin := h.waitStatus(c.TransferID, func(v View) bool { return v.Cleanup != "" })
	if fin.Status != StateFailed || !strings.Contains(fin.Error, "idle timeout") || fin.Cleanup != CleanupOK {
		t.Errorf("stalled upload: %+v", fin)
	}
	waitNoStaging(t, h.dir)

	// TTL: an unused link expires, notifies, and answers the uniform 404.
	for len(h.failed) > 0 {
		<-h.failed
	}
	exp := h.create(CreateParams{Direction: DirectionUpload, Path: dest})
	clk.Advance(301 * time.Second)
	h.svc.Sweep()
	if v := h.status(exp.TransferID); v.Status != StateExpired {
		t.Errorf("status after TTL: %s", v.Status)
	}
	if st, _ := h.put(exp.URL, strings.NewReader("late")); st != 404 {
		t.Errorf("expired link: %d", st)
	}
	select {
	case v := <-h.failed:
		if v.Status != StateExpired {
			t.Errorf("notification: %+v", v)
		}
	default:
		t.Error("no notification for the expired link")
	}
	// A link that is past its TTL but not yet swept is rejected at claim too.
	late := h.create(CreateParams{Direction: DirectionUpload, Path: dest})
	clk.Advance(301 * time.Second)
	if st, _ := h.put(late.URL, strings.NewReader("late")); st != 404 {
		t.Errorf("unswept expired link: %d", st)
	}

	// Retention: finished records are evicted, status then answers from audit.
	clk.Advance(2 * time.Hour)
	h.svc.Sweep()
	h.svc.mu.Lock()
	n := len(h.svc.byID)
	h.svc.mu.Unlock()
	if n != 0 {
		t.Errorf("%d records retained past statusRetentionSeconds", n)
	}
	if v := h.status(c.TransferID); v.Status != StateFailed || !strings.Contains(v.Error, "idle timeout") {
		t.Errorf("status from the audit row: %+v", v)
	}
}

func TestLimits(t *testing.T) {
	h := newHarness(t, harnessOpts{limits: config.Transfer{
		MaxTransferBytes: 1 << 16, MaxPendingPerSession: 2, MaxPendingGlobal: 3,
		MaxActivePerAccount: 1, MaxActiveGlobal: 1, MaxStatusRecords: 6,
	}})
	ctx := context.Background()
	p := func(name string) string { return filepath.Join(h.dir, name) }

	// Byte cap without a Content-Length: aborted mid-stream, staging removed.
	c := h.create(CreateParams{Direction: DirectionUpload, Path: p("big")})
	if code, _ := h.put(c.URL, io.MultiReader(bytes.NewReader(randomBytes(1<<17)))); code != 413 {
		t.Errorf("oversized chunked upload: %d", code)
	}
	waitNoStaging(t, h.dir)
	if _, err := os.Stat(p("big")); !os.IsNotExist(err) {
		t.Error("oversized upload reached the destination")
	}
	// With a Content-Length it is rejected before any staging.
	c = h.create(CreateParams{Direction: DirectionUpload, Path: p("big")})
	if code, _ := h.put(c.URL, bytes.NewReader(randomBytes(1<<17))); code != 413 {
		t.Errorf("oversized upload: %d", code)
	}
	if _, err := h.svc.Create(ctx, testCaller, CreateParams{SessionID: h.sessID, Direction: DirectionUpload, Path: p("x"), MaxBytes: 1 << 20}); err == nil {
		t.Error("maxBytes above the server limit accepted")
	}

	// Pending bounds.
	a := h.create(CreateParams{Direction: DirectionUpload, Path: p("a")})
	b := h.create(CreateParams{Direction: DirectionUpload, Path: p("b")})
	if _, err := h.svc.Create(ctx, testCaller, CreateParams{SessionID: h.sessID, Direction: DirectionUpload, Path: p("c")}); err == nil ||
		!strings.Contains(err.Error(), "maxPendingPerSession") {
		t.Errorf("per-session pending bound: %v", err)
	}
	second := h.openSession()
	h.create(CreateParams{SessionID: second, Direction: DirectionUpload, Path: p("d")})
	if _, err := h.svc.Create(ctx, testCaller, CreateParams{SessionID: second, Direction: DirectionUpload, Path: p("e")}); err == nil ||
		!strings.Contains(err.Error(), "maxPendingGlobal") {
		t.Errorf("global pending bound: %v", err)
	}

	// Active capacity is acquired at claim: the excess gets 503 + Retry-After,
	// stays pending, and succeeds once the slot frees.
	body := newGatedBody([]byte("first-upload"), 5)
	first := make(chan int, 1)
	go func() { st, _ := h.put(a.URL, body); first <- st }()
	<-body.firstDone
	h.waitStatus(a.TransferID, func(v View) bool { return v.Status == StateActive })

	req, _ := http.NewRequest(http.MethodPut, b.URL, strings.NewReader("second"))
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 503 || res.Header.Get("Retry-After") == "" || res.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("capacity rejection: %d retry-after=%q cache-control=%q", res.StatusCode, res.Header.Get("Retry-After"), res.Header.Get("Cache-Control"))
	}
	if v := h.status(b.TransferID); v.Status != StatePending {
		t.Errorf("rejected claim consumed the token: %s", v.Status)
	}
	body.release()
	if st := <-first; st != 200 {
		t.Fatalf("first upload: %d", st)
	}
	if st, out := h.put(b.URL, strings.NewReader("second")); st != 200 {
		t.Errorf("retry after the slot freed: %d %+v", st, out)
	}
}

// The status map never exceeds maxStatusRecords under a burst.
func TestStatusMapBound(t *testing.T) {
	h := newHarness(t, harnessOpts{limits: config.Transfer{MaxStatusRecords: 8, MaxPendingPerSession: 2, MaxPendingGlobal: 4, MaxActiveGlobal: 2, MaxActivePerAccount: 2}})
	ctx := context.Background()
	var first string
	for i := 0; i < 40; i++ {
		c := h.create(CreateParams{Direction: DirectionUpload, Path: filepath.Join(h.dir, "burst")})
		if first == "" {
			first = c.TransferID
		}
		if _, err := h.svc.Cancel(ctx, testCaller, c.TransferID); err != nil {
			t.Fatal(err)
		}
		h.svc.mu.Lock()
		n := len(h.svc.byID)
		h.svc.mu.Unlock()
		if n > 8 {
			t.Fatalf("status map grew to %d", n)
		}
	}
	// The evicted record is still answerable from the audit row.
	if v := h.status(first); v.Status != StateCancelled {
		t.Errorf("evicted record: %+v", v)
	}
}

// Downloads are byte-identical, sha256 describes the bytes sent, and
// shrink/grow are reported as observed.
func TestDownload(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	get := func(url string) (*http.Response, []byte, error) {
		res, err := http.Get(url)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		data, err := io.ReadAll(res.Body)
		return res, data, err
	}

	t.Run("identical", func(t *testing.T) {
		src := filepath.Join(h.dir, "dump.bin")
		data := randomBytes(6 << 20)
		os.WriteFile(src, data, 0o600)
		c := h.create(CreateParams{Direction: DirectionDownload, Path: src})
		if c.Method != "GET" || !strings.Contains(c.Command, "curl -fsS -o './dump.bin'") {
			t.Errorf("created: %+v", c)
		}
		res, got, err := get(c.URL)
		if err != nil || res.StatusCode != 200 || !bytes.Equal(got, data) {
			t.Fatalf("download: %d err=%v equal=%v", res.StatusCode, err, bytes.Equal(got, data))
		}
		if res.Header.Get("Cache-Control") != "no-store" || res.Header.Get("Content-Type") != "application/octet-stream" ||
			res.ContentLength != int64(len(data)) {
			t.Errorf("headers: %+v", res.Header)
		}
		v := h.waitStatus(c.TransferID, func(v View) bool { return v.Status.finished() })
		if v.Status != StateCompleted || v.SHA256 != sha(data) || v.Bytes != int64(len(data)) || v.Truncated == nil || *v.Truncated {
			t.Errorf("status: %+v", v)
		}
		if r2, _, _ := get(c.URL); r2.StatusCode != 404 {
			t.Errorf("second use: %d", r2.StatusCode)
		}
	})

	t.Run("directory refused", func(t *testing.T) {
		if _, err := h.svc.Create(context.Background(), testCaller, CreateParams{SessionID: h.sessID, Direction: DirectionDownload, Path: h.dir}); err == nil {
			t.Error("download of a directory accepted")
		}
	})

	// Mid-stream control: read a little, mutate the file, read the rest. The
	// file is far larger than the socket buffers, so the server is still
	// streaming when the mutation lands.
	const size = 64 << 20
	partial := func(t *testing.T, mutate func(path string)) (View, []byte, error) {
		src := filepath.Join(h.dir, "live-"+randHex(3))
		f, _ := os.Create(src)
		f.Truncate(size)
		f.Close()
		c := h.create(CreateParams{Direction: DirectionDownload, Path: src})
		res, err := http.Get(c.URL)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		head := make([]byte, 1<<20)
		if _, err := io.ReadFull(res.Body, head); err != nil {
			t.Fatal(err)
		}
		mutate(src)
		rest, err := io.ReadAll(res.Body)
		v := h.waitStatus(c.TransferID, func(v View) bool { return v.Status.finished() })
		return v, append(head, rest...), err
	}

	t.Run("shrinks mid-download", func(t *testing.T) {
		v, got, err := partial(t, func(p string) { os.Truncate(p, 1<<20) })
		if err == nil || len(got) >= size {
			t.Errorf("client saw a complete body (%d bytes, err=%v)", len(got), err)
		}
		if v.Status != StateFailed || v.Error != "file shrank during transfer" {
			t.Errorf("status: %+v", v)
		}
	})

	t.Run("grows mid-download", func(t *testing.T) {
		v, got, err := partial(t, func(p string) {
			f, _ := os.OpenFile(p, os.O_WRONLY|os.O_APPEND, 0)
			f.Write([]byte("appended"))
			f.Close()
		})
		if err != nil || len(got) != size {
			t.Fatalf("body: %d bytes, err=%v", len(got), err)
		}
		if v.Status != StateCompleted || v.Truncated == nil || !*v.Truncated || v.SHA256 != sha(got) {
			t.Errorf("status: status=%s truncated=%v", v.Status, v.Truncated)
		}
		row := h.auditRow(v.TransferID)
		if row.Truncated == nil || !*row.Truncated {
			t.Errorf("audit truncated: %+v", row.Truncated)
		}
		evs := h.rec.forTransfer(v.TransferID)
		if evs[len(evs)-1]["truncated"] != true {
			t.Errorf("last event: %+v", evs[len(evs)-1])
		}
	})
}

// Without the posix-rename/hardlink extensions link uploads are refused at
// create; inline tools and downloads still work.
func TestUploadRequiresExtensions(t *testing.T) {
	if err := sftp.SetSFTPExtensions("statvfs@openssh.com"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		sftp.SetSFTPExtensions("statvfs@openssh.com", "posix-rename@openssh.com", "hardlink@openssh.com")
	})
	h := newHarness(t, harnessOpts{})
	dest := filepath.Join(h.dir, "f")
	_, err := h.svc.Create(context.Background(), testCaller, CreateParams{SessionID: h.sessID, Direction: DirectionUpload, Path: dest})
	if err == nil || !strings.Contains(err.Error(), "lacks posix-rename/hardlink") {
		t.Fatalf("create without extensions: %v", err)
	}
	if _, err := h.svc.WriteFile(context.Background(), testCaller, WriteParams{SessionID: h.sessID, Path: dest, Content: "inline works"}); err != nil {
		t.Errorf("inline write without extensions: %v", err)
	}
	c := h.create(CreateParams{Direction: DirectionDownload, Path: dest})
	res, err := http.Get(c.URL)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if string(raw) != "inline works" {
		t.Errorf("download without extensions: %q", raw)
	}
}
