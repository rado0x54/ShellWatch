// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Link tier (#263): PUT/GET /api/transfers/{token}. The token is the only
// credential on the route (the agent's sandbox has no OAuth token), which is
// why it is short-lived, single-use and bound to one transfer. Bytes stream
// between the HTTP body and a dedicated SFTP channel through a counting
// reader with a running sha256 — never buffered in full, never in model
// context.
//
// Uploads stage in a private directory next to the destination and commit
// atomically: hardlink (no-clobber) or posix-rename (replace). There is no
// fallback to weaker semantics.
package transfer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"os"
	"path"
	"strconv"
	"time"

	"github.com/pkg/sftp"

	"github.com/rado0x54/shellwatch/internal/terminal"
)

const (
	// uploadConcurrency pipelines SFTP write requests so throughput is not
	// bound to one round trip per 32 KiB packet.
	uploadConcurrency = 16
	// downloadChunk is the read size; pkg/sftp splits a read this large into
	// concurrent requests.
	downloadChunk = 256 << 10
	// unreadBodyDrain bounds net/http's drain of an unread upload body before
	// a failure response is written.
	unreadBodyDrain = time.Second
	// retryAfterSeconds is the hint on a capacity rejection.
	retryAfterSeconds = 5
)

// httpError is a link failure with the HTTP status it maps to (when the
// response has not started yet).
type httpError struct {
	status int
	msg    string
}

func (e *httpError) Error() string { return e.msg }

func failf(status int, format string, args ...any) *httpError {
	return &httpError{status: status, msg: fmt.Sprintf(format, args...)}
}

var errUniformNotFound = &httpError{status: http.StatusNotFound, msg: "Not found"}

func writeJSON(w http.ResponseWriter, status int, body map[string]any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// Handle serves one transfer link. Unknown, used, expired and
// session-invalidated tokens — and a method that does not match the link's
// direction — all get the same 404.
func (s *Service) Handle(w http.ResponseWriter, r *http.Request, token string) {
	w.Header().Set("Cache-Control", "no-store")

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	rc := http.NewResponseController(w)
	interrupt := func() {
		// Unblock a handler parked in body I/O; errors (unsupported writer)
		// are irrelevant — the context is cancelled as well.
		_ = rc.SetReadDeadline(time.Now())
		_ = rc.SetWriteDeadline(time.Now())
	}

	x, herr := s.claim(r.Method, token, cancel, interrupt)
	if herr != nil {
		if herr.status == http.StatusServiceUnavailable {
			w.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds))
		}
		_ = rc.SetReadDeadline(time.Now().Add(unreadBodyDrain)) // see below
		writeJSON(w, herr.status, map[string]any{"error": herr.msg})
		return
	}
	s.emit(x, true) // audit row: active, before any SFTP resource is opened
	go s.watch(ctx, x)

	headersSent := false
	if x.Direction == DirectionUpload {
		herr = s.upload(ctx, r, x)
	} else {
		herr = s.download(ctx, w, x, &headersSent)
	}
	if herr != nil {
		// No-op when an abort (cancel, session end, timeout) or the commit
		// already finalized the transfer; then its recorded error wins.
		s.fail(x, herr.msg)
	}
	s.notifyFailed(x)
	// An external abort interrupted body I/O with past deadlines: lift the
	// write deadline so the outcome can still be written. The read side stays
	// bounded — before replying, net/http drains what is left of an unread
	// request body, and an upload that stalled (the reason it was aborted)
	// would park that drain, and the response, indefinitely.
	_ = rc.SetWriteDeadline(time.Time{})
	_ = rc.SetReadDeadline(time.Now().Add(unreadBodyDrain))

	v := s.view(x)
	if headersSent {
		// Download body already under way: a failure can only be signalled by
		// ending the response short of Content-Length.
		return
	}
	if v.Status == StateCompleted {
		writeJSON(w, http.StatusOK, v.StatusResult())
		return
	}
	// The handler's own failure (or a commit outcome) carries a specific
	// status; a transfer finalized from outside (cancel, session end, idle
	// timeout) answers 409 with the recorded reason.
	status := http.StatusConflict
	if herr != nil && (v.Error == herr.msg || v.CommitOutcome != "") {
		status = herr.status
	}
	body := v.StatusResult()
	if _, ok := body["error"]; !ok && herr != nil {
		body["error"] = herr.msg
	}
	writeJSON(w, status, body)
}

// claim consumes the token and moves pending → active. The token lookup, the
// session-open check and the capacity acquisition happen in ONE critical
// section, before any SFTP resource exists. A capacity shortage answers 503
// and leaves the token pending, so a retrying client can still succeed
// within the TTL.
func (s *Service) claim(method, token string, cancel context.CancelFunc, interrupt func()) (*xfer, *httpError) {
	now := s.clk.Now()
	s.mu.Lock()
	x, ok := s.byToken[token]
	if !ok || x.Status != StatePending {
		s.mu.Unlock()
		return nil, errUniformNotFound
	}
	want := http.MethodPut
	if x.Direction == DirectionDownload {
		want = http.MethodGet
	}
	if method != want {
		s.mu.Unlock()
		return nil, errUniformNotFound
	}
	if !now.Before(x.ExpiresAt) {
		s.mu.Unlock()
		s.abort(x, StateExpired, "link expired before it was used")
		return nil, errUniformNotFound
	}
	if sess := s.mgr.GetSession(x.SessionID); sess == nil || sess.Status != terminal.StatusOpen {
		s.mu.Unlock()
		s.abort(x, StateCancelled, "session closed")
		return nil, errUniformNotFound
	}
	activeAccount, activeGlobal := 0, 0
	for _, o := range s.byID {
		if o.Status == StateActive || o.Status == StateCommitting {
			activeGlobal++
			if o.AccountID == x.AccountID {
				activeAccount++
			}
		}
	}
	if activeAccount >= s.lim.MaxActivePerAccount || activeGlobal >= s.lim.MaxActiveGlobal {
		s.mu.Unlock()
		return nil, failf(http.StatusServiceUnavailable, "too many active transfers; retry shortly")
	}
	x.Status = StateActive
	x.UpdatedAt = now
	x.lastProgress = time.Time{}
	x.claimed, x.cancel, x.interrupt = true, cancel, interrupt
	delete(s.byToken, token) // single use
	v := x.View
	s.mu.Unlock()
	logTransfer(v)
	return x, nil
}

// watch enforces the idle timeout and the hard duration cap of an active
// transfer until its request context ends.
func (s *Service) watch(ctx context.Context, x *xfer) {
	idle := time.Duration(s.lim.IdleTimeoutSeconds) * time.Second
	started := s.clk.Now()
	maxCh, stopMax := s.clk.After(time.Duration(s.lim.MaxDurationSeconds) * time.Second)
	defer stopMax()
	wait := idle
	for {
		idleCh, stopIdle := s.clk.After(wait)
		select {
		case <-ctx.Done():
			stopIdle()
			return
		case <-maxCh:
			stopIdle()
			s.abort(x, StateFailed, fmt.Sprintf("transfer exceeded transfer.maxDurationSeconds (%d)", s.lim.MaxDurationSeconds))
			return
		case <-idleCh:
			s.mu.Lock()
			last := x.lastProgress
			s.mu.Unlock()
			if last.IsZero() {
				last = started
			}
			if quiet := s.clk.Now().Sub(last); quiet >= idle {
				s.abort(x, StateFailed, fmt.Sprintf("idle timeout: no bytes moved for %d seconds", s.lim.IdleTimeoutSeconds))
				return
			} else {
				wait = idle - quiet
			}
		}
	}
}

// openChannel opens the transfer's OWN sftp channel, bounded like an inline
// call. Cancelling a transfer closes this channel and its file handle only —
// never the PTY, never the session's shared inline channel.
func (s *Service) openChannel(ctx context.Context, sessionID string) (*sftp.Client, *httpError) {
	openCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	deadline, stop := s.clk.After(time.Duration(s.lim.InlineTimeoutSeconds) * time.Second)
	defer stop()
	type result struct {
		client *sftp.Client
		err    error
	}
	done := make(chan result, 1)
	go func() {
		c, err := s.mgr.OpenSFTP(openCtx, sessionID)
		done <- result{c, err}
	}()
	select {
	case r := <-done:
		if r.err != nil {
			return nil, failf(http.StatusBadGateway, "open sftp channel: %v", r.err)
		}
		return r.client, nil
	case <-deadline:
		cancel()
		go func() {
			if r := <-done; r.client != nil {
				_ = r.client.Close()
			}
		}()
		return nil, failf(http.StatusBadGateway, "open sftp channel: timed out")
	}
}

// meter is the counting reader/writer core: byte cap, running sha256,
// progress accounting, and prompt reaction to cancellation.
type meter struct {
	ctx  context.Context
	s    *Service
	x    *xfer
	hash hash.Hash
	n    int64
}

func (m *meter) add(p []byte) {
	m.hash.Write(p)
	m.n += int64(len(p))
	m.s.progress(m.x, int64(len(p)))
}

func (m *meter) sum() string { return hex.EncodeToString(m.hash.Sum(nil)) }

var errTooLarge = errors.New("transfer exceeds the byte cap")

// uploadReader meters the request body on its way to the SFTP channel.
type uploadReader struct {
	meter
	body io.Reader
	max  int64
}

func (r *uploadReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := r.body.Read(p)
	if n > 0 {
		if r.n+int64(n) > r.max {
			return 0, errTooLarge
		}
		r.add(p[:n])
	}
	return n, err
}

// upload stages, streams, and commits. See the package comment and the tool
// documentation (docs/api/mcp-tools.md) for the contract each step keeps.
func (s *Service) upload(ctx context.Context, r *http.Request, x *xfer) *httpError {
	if r.ContentLength > x.maxBytes {
		return failf(http.StatusRequestEntityTooLarge, "upload is %d bytes, above the %d byte cap", r.ContentLength, x.maxBytes)
	}
	if r.ContentLength >= 0 {
		s.update(x, func(v *View) { v.TotalBytes = r.ContentLength })
	}
	client, herr := s.openChannel(ctx, x.SessionID)
	if herr != nil {
		return herr
	}
	defer client.Close()
	// Last resort against a stalled server: if the handler has not unwound a
	// while after its context ended, drop the channel under it.
	handlerDone := make(chan struct{})
	defer close(handlerDone)
	go func() {
		select {
		case <-handlerDone:
			return
		case <-ctx.Done():
		}
		grace, stop := s.clk.After(2 * time.Duration(s.lim.CleanupTimeoutSeconds) * time.Second)
		defer stop()
		select {
		case <-handlerDone:
		case <-grace:
			_ = client.Close()
		}
	}()

	if err := requireUploadExtensions(client); err != nil {
		return failf(http.StatusConflict, "%v", err)
	}
	existing, err := checkWriteDestination(client, x.Path)
	if err != nil {
		return failf(http.StatusConflict, "%v", err)
	}
	if existing != nil && !x.overwrite {
		return failf(http.StatusConflict, "%s already exists; create the link with overwrite=true to replace it", x.Path)
	}

	// 1. Private staging directory next to the destination. pkg/sftp sends no
	// attrs on MKDIR or OPEN, so chmod-after-create is unavoidable: doing it
	// on the still-EMPTY directory means no file exists during the window,
	// and once it is 0700 nobody else can traverse into it.
	dir, base := path.Split(x.Path)
	staging := path.Join(dir, "."+base+"."+randHex(4)+".tmp")
	data := path.Join(staging, "data")
	if err := client.Mkdir(staging); err != nil {
		// A collision is a hard failure: an existing entry is never reused.
		return failf(http.StatusBadGateway, "create staging directory %s: %v", staging, err)
	}
	s.update(x, func(v *View) { v.StagingPath = staging }) // audit row carries it from now on
	removeData := false
	herr = func() *httpError {
		if err := client.Chmod(staging, 0o700); err != nil {
			return failf(http.StatusBadGateway, "chmod staging directory: %v", err)
		}
		f, err := client.OpenFile(data, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
		if err != nil {
			return failf(http.StatusBadGateway, "create staging file: %v", err)
		}
		removeData = true
		if err := f.Chmod(0o600); err != nil { // before the first byte
			f.Close()
			return failf(http.StatusBadGateway, "chmod staging file: %v", err)
		}

		// 2. Stream under the byte cap.
		in := &uploadReader{meter: meter{ctx: ctx, s: s, x: x, hash: sha256.New()}, body: r.Body, max: x.maxBytes}
		_, err = f.ReadFromWithConcurrency(in, uploadConcurrency)
		closeErr := f.Close()
		switch {
		case errors.Is(err, errTooLarge):
			return failf(http.StatusRequestEntityTooLarge, "upload exceeds the %d byte cap", x.maxBytes)
		case err != nil:
			return failf(http.StatusBadGateway, "upload stream failed: %v", err)
		case closeErr != nil:
			return failf(http.StatusBadGateway, "close staging file: %v", closeErr)
		}
		digest := in.sum()
		if x.expectSHA != "" && digest != x.expectSHA {
			return failf(http.StatusUnprocessableEntity, "sha256 mismatch: expected %s, received %s", x.expectSHA, digest)
		}
		s.update(x, func(v *View) { v.SHA256 = digest })

		// 3. Final mode on the staged file.
		mode := os.FileMode(0o644)
		switch {
		case x.mode != nil:
			mode = *x.mode
		case existing != nil:
			mode = existing.Mode().Perm()
		}
		if err := client.Chmod(data, mode); err != nil {
			return failf(http.StatusBadGateway, "chmod staged file: %v", err)
		}

		// 4. Commit. Entering committing is the point of no return for
		// cancellation: a cancel that got here first wins, one that arrives
		// later is ignored.
		if !s.beginCommit(x) {
			return failf(http.StatusConflict, "transfer was cancelled")
		}
		if s.beforeCommit != nil {
			s.beforeCommit(x.TransferID, client)
		}
		cerr, timedOut := s.commit(client, func() error {
			if x.overwrite {
				// Atomic replace. Never remove-then-rename: on failure the
				// original is still in place.
				return client.PosixRename(data, x.Path)
			}
			// link(2) fails on ANY existing entry, so no-clobber is atomic
			// with no pre-check.
			return client.Link(data, x.Path)
		})

		// 5. completed only after an acknowledged commit.
		switch {
		case timedOut:
			s.finish(x, StateFailed, func(v *View) {
				v.CommitOutcome = CommitUnknown
				v.Error = fmt.Sprintf("no reply to the commit within transfer.commitTimeoutSeconds (%d); the outcome is unknown — inspect the destination (size, sha256) before retrying", s.lim.CommitTimeoutSeconds)
			})
			return failf(http.StatusBadGateway, "commit outcome unknown")
		case cerr == nil:
			removeData = !x.overwrite // a rename moved the staged file away
			s.finish(x, StateCompleted, func(v *View) { v.CommitOutcome = CommitOK })
			return nil
		case isConnLost(cerr):
			s.finish(x, StateFailed, func(v *View) {
				v.CommitOutcome = CommitUnknown
				v.Error = "connection lost after the commit was sent and before its reply arrived; the outcome is unknown — inspect the destination (size, sha256) before retrying"
			})
			return failf(http.StatusBadGateway, "commit outcome unknown")
		default:
			hint := "the original file is still in place"
			if !x.overwrite {
				hint = "the destination was not touched (it already exists, or the filesystem refuses hard links)"
			}
			s.finish(x, StateFailed, func(v *View) {
				v.CommitOutcome = CommitFailed
				v.Error = fmt.Sprintf("commit failed: %v; %s", cerr, hint)
			})
			return failf(http.StatusConflict, "commit failed: %v", cerr)
		}
	}()
	if herr != nil {
		// Finalize before cleaning up so status/cancel answer promptly; a
		// no-op when the transfer is already terminal.
		s.fail(x, herr.msg)
	}

	// 6. Cleanup: best effort and bounded.
	s.cleanupStaging(x, client, staged{dir: staging, data: data, removeData: removeData})
	return herr
}

// commit issues the commit call under transfer.commitTimeoutSeconds. A
// committing transfer is deliberately immune to abort — cancel, the idle
// watchdog and the duration cap all stand down once the commit is issued — so
// this is the only bound on a server that keeps the connection open and never
// answers. On expiry the transfer's own channel is closed (which also
// releases the parked request) and the caller records the outcome as unknown:
// the request was sent, its reply never came.
func (s *Service) commit(client *sftp.Client, call func() error) (err error, timedOut bool) {
	done := make(chan error, 1)
	go func() { done <- call() }()
	timeout, stop := s.clk.After(time.Duration(s.lim.CommitTimeoutSeconds) * time.Second)
	defer stop()
	select {
	case err := <-done:
		return err, false
	case <-timeout:
		_ = client.Close()
		return nil, true
	}
}

// staged names an upload's staging area for cleanup.
type staged struct {
	dir  string // the private staging directory
	data string // the staged file inside it
	// removeData is false once a posix-rename moved the staged file away.
	removeData bool
}

// cleanupStaging removes the staged file (when it still exists) and the
// staging directory, bounded by transfer.cleanupTimeoutSeconds. A failure —
// including a connection that is already gone — is recorded as
// cleanup "failed" with the staging path, so the human can remove the
// leftover; success clears the staging path.
func (s *Service) cleanupStaging(x *xfer, client *sftp.Client, st staged) {
	done := make(chan error, 1)
	go func() {
		if st.removeData {
			if err := client.Remove(st.data); err != nil && !errors.Is(err, os.ErrNotExist) {
				done <- err
				return
			}
		}
		done <- client.RemoveDirectory(st.dir)
	}()
	timeout, stop := s.clk.After(time.Duration(s.lim.CleanupTimeoutSeconds) * time.Second)
	defer stop()
	var err error
	select {
	case err = <-done:
	case <-timeout:
		_ = client.Close() // unblocks the goroutine; the leftover is reported
		err = errors.New("cleanup timed out")
	}
	s.update(x, func(v *View) {
		if err != nil {
			v.Cleanup = CleanupFailed
		} else {
			v.Cleanup, v.StagingPath = CleanupOK, ""
		}
	})
}

// download streams a remote file to the response.
//
// The file is opened first and size/mode come from the open handle. Exactly
// Content-Length bytes are sent; a premature EOF observed before that ends
// the response short and fails the transfer. After the last selected byte one
// extra byte is probed on the same handle: data there is OBSERVED growth
// (truncated: true). Concurrent mutation cannot be detected in general.
// completed means the server finished writing the response — it cannot attest
// that the client saved the file.
func (s *Service) download(ctx context.Context, w http.ResponseWriter, x *xfer, headersSent *bool) *httpError {
	client, herr := s.openChannel(ctx, x.SessionID)
	if herr != nil {
		return herr
	}
	defer client.Close()
	// A cancelled transfer must not stay parked on a stalled server.
	stopWatch := context.AfterFunc(ctx, func() { _ = client.Close() })
	defer stopWatch()

	f, err := client.Open(x.Path)
	if err != nil {
		return failf(http.StatusConflict, "open %s: %v", x.Path, err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return failf(http.StatusBadGateway, "stat %s: %v", x.Path, err)
	}
	if !fi.Mode().IsRegular() {
		return failf(http.StatusConflict, "%s is a %s, not a regular file", x.Path, fileType(fi.Mode()))
	}
	size := fi.Size()
	if size > x.maxBytes {
		return failf(http.StatusRequestEntityTooLarge, "%s is %d bytes, above the %d byte cap", x.Path, size, x.maxBytes)
	}
	s.update(x, func(v *View) { v.TotalBytes = size })

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	w.Header().Set("X-Transfer-Id", x.TransferID)
	w.WriteHeader(http.StatusOK)
	*headersSent = true

	m := &meter{ctx: ctx, s: s, x: x, hash: sha256.New()}
	buf := make([]byte, downloadChunk)
	for remaining := size; remaining > 0; {
		if err := ctx.Err(); err != nil {
			return failf(http.StatusConflict, "transfer aborted: %v", err)
		}
		chunk := buf
		if int64(len(chunk)) > remaining {
			chunk = chunk[:remaining]
		}
		n, err := f.Read(chunk)
		if n > 0 {
			if _, werr := w.Write(chunk[:n]); werr != nil {
				return failf(http.StatusBadGateway, "client stopped reading: %v", werr)
			}
			m.add(chunk[:n])
			remaining -= int64(n)
		}
		if err != nil && remaining > 0 {
			if errors.Is(err, io.EOF) {
				return failf(http.StatusConflict, "file shrank during transfer")
			}
			return failf(http.StatusBadGateway, "read %s: %v", x.Path, err)
		}
	}
	// Post-copy probe (a read, not a stat): one extra byte on the same handle.
	var probe [1]byte
	n, _ := f.Read(probe[:])
	grew := n > 0
	s.finish(x, StateCompleted, func(v *View) {
		v.SHA256 = m.sum() // always the bytes actually sent
		v.Truncated = &grew
	})
	return nil
}
