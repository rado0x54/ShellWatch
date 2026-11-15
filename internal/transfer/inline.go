// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Inline tier (#263): list/read/write of small files through tool calls.
// One SFTP channel per session, opened lazily and reused; concurrent calls on
// a session pass a semaphore (transfer.maxInlineConcurrency) and the whole
// call — channel setup included — is bounded by transfer.inlineTimeoutSeconds,
// so a stalled server cannot hold an MCP request open. Every operation mints a
// transferId, one audit row and one terminal:file frame.
package transfer

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/pkg/sftp"

	"github.com/rado0x54/shellwatch/internal/clock"
)

// errInlineTimeout is the inline tier's bound firing.
var errInlineTimeout = errors.New("file operation timed out")

// sessionFS is one session's shared inline SFTP channel + its semaphore.
type sessionFS struct {
	sem chan struct{}

	mu     sync.Mutex
	client *sftp.Client
}

func (s *Service) sessionFS(sessionID string) *sessionFS {
	s.mu.Lock()
	defer s.mu.Unlock()
	fs, ok := s.sessions[sessionID]
	if !ok {
		fs = &sessionFS{sem: make(chan struct{}, s.lim.MaxInlineConcurrency)}
		s.sessions[sessionID] = fs
	}
	return fs
}

// dropSession closes and forgets a session's inline channel (session ended).
func (s *Service) dropSession(sessionID string) {
	s.mu.Lock()
	fs := s.sessions[sessionID]
	delete(s.sessions, sessionID)
	s.mu.Unlock()
	if fs != nil {
		fs.discard(nil)
	}
}

// get returns the shared client, opening the channel on first use.
func (fs *sessionFS) get(ctx context.Context, open func(context.Context) (*sftp.Client, error)) (*sftp.Client, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if fs.client != nil {
		return fs.client, nil
	}
	client, err := open(ctx)
	if err != nil {
		return nil, err
	}
	fs.client = client
	return client, nil
}

// discard closes the shared client so the next call reopens the channel.
// only, when non-nil, limits it to that client (a newer one is left alone).
func (fs *sessionFS) discard(only *sftp.Client) {
	fs.mu.Lock()
	client := fs.client
	if client == nil || (only != nil && client != only) {
		fs.mu.Unlock()
		return
	}
	fs.client = nil
	fs.mu.Unlock()
	_ = client.Close()
}

// inline runs fn on the session's shared SFTP channel under the inline
// bounds. On timeout the channel is closed — that is what unblocks a request
// parked on a stalled server and what keeps channels from leaking — and the
// next call opens a fresh one.
func (s *Service) inline(ctx context.Context, sessionID string, fn func(*sftp.Client) error) error {
	deadline, stop := s.clk.After(time.Duration(s.lim.InlineTimeoutSeconds) * time.Second)
	defer stop()
	fs := s.sessionFS(sessionID)

	select {
	case fs.sem <- struct{}{}:
	case <-deadline:
		return errInlineTimeout
	case <-ctx.Done():
		return ctx.Err()
	}

	opCtx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	var used atomic.Pointer[sftp.Client]
	go func() {
		defer func() { <-fs.sem }() // the slot frees when the work really stopped
		defer cancel()
		client, err := fs.get(opCtx, func(c context.Context) (*sftp.Client, error) {
			return s.mgr.OpenSFTP(c, sessionID)
		})
		if err != nil {
			done <- err
			return
		}
		if opCtx.Err() != nil {
			// The caller already gave up (timeout while queued behind a
			// channel setup): never start the operation after reporting failure.
			done <- errInlineTimeout
			return
		}
		used.Store(client)
		err = fn(client)
		if isConnLost(err) {
			fs.discard(client) // dead channel: reopen on the next call
		}
		done <- err
	}()

	giveUp := func() {
		cancel() // unblocks a channel setup in flight
		if client := used.Load(); client != nil {
			fs.discard(client) // unblocks a request parked on the server
		}
	}
	select {
	case err := <-done:
		return err
	case <-deadline:
		giveUp()
		return errInlineTimeout
	case <-ctx.Done():
		giveUp()
		return ctx.Err()
	}
}

// inlineOp wraps one audited inline operation: session check, the bounded
// SFTP call, the audit row + terminal:file frame, and — on success with
// actual content — the session activity touch.
type inlineOp struct {
	direction string
	path      string
	bytes     int64
	sha256    string
	// touch reports whether a successful call counts as session activity.
	touch bool
}

func (s *Service) runInline(ctx context.Context, c Caller, sessionID string, op *inlineOp, fn func(*sftp.Client) error) (string, error) {
	sess, err := s.openSession(c, sessionID)
	if err != nil {
		return "", err
	}
	if err := validatePath(op.path); err != nil {
		return "", err
	}
	started := s.clk.Now()
	err = s.inline(ctx, sessionID, fn)

	now := s.clk.Now()
	v := View{
		TransferID: newTransferID(), AccountID: c.AccountID, SessionID: sess.SessionID,
		EndpointID: sess.EndpointID, Tier: TierInline, Direction: op.direction, Path: op.path,
		Status: StateCompleted, TotalBytes: -1,
		ClientID: c.ClientID, ClientName: c.ClientName, ClientVersion: c.ClientVersion, SourceIP: c.SourceIP,
		CreatedAt: started, UpdatedAt: now, FinishedAt: now,
	}
	if err != nil {
		// op is not read on failure: after a timeout the abandoned goroutine
		// may still be unwinding.
		v.Status, v.Error = StateFailed, err.Error()
	} else {
		v.Bytes, v.SHA256 = op.bytes, op.sha256
	}
	s.emitView(v)
	if err == nil && op.touch {
		s.mgr.TouchActivity(sessionID)
	}
	return v.TransferID, err
}

// DirEntry is one shellwatch_list_dir row.
type DirEntry struct {
	Name      string `json:"name"`
	Type      string `json:"type"`
	Size      int64  `json:"size"`
	Mode      uint32 `json:"mode"`
	ModeOctal string `json:"modeOctal"`
	Mtime     string `json:"mtime"`
	// Target is the link target (symlinks only).
	Target string `json:"target,omitempty"`
}

// ListResult is the shellwatch_list_dir result.
type ListResult struct {
	TransferID string     `json:"transferId"`
	Entries    []DirEntry `json:"entries"`
	Truncated  bool       `json:"truncated"`
}

const (
	listDefaultEntries = 200
	listMaxEntries     = 1000
)

// ListDir lists a remote directory (sorted by name, capped at maxEntries).
func (s *Service) ListDir(ctx context.Context, c Caller, sessionID, dir string, maxEntries int) (*ListResult, error) {
	switch {
	case maxEntries <= 0:
		maxEntries = listDefaultEntries
	case maxEntries > listMaxEntries:
		maxEntries = listMaxEntries
	}
	res := &ListResult{Entries: []DirEntry{}}
	op := &inlineOp{direction: DirectionList, path: dir}
	id, err := s.runInline(ctx, c, sessionID, op, func(client *sftp.Client) error {
		infos, err := client.ReadDirContext(ctx, dir)
		if err != nil {
			return remoteErr("list", dir, err)
		}
		sort.Slice(infos, func(i, j int) bool { return infos[i].Name() < infos[j].Name() })
		if len(infos) > maxEntries {
			infos, res.Truncated = infos[:maxEntries], true
		}
		for _, fi := range infos {
			e := DirEntry{
				Name: fi.Name(), Type: fileType(fi.Mode()), Size: fi.Size(),
				Mode: uint32(fi.Mode().Perm()), ModeOctal: octal(fi.Mode()),
				Mtime: fi.ModTime().UTC().Format(clock.ISOMillis),
			}
			if fi.Mode()&os.ModeSymlink != 0 {
				if target, err := client.ReadLink(path.Join(dir, fi.Name())); err == nil {
					e.Target = target
				}
			}
			res.Entries = append(res.Entries, e)
		}
		// Listing an empty directory is not session activity.
		op.touch = len(res.Entries) > 0
		return nil
	})
	if err != nil {
		return nil, err
	}
	res.TransferID = id
	return res, nil
}

// ReadResult is the shellwatch_read_file result.
type ReadResult struct {
	TransferID string `json:"transferId"`
	Path       string `json:"path"`
	Size       int64  `json:"size"`
	Mode       uint32 `json:"mode"`
	ModeOctal  string `json:"modeOctal"`
	Mtime      string `json:"mtime"`
	SHA256     string `json:"sha256"`
	Content    string `json:"content"`
	Encoding   string `json:"encoding"`
}

// ReadFile reads a small remote file. The read is bounded, not the stat: it
// streams through a LimitReader of maxInlineBytes+1, so a file that grows
// past the cap after the advisory stat still fails without partial content.
func (s *Service) ReadFile(ctx context.Context, c Caller, sessionID, file, encoding string) (*ReadResult, error) {
	encoding, err := normalizeEncoding(encoding)
	if err != nil {
		return nil, err
	}
	limit := s.lim.MaxInlineBytes
	tooLarge := func(size string) error {
		return fmt.Errorf("%s is %s, above the inline limit of %d bytes; use shellwatch_transfer_file (direction \"download\") instead", file, size, limit)
	}
	res := &ReadResult{Path: file, Encoding: encoding}
	op := &inlineOp{direction: DirectionDownload, path: file, touch: true}
	id, err := s.runInline(ctx, c, sessionID, op, func(client *sftp.Client) error {
		// Advisory: a clear error for directories/special files and for files
		// that are obviously too large, before opening anything.
		fi, err := client.Stat(file)
		if err != nil {
			return remoteErr("stat", file, err)
		}
		if !fi.Mode().IsRegular() {
			return fmt.Errorf("%s is a %s, not a regular file", file, fileType(fi.Mode()))
		}
		if fi.Size() > limit {
			return tooLarge(fmt.Sprintf("%d bytes", fi.Size()))
		}
		f, err := client.Open(file)
		if err != nil {
			return remoteErr("open", file, err)
		}
		defer f.Close()
		data, err := io.ReadAll(io.LimitReader(f, limit+1))
		if err != nil {
			return remoteErr("read", file, err)
		}
		if int64(len(data)) > limit {
			return tooLarge(fmt.Sprintf("larger than %d bytes (it grew while being read)", limit))
		}
		if st, err := f.Stat(); err == nil {
			fi = st // metadata from the open handle, not the earlier path stat
		}
		if encoding == "utf8" {
			if !utf8.Valid(data) {
				return fmt.Errorf("%s is not valid UTF-8; read it with encoding \"base64\"", file)
			}
			res.Content = string(data)
		} else {
			res.Content = base64.StdEncoding.EncodeToString(data)
		}
		sum := sha256.Sum256(data)
		res.Size = int64(len(data))
		res.Mode, res.ModeOctal = uint32(fi.Mode().Perm()), octal(fi.Mode())
		res.Mtime = fi.ModTime().UTC().Format(clock.ISOMillis)
		res.SHA256 = hex.EncodeToString(sum[:])
		op.bytes, op.sha256 = res.Size, res.SHA256
		return nil
	})
	if err != nil {
		return nil, err
	}
	res.TransferID = id
	return res, nil
}

// WriteParams describe a shellwatch_write_file call.
type WriteParams struct {
	SessionID string
	Path      string
	Content   string
	Encoding  string
	Overwrite bool
	// Mode is the permission bits to set (optional).
	Mode *os.FileMode
}

// WriteResult is the shellwatch_write_file result.
type WriteResult struct {
	TransferID string `json:"transferId"`
	Path       string `json:"path"`
	Bytes      int64  `json:"bytes"`
	SHA256     string `json:"sha256"`
}

// WriteFile writes a small remote file.
//
// The content is decoded and size-checked BEFORE the destination is opened,
// so a malformed payload never touches an existing file. overwrite=false
// creates with O_EXCL and sets the mode on the still-empty file before any
// content byte is written; overwrite=true truncates in place, so inode,
// owner, mode and hard links survive, and a supplied mode is applied after
// the write (deliberately overriding preservation).
func (s *Service) WriteFile(ctx context.Context, c Caller, p WriteParams) (*WriteResult, error) {
	encoding, err := normalizeEncoding(p.Encoding)
	if err != nil {
		return nil, err
	}
	data := []byte(p.Content)
	if encoding == "base64" {
		if data, err = base64.StdEncoding.DecodeString(p.Content); err != nil {
			return nil, fmt.Errorf("content is not valid base64: %v", err)
		}
	}
	if int64(len(data)) > s.lim.MaxInlineBytes {
		return nil, fmt.Errorf("content is %d bytes, above the inline limit of %d bytes; use shellwatch_transfer_file (direction \"upload\") instead", len(data), s.lim.MaxInlineBytes)
	}
	sum := sha256.Sum256(data)
	res := &WriteResult{Path: p.Path, Bytes: int64(len(data)), SHA256: hex.EncodeToString(sum[:])}

	var opened atomic.Bool
	op := &inlineOp{direction: DirectionUpload, path: p.Path, touch: true}
	id, err := s.runInline(ctx, c, p.SessionID, op, func(client *sftp.Client) error {
		existing, err := checkWriteDestination(client, p.Path)
		if err != nil {
			return err
		}
		if existing != nil && !p.Overwrite {
			return fmt.Errorf("%s already exists; pass overwrite=true to replace it", p.Path)
		}
		flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
		if p.Overwrite {
			// In place: O_TRUNC keeps the inode (owner, mode, hard links).
			flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
		}
		f, err := client.OpenFile(p.Path, flags)
		if err != nil {
			return remoteErr("open", p.Path, err)
		}
		opened.Store(true)
		if existing == nil {
			// pkg/sftp sends no attrs on open, so this chmod on the
			// still-empty file is the earliest point the mode can be set.
			mode := os.FileMode(0o644)
			if p.Mode != nil {
				mode = *p.Mode
			}
			if err := f.Chmod(mode); err != nil {
				f.Close()
				return remoteErr("chmod", p.Path, err)
			}
		}
		if _, err := f.Write(data); err != nil {
			f.Close()
			return remoteErr("write", p.Path, err)
		}
		if existing != nil && p.Mode != nil {
			if err := f.Chmod(*p.Mode); err != nil {
				f.Close()
				return remoteErr("chmod", p.Path, err)
			}
		}
		if err := f.Close(); err != nil {
			return remoteErr("close", p.Path, err)
		}
		op.bytes, op.sha256 = res.Bytes, res.SHA256
		return nil
	})
	if err != nil {
		if errors.Is(err, errInlineTimeout) && opened.Load() {
			return nil, fmt.Errorf("%w; the destination was already opened and may hold partial content", err)
		}
		return nil, err
	}
	res.TransferID = id
	return res, nil
}

func normalizeEncoding(enc string) (string, error) {
	switch enc {
	case "", "utf8", "utf-8":
		return "utf8", nil
	case "base64":
		return "base64", nil
	}
	return "", errors.New(`encoding must be "utf8" or "base64"`)
}

func octal(m os.FileMode) string { return fmt.Sprintf("%04o", m.Perm()) }
