// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// File-key discovery + watching (port of src/transport/key-scanner.ts +
// key-directory-watcher.ts): scan a directory of .pem private keys into
// ssh.Signers, upsert discovered keys into ssh_keys (so /api/keys lists them),
// track which keys are currently on disk (availability), and re-sync on
// filesystem changes via fsnotify. Keys that vanish become unavailable but
// stay in the DB.
package sshx

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"golang.org/x/crypto/ssh"

	"github.com/rado0x54/shellwatch/internal/store"
)

// scannedKey is one discovered file key.
type scannedKey struct {
	filename    string
	signer      ssh.Signer
	publicKey   string // "algo base64" authorized_keys form
	fingerprint string // SHA256:...
}

// KeyDir loads file-key signers from a directory, keeps ssh_keys in sync, and
// tracks availability. Zero value (no directory) is a no-op.
type KeyDir struct {
	dir string

	mu        sync.Mutex
	available map[string]scannedKey // fingerprint -> key
	loaded    bool
}

func NewKeyDir(dir string) *KeyDir {
	return &KeyDir{dir: dir, available: map[string]scannedKey{}}
}

// Signers returns the currently-available file-key signers (scanning on first
// use if Watch hasn't run).
func (k *KeyDir) Signers() ([]ssh.Signer, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if !k.loaded {
		k.scanLocked()
	}
	out := make([]ssh.Signer, 0, len(k.available))
	for _, sk := range k.available {
		out = append(out, sk.signer)
	}
	return out, nil
}

// IsAvailable reports whether a file key with this fingerprint is on disk now.
func (k *KeyDir) IsAvailable(fingerprint string) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	_, ok := k.available[fingerprint]
	return ok
}

// Reload forces a re-scan of availability (no DB upsert).
func (k *KeyDir) Reload() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.scanLocked()
	return nil
}

// Watch performs the initial scan + ssh_keys upsert, then watches the directory
// for changes (debounced), re-syncing on each. Blocks until ctx is cancelled;
// run it in a goroutine. A nil/absent directory is a no-op.
func (k *KeyDir) Watch(ctx context.Context, keys *store.SSHKeys, now func() string) {
	if k.dir == "" {
		return
	}
	k.sync(ctx, keys, now)

	w, err := fsnotify.NewWatcher()
	if err != nil {
		slog.Warn("key-directory watcher: init failed (keys still scanned once)", "err", err)
		return
	}
	defer w.Close()
	if err := w.Add(k.dir); err != nil {
		slog.Warn("key-directory watcher: add dir failed", "dir", k.dir, "err", err)
		return
	}
	slog.Info("watching key directory", "dir", k.dir)

	// Debounce: editors emit several events per save.
	var timer *time.Timer
	debounce := func() {
		if timer != nil {
			timer.Stop()
		}
		timer = time.AfterFunc(500*time.Millisecond, func() { k.sync(ctx, keys, now) })
	}
	for {
		select {
		case <-ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return
		case _, ok := <-w.Events:
			if !ok {
				return
			}
			debounce()
		case err, ok := <-w.Errors:
			if !ok {
				return
			}
			slog.Warn("key-directory watcher error", "err", err)
		}
	}
}

// sync rescans the directory, updates availability, and upserts new keys.
func (k *KeyDir) sync(ctx context.Context, keys *store.SSHKeys, now func() string) {
	k.mu.Lock()
	k.scanLocked()
	snapshot := make([]scannedKey, 0, len(k.available))
	for _, sk := range k.available {
		snapshot = append(snapshot, sk)
	}
	k.mu.Unlock()

	if keys == nil {
		return
	}
	for _, sk := range snapshot {
		id := strings.TrimSuffix(sk.filename, ".pem")
		if err := keys.UpsertFileKey(ctx, id, sk.filename, sk.publicKey, sk.fingerprint, now()); err != nil {
			slog.Warn("key-directory watcher: upsert failed", "file", sk.filename, "err", err)
		}
	}
}

// scanLocked reads .pem keys from the directory into the availability map. Must
// hold k.mu.
func (k *KeyDir) scanLocked() {
	k.loaded = true
	next := map[string]scannedKey{}
	entries, err := os.ReadDir(k.dir)
	if err != nil {
		k.available = next // directory gone/unreadable -> nothing available
		return
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".pem") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(k.dir, e.Name()))
		if err != nil {
			continue
		}
		signer, err := ssh.ParsePrivateKey(raw)
		if err != nil {
			continue // unparseable / passphrase-protected
		}
		pub := signer.PublicKey()
		fp := ssh.FingerprintSHA256(pub)
		next[fp] = scannedKey{
			filename:    e.Name(),
			signer:      signer,
			publicKey:   strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))),
			fingerprint: fp,
		}
	}
	k.available = next
}
