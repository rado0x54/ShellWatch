// Package credstore manages per-server API tokens for shellwatch-agent.
//
// Primary backend is the OS keyring (macOS Keychain, libsecret on Linux,
// DPAPI on Windows) via zalando/go-keyring. When the keyring is unavailable
// — typical on a headless Linux box without a D-Bus session, or when SSH'd
// into a Mac with no logged-in GUI user — the store transparently falls
// back to a 0600-mode JSON file at $XDG_CONFIG_HOME/shellwatch/credentials
// (or ~/.config/shellwatch/credentials).
//
// Tokens are keyed by canonical server URL so multiple ShellWatch instances
// (`https://app.shellwatch.ai`, `https://app-dev.shellwatch.ai`, etc.) can
// coexist in one user's store.
package credstore

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/zalando/go-keyring"
)

// ServiceName is the keyring service identifier. Stable across releases —
// changing it would orphan every existing user's token.
const ServiceName = "ai.shellwatch.agent"

// keyringTimeout caps every keyring call to bound startup latency and avoid
// hangs on stuck D-Bus sessions. Mirrors the pattern from `gh`'s wrapper.
const keyringTimeout = 3 * time.Second

// ErrNotFound is returned when no credential exists for the given server.
var ErrNotFound = errors.New("credstore: no credential for server")

// Store is the credential storage interface. Both backends (keyring + file)
// implement it; tests can substitute fakes.
type Store interface {
	Get(serverURL string) (string, error)
	Set(serverURL, token string) error
	Delete(serverURL string) error
}

// New returns a Store that uses the OS keyring when available and falls back
// to a file at the default config path otherwise. The choice is per-call:
// a healthy keyring + a stale file entry, for example, will read from the
// keyring. Set always writes to whichever backend is operational and removes
// the same entry from the other to avoid drift.
func New() (Store, error) {
	path, err := defaultFilePath()
	if err != nil {
		return nil, err
	}
	return &dualStore{file: &fileStore{path: path}, keyring: &keyringStore{}}, nil
}

// CanonicalizeServerURL trims trailing slashes and lowercases the scheme +
// host. Stored credential keys go through this so `https://X/` and
// `https://X` resolve the same token.
func CanonicalizeServerURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid server URL: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("server URL must include scheme and host")
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	u.Path = strings.TrimRight(u.Path, "/")
	u.Fragment = ""
	u.RawQuery = ""
	return u.String(), nil
}

// dualStore tries the keyring first, then the file. Errors from one backend
// don't mask the other — Get is a "found-anywhere" lookup, Set picks the
// keyring when it's reachable, Delete is best-effort on both sides.
type dualStore struct {
	keyring *keyringStore
	file    *fileStore
}

func (d *dualStore) Get(serverURL string) (string, error) {
	key, err := CanonicalizeServerURL(serverURL)
	if err != nil {
		return "", err
	}
	if token, err := d.keyring.Get(key); err == nil {
		return token, nil
	} else if !isMissing(err) && !isUnavailable(err) {
		// Real keyring failure (permission denied, stuck D-Bus). Surface so
		// the user can investigate rather than silently falling through.
		return "", err
	}
	return d.file.Get(key)
}

func (d *dualStore) Set(serverURL, token string) error {
	key, err := CanonicalizeServerURL(serverURL)
	if err != nil {
		return err
	}
	if err := d.keyring.Set(key, token); err == nil {
		// Wrote to keyring. Remove any stale file entry so a future Get
		// can't return a different token from the file backend.
		_ = d.file.Delete(key)
		return nil
	} else if !isUnavailable(err) {
		return err
	}
	// Keyring unavailable — fall back to file.
	return d.file.Set(key, token)
}

func (d *dualStore) Delete(serverURL string) error {
	key, err := CanonicalizeServerURL(serverURL)
	if err != nil {
		return err
	}
	// Best-effort across both backends — we want logout to leave nothing behind.
	keyringErr := d.keyring.Delete(key)
	fileErr := d.file.Delete(key)
	// Surface real failures (permission denied, stuck D-Bus, malformed file).
	if keyringErr != nil && !isMissing(keyringErr) && !isUnavailable(keyringErr) {
		return keyringErr
	}
	if fileErr != nil && !errors.Is(fileErr, ErrNotFound) {
		return fileErr
	}
	// Nothing to delete: either both backends explicitly reported "not
	// found", or the keyring was unavailable AND the file had no entry.
	// Without this second case, an unavailable keyring would silently make
	// logout return "OK" when in fact nothing was removed.
	keyringNothing := isMissing(keyringErr) || isUnavailable(keyringErr)
	fileNothing := errors.Is(fileErr, ErrNotFound)
	if keyringNothing && fileNothing {
		return ErrNotFound
	}
	return nil
}

// keyringStore is a thin wrapper around zalando/go-keyring with timeouts.
type keyringStore struct{}

func (k *keyringStore) Get(key string) (string, error) {
	return withResult(func() (string, error) { return keyring.Get(ServiceName, key) })
}

func (k *keyringStore) Set(key, token string) error {
	return withErr(func() error { return keyring.Set(ServiceName, key, token) })
}

func (k *keyringStore) Delete(key string) error {
	return withErr(func() error { return keyring.Delete(ServiceName, key) })
}

// withErr / withResult cap a keyring call at `keyringTimeout` and surface a
// timeout as a synthetic "unavailable" error so dualStore can fall back.
func withErr(fn func() error) error {
	ch := make(chan error, 1)
	go func() { ch <- fn() }()
	select {
	case err := <-ch:
		return err
	case <-time.After(keyringTimeout):
		return errKeyringUnavailable{msg: "keyring operation timed out"}
	}
}

func withResult(fn func() (string, error)) (string, error) {
	type result struct {
		v   string
		err error
	}
	ch := make(chan result, 1)
	go func() {
		v, err := fn()
		ch <- result{v, err}
	}()
	select {
	case r := <-ch:
		return r.v, r.err
	case <-time.After(keyringTimeout):
		return "", errKeyringUnavailable{msg: "keyring operation timed out"}
	}
}

// errKeyringUnavailable signals the keyring isn't reachable on this system.
// Distinct from ErrNotFound (entry missing but keyring is healthy).
type errKeyringUnavailable struct{ msg string }

func (e errKeyringUnavailable) Error() string { return e.msg }

func isMissing(err error) bool {
	return errors.Is(err, keyring.ErrNotFound)
}

func isUnavailable(err error) bool {
	if err == nil {
		return false
	}
	var unav errKeyringUnavailable
	if errors.As(err, &unav) {
		return true
	}
	// go-keyring reports "secret service is not available" on Linux without
	// a session bus and similar shapes on Windows when the credential
	// manager is locked. The library doesn't export sentinels for these
	// shapes, so we match by string. NOTE: if go-keyring is bumped beyond
	// v0.2.8, sanity-check these strings against the upstream source —
	// silently regressing "unavailable" detection will turn the dual-store
	// fallback into a hard failure on headless runners.
	msg := err.Error()
	return strings.Contains(msg, "secret service is not available") ||
		strings.Contains(msg, "no such interface")
}

// fileStore is the fallback persistence layer. The on-disk format is a flat
// JSON object mapping canonical server URL → token, written with mode 0600.
type fileStore struct {
	path string
}

type credentialFile struct {
	Tokens map[string]string `json:"tokens"`
}

func (f *fileStore) Get(key string) (string, error) {
	cf, err := f.read()
	if err != nil {
		return "", err
	}
	token, ok := cf.Tokens[key]
	if !ok {
		return "", ErrNotFound
	}
	return token, nil
}

func (f *fileStore) Set(key, token string) error {
	cf, err := f.read()
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	if cf.Tokens == nil {
		cf.Tokens = make(map[string]string)
	}
	cf.Tokens[key] = token
	return f.write(cf)
}

func (f *fileStore) Delete(key string) error {
	cf, err := f.read()
	if err != nil {
		return err
	}
	if _, ok := cf.Tokens[key]; !ok {
		return ErrNotFound
	}
	delete(cf.Tokens, key)
	return f.write(cf)
}

func (f *fileStore) read() (credentialFile, error) {
	data, err := os.ReadFile(f.path)
	if errors.Is(err, os.ErrNotExist) {
		return credentialFile{Tokens: map[string]string{}}, ErrNotFound
	}
	if err != nil {
		return credentialFile{}, fmt.Errorf("read credentials file: %w", err)
	}
	var cf credentialFile
	if err := json.Unmarshal(data, &cf); err != nil {
		return credentialFile{}, fmt.Errorf("parse credentials file: %w", err)
	}
	if cf.Tokens == nil {
		cf.Tokens = map[string]string{}
	}
	return cf, nil
}

func (f *fileStore) write(cf credentialFile) error {
	if err := os.MkdirAll(filepath.Dir(f.path), 0o700); err != nil {
		return fmt.Errorf("create credentials dir: %w", err)
	}
	data, err := json.MarshalIndent(cf, "", "  ")
	if err != nil {
		return fmt.Errorf("encode credentials: %w", err)
	}
	// Write to a temp sibling and rename — avoids leaving a half-written
	// file with secrets in it if the process is killed mid-write.
	tmp := f.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write credentials file: %w", err)
	}
	if err := os.Rename(tmp, f.path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("commit credentials file: %w", err)
	}
	// Re-apply 0600 in case umask masked off bits during MkdirAll.
	_ = os.Chmod(f.path, 0o600)
	return nil
}

// defaultFilePath resolves the per-user config dir + "shellwatch/credentials".
// Delegates to os.UserConfigDir for platform-correct paths:
//   - Linux:   $XDG_CONFIG_HOME (or ~/.config)
//   - macOS:   ~/Library/Application Support
//   - Windows: %AppData% (which inherits user-only ACLs from the Windows
//     profile, so the 0600-mode write actually has the protection callers
//     would expect — Go's os.Chmod on Windows only flips read-only and
//     doesn't set ACLs, so path choice is what's load-bearing).
func defaultFilePath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolve user config dir: %w", err)
	}
	return filepath.Join(dir, "shellwatch", "credentials"), nil
}

// NewFileStore constructs a file-only store at an explicit path. Used by
// tests; production code should prefer New().
func NewFileStore(path string) Store {
	return &fileStore{path: path}
}
