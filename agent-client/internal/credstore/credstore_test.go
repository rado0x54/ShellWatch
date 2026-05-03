// SPDX-License-Identifier: MIT
package credstore

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// File-backed paths are deterministic and OS-agnostic, so the meaningful
// tests target NewFileStore directly. Keyring-backed behavior is best
// covered by manual smoke testing on each platform — go-keyring's tests
// already verify the wire path to security/libsecret/DPAPI.

func TestFileStore_RoundTrip(t *testing.T) {
	store := NewFileStore(filepath.Join(t.TempDir(), "credentials"))

	if _, err := store.Get("https://example.com"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get on empty store: want ErrNotFound, got %v", err)
	}

	if err := store.Set("https://example.com", "sw_abc"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := store.Get("https://example.com")
	if err != nil {
		t.Fatalf("Get after Set: %v", err)
	}
	if got != "sw_abc" {
		t.Fatalf("Get: got %q, want sw_abc", got)
	}

	if err := store.Delete("https://example.com"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := store.Get("https://example.com"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get after Delete: want ErrNotFound, got %v", err)
	}
}

func TestFileStore_MultipleServers(t *testing.T) {
	store := NewFileStore(filepath.Join(t.TempDir(), "credentials"))

	if err := store.Set("https://prod.example.com", "sw_prod"); err != nil {
		t.Fatalf("Set prod: %v", err)
	}
	if err := store.Set("https://dev.example.com", "sw_dev"); err != nil {
		t.Fatalf("Set dev: %v", err)
	}

	prod, _ := store.Get("https://prod.example.com")
	dev, _ := store.Get("https://dev.example.com")
	if prod != "sw_prod" || dev != "sw_dev" {
		t.Fatalf("multi-server isolation broken: prod=%q dev=%q", prod, dev)
	}

	// Deleting one server's entry must not affect the other.
	if err := store.Delete("https://prod.example.com"); err != nil {
		t.Fatalf("Delete prod: %v", err)
	}
	if _, err := store.Get("https://prod.example.com"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get prod after delete: want ErrNotFound, got %v", err)
	}
	if got, err := store.Get("https://dev.example.com"); err != nil || got != "sw_dev" {
		t.Fatalf("dev still present? got %q err %v", got, err)
	}
}

func TestFileStore_Mode0600(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials")
	store := NewFileStore(path)
	if err := store.Set("https://example.com", "sw_secret"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Fatalf("file mode: got %o, want 0600", mode)
	}
}

func TestFileStore_AtomicReplace(t *testing.T) {
	// Set twice, ensure the second value is what's read back. The atomic
	// rename makes this trivial; the test mostly guards against a future
	// regression where someone changes write() to truncate-then-write.
	store := NewFileStore(filepath.Join(t.TempDir(), "credentials"))
	_ = store.Set("https://example.com", "sw_first")
	if err := store.Set("https://example.com", "sw_second"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, _ := store.Get("https://example.com")
	if got != "sw_second" {
		t.Fatalf("Get after re-Set: got %q, want sw_second", got)
	}
}

// Regression: dualStore.Delete used to return nil when the keyring was
// "unavailable" (typical on a headless CI runner without D-Bus) and the
// file had no entry, even though nothing was actually removed — making
// `shellwatch-agent logout` print "OK: removed token" on a fresh box.
// We exercise that path indirectly via the file backend (the only
// portable backend in tests): a Delete on an empty store must report
// ErrNotFound, not nil.
func TestFileStore_DeleteOnEmptyReturnsNotFound(t *testing.T) {
	store := NewFileStore(filepath.Join(t.TempDir(), "credentials"))
	err := store.Delete("https://example.com")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Delete on empty store: want ErrNotFound, got %v", err)
	}
}

func TestFileStore_CorruptFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials")
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	store := NewFileStore(path)
	if _, err := store.Get("https://example.com"); err == nil {
		t.Fatalf("Get on corrupt file: want error, got nil")
	}
}

func TestCanonicalizeServerURL(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"https://app.shellwatch.ai", "https://app.shellwatch.ai"},
		{"https://app.shellwatch.ai/", "https://app.shellwatch.ai"},
		{"HTTPS://APP.SHELLWATCH.AI", "https://app.shellwatch.ai"},
		{"https://app.shellwatch.ai/?foo=bar#baz", "https://app.shellwatch.ai"},
		{"http://localhost:3000", "http://localhost:3000"},
	}
	for _, tc := range cases {
		got, err := CanonicalizeServerURL(tc.in)
		if err != nil {
			t.Errorf("CanonicalizeServerURL(%q) error: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("CanonicalizeServerURL(%q): got %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestCanonicalizeServerURL_Rejects(t *testing.T) {
	bad := []string{
		"",
		"not-a-url",
		"://missing-scheme",
		"https://",
	}
	for _, in := range bad {
		if _, err := CanonicalizeServerURL(in); err == nil {
			t.Errorf("CanonicalizeServerURL(%q): want error, got nil", in)
		}
	}
}
