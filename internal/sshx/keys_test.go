// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
package sshx

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/rado0x54/shellwatch/internal/store"
)

func writeTestKey(t *testing.T, dir, name string) string {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	signer, _ := ssh.NewSignerFromKey(priv)
	return ssh.FingerprintSHA256(signer.PublicKey())
}

func TestKeyDirScanUpsertAvailability(t *testing.T) {
	dir := t.TempDir()
	fp := writeTestKey(t, dir, "deploy.pem")
	// A non-.pem file is ignored.
	os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("ignore me"), 0o600)

	db, err := store.Open("sqlite::memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := store.Migrate(db); err != nil {
		t.Fatal(err)
	}
	keys := store.NewSSHKeys(db)
	kd := NewKeyDir(dir)

	kd.sync(context.Background(), keys, func() string { return "2026-01-01T00:00:00.000Z" })

	// Available + offered as a signer.
	if !kd.IsAvailable(fp) {
		t.Errorf("scanned key should be available: %s", fp)
	}
	signers, _ := kd.Signers()
	if len(signers) != 1 {
		t.Fatalf("expected 1 signer, got %d", len(signers))
	}

	// Upserted into ssh_keys with id from the filename, type "file".
	all, err := keys.ListFull(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 || all[0].ID != "deploy" || all[0].Type != "file" || all[0].Fingerprint != fp {
		t.Fatalf("upsert wrong: %+v", all)
	}

	// Idempotent: a second sync doesn't duplicate.
	kd.sync(context.Background(), keys, func() string { return "2026-01-02T00:00:00.000Z" })
	all, _ = keys.ListFull(context.Background())
	if len(all) != 1 {
		t.Fatalf("re-sync duplicated: %d rows", len(all))
	}

	// Removed key -> unavailable (but stays in the DB).
	os.Remove(filepath.Join(dir, "deploy.pem"))
	kd.Reload()
	if kd.IsAvailable(fp) {
		t.Error("removed key should be unavailable")
	}
	all, _ = keys.ListFull(context.Background())
	if len(all) != 1 {
		t.Error("removed key should remain in the DB")
	}
}
