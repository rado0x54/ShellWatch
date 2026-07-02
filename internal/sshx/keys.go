// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// File-key discovery (slimmed port of src/transport/key-scanner.go +
// key-directory-watcher): load PEM private keys from the key directory into
// ssh.Signers. The fsnotify watcher + ssh_keys DB upsert are Phase 5
// periphery; slice 3 needs signers to authenticate.
package sshx

import (
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
)

// KeyDir loads and caches file-key signers from a directory.
type KeyDir struct {
	dir string

	mu      sync.Mutex
	signers []ssh.Signer
	loaded  bool
}

func NewKeyDir(dir string) *KeyDir {
	return &KeyDir{dir: dir}
}

// Signers returns the file-key signers, scanning the directory on first use.
func (k *KeyDir) Signers() ([]ssh.Signer, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.loaded {
		return k.signers, nil
	}
	signers, err := loadSigners(k.dir)
	if err != nil {
		return nil, err
	}
	k.signers = signers
	k.loaded = true
	return signers, nil
}

// Reload forces a re-scan (used when the key directory changes).
func (k *KeyDir) Reload() error {
	signers, err := loadSigners(k.dir)
	if err != nil {
		return err
	}
	k.mu.Lock()
	k.signers, k.loaded = signers, true
	k.mu.Unlock()
	return nil
}

func loadSigners(dir string) ([]ssh.Signer, error) {
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var signers []ssh.Signer
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".pem") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		signer, err := ssh.ParsePrivateKey(raw)
		if err != nil {
			continue // skip unparseable / passphrase-protected keys
		}
		signers = append(signers, signer)
	}
	return signers, nil
}
