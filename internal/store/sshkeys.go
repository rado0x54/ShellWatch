// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// store.SSHKeys reads the auto-discovered file-key metadata table (ssh_keys).
// The key-directory watcher that populates it is Phase 5 periphery; the MCP
// manage_keys tool + the transport factory read it here.
package store

import (
	"context"
	"database/sql"
	"errors"

	"github.com/rado0x54/shellwatch/internal/store/gen"
)

// SSHKey is the wire shape for the manage_keys list.
type SSHKey struct {
	ID          string
	Label       string
	Type        string
	Fingerprint string
}

// SSHKeys owns ssh_keys reads.
type SSHKeys struct {
	db *sql.DB
}

func NewSSHKeys(db *sql.DB) *SSHKeys {
	return &SSHKeys{db: db}
}

// List returns all enabled file keys.
func (k *SSHKeys) List(ctx context.Context) ([]SSHKey, error) {
	rows, err := gen.New(k.db).ListSSHKeys(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]SSHKey, 0, len(rows))
	for _, r := range rows {
		out = append(out, SSHKey{ID: r.ID, Label: r.Label, Type: r.Type, Fingerprint: r.Fingerprint})
	}
	return out, nil
}

// SSHKeyDetail adds the public key (manage_keys read).
type SSHKeyDetail struct {
	SSHKey
	PublicKey string
}

// Get returns a single key by id (nil when absent).
func (k *SSHKeys) Get(ctx context.Context, id string) (*SSHKeyDetail, error) {
	r, err := gen.New(k.db).GetSSHKey(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &SSHKeyDetail{
		SSHKey:    SSHKey{ID: r.ID, Label: r.Label, Type: r.Type, Fingerprint: r.Fingerprint},
		PublicKey: r.PublicKey,
	}, nil
}
