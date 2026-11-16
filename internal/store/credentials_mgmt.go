// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Credential management reads/writes for /api/webauthn/credentials (list,
// label, revoke) + export-seed (port of credentials.ts + accounts.ts export).
package store

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/rado0x54/shellwatch/internal/store/gen"
)

// CredentialRow is the full listing shape.
type CredentialRow struct {
	ID               string
	CredentialID     string
	PublicKeyCOSE    []byte
	PublicKeyOpenSSH *string
	Label            string
	Revoked          bool
	State            string
	CreatedAt        string
	LastUsedAt       *string
	// Priority is the passkey's position in the account's signing order
	// (lower = tried first); nil for pending and revoked credentials.
	Priority *int64
}

// ListForAccountFull returns all of an account's credentials (list endpoint).
func (c *Credentials) ListForAccountFull(ctx context.Context, accountID string) ([]CredentialRow, error) {
	rows, err := gen.New(c.db).ListCredentialsForAccountFull(ctx, accountID)
	if err != nil {
		return nil, err
	}
	out := make([]CredentialRow, 0, len(rows))
	for _, r := range rows {
		out = append(out, CredentialRow{
			ID: r.ID, CredentialID: r.CredentialID, PublicKeyCOSE: r.PublicKey,
			PublicKeyOpenSSH: nsp(r.PublicKeyOpenssh), Label: r.Label, Revoked: r.Revoked != 0,
			State: r.State, CreatedAt: r.CreatedAt, LastUsedAt: nsp(r.LastUsedAt),
			Priority: nip(r.Priority),
		})
	}
	return out, nil
}

// LabelConflict reports whether another credential in the account already uses
// the label.
func (c *Credentials) LabelConflict(ctx context.Context, accountID, label, exceptID string) (bool, error) {
	n, err := gen.New(c.db).LabelConflictExists(ctx, gen.LabelConflictExistsParams{
		AccountID: accountID, Label: label, ID: exceptID,
	})
	return n, err
}

// SetLabel renames a credential (account-scoped).
func (c *Credentials) SetLabel(ctx context.Context, id, accountID, label string) error {
	return gen.New(c.db).UpdateCredentialLabel(ctx, gen.UpdateCredentialLabelParams{
		Label: label, ID: id, AccountID: accountID,
	})
}

// Revoke marks a credential revoked.
func (c *Credentials) Revoke(ctx context.Context, id string) error {
	return gen.New(c.db).RevokeCredentialByID(ctx, id)
}

// ActiveCount returns the account's active (non-revoked, confirmed) credential
// count (the last-passkey guard).
func (c *Credentials) ActiveCount(ctx context.Context, accountID string) (int64, error) {
	return gen.New(c.db).CountActiveCredentials(ctx, accountID)
}

// ExportSeed returns the account's active passkeys as seed-config entries.
func (c *Credentials) ExportSeed(ctx context.Context, accountID string) ([]SeedPasskey, error) {
	rows, err := gen.New(c.db).ExportActiveCredentials(ctx, accountID)
	if err != nil {
		return nil, err
	}
	out := make([]SeedPasskey, 0, len(rows))
	for _, r := range rows {
		var transports []string
		if r.Transports.Valid {
			_ = json.Unmarshal([]byte(r.Transports.String), &transports)
		}
		if transports == nil {
			transports = []string{}
		}
		out = append(out, SeedPasskey{
			CredentialID: r.CredentialID, PublicKeyHex: hex.EncodeToString(r.PublicKey),
			Counter: r.Counter, Transports: transports, Label: r.Label,
		})
	}
	return out, nil
}

func nip(n sql.NullInt64) *int64 {
	if !n.Valid {
		return nil
	}
	v := n.Int64
	return &v
}

// ErrInvalidOrder is returned by Reorder when the id list is not exactly the
// account's active, non-revoked credentials (missing, extra, duplicate or
// foreign ids). Nothing is changed.
type ErrInvalidOrder struct{ Reason string }

func (e *ErrInvalidOrder) Error() string { return "invalid credential order: " + e.Reason }

// IsInvalidOrder reports whether err is an *ErrInvalidOrder.
func IsInvalidOrder(err error) bool {
	var e *ErrInvalidOrder
	return errors.As(err, &e)
}

// Reorder rewrites the account's passkey priorities to 0..n-1 in the order
// of ids (credential row ids). ids must be exactly the account's active,
// non-revoked credentials; validation and the rewrite run in one transaction
// so a concurrent activation or revocation can't slip in between (#308).
func (c *Credentials) Reorder(ctx context.Context, accountID string, ids []string) error {
	return WithTx(ctx, c.db, func(tx *sql.Tx) error {
		q := gen.New(tx)
		active, err := q.ListActiveCredentialRowIDs(ctx, accountID)
		if err != nil {
			return err
		}
		want := make(map[string]bool, len(active))
		for _, id := range active {
			want[id] = true
		}
		seen := make(map[string]bool, len(ids))
		for _, id := range ids {
			if seen[id] {
				return &ErrInvalidOrder{Reason: "duplicate id"}
			}
			seen[id] = true
			if !want[id] {
				return &ErrInvalidOrder{Reason: "unknown or inactive id"}
			}
		}
		if len(ids) != len(active) {
			return &ErrInvalidOrder{Reason: "missing ids"}
		}
		for i, id := range ids {
			if err := q.SetCredentialPriority(ctx, gen.SetCredentialPriorityParams{
				Priority: sql.NullInt64{Int64: int64(i), Valid: true}, ID: id, AccountID: accountID,
			}); err != nil {
				return err
			}
		}
		return nil
	})
}
