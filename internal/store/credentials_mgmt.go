// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Credential management reads/writes for /api/webauthn/credentials (list,
// label, revoke) + export-seed (port of credentials.ts + accounts.ts export).
package store

import (
	"context"
	"encoding/hex"
	"encoding/json"

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
