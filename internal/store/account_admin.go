// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Account reads/writes for the self-service (/api/auth/me) + admin
// (/api/accounts) REST surfaces (port of account-repo.ts + accounts.ts).
package store

import (
	"context"
	"database/sql"
	"errors"

	"github.com/rado0x54/shellwatch/internal/store/gen"
)

// Account is the full account row.
type Account struct {
	ID                string
	Name              string
	IsAdmin           bool
	Enabled           bool
	MaxSessions       int64
	LastUsedAt        *string
	CreatedAt         string
	ShowDemoEndpoints bool
}

// adminID returns the admin account id ("" when none).
func (a *Accounts) adminID(ctx context.Context) string {
	id, err := gen.New(a.db).GetAdminAccountID(ctx)
	if err != nil {
		return ""
	}
	return id
}

// IsAdmin reports whether accountID is the admin account.
func (a *Accounts) IsAdmin(ctx context.Context, accountID string) bool {
	return accountID != "" && a.adminID(ctx) == accountID
}

// Get returns one account with its admin flag (nil when absent).
func (a *Accounts) Get(ctx context.Context, accountID string) (*Account, error) {
	row, err := gen.New(a.db).GetAccount(ctx, accountID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	adminID := a.adminID(ctx)
	return &Account{
		ID: row.ID, Name: row.Name, IsAdmin: row.ID == adminID, Enabled: row.Enabled != 0,
		MaxSessions: row.MaxSessions, LastUsedAt: nsp(row.LastUsedAt), CreatedAt: row.CreatedAt,
		ShowDemoEndpoints: row.ShowDemoEndpoints != 0,
	}, nil
}

// List returns all accounts (admin view).
func (a *Accounts) List(ctx context.Context) ([]Account, error) {
	rows, err := gen.New(a.db).ListAllAccounts(ctx)
	if err != nil {
		return nil, err
	}
	adminID := a.adminID(ctx)
	out := make([]Account, 0, len(rows))
	for _, r := range rows {
		out = append(out, Account{
			ID: r.ID, Name: r.Name, IsAdmin: r.ID == adminID, Enabled: r.Enabled != 0,
			MaxSessions: r.MaxSessions, LastUsedAt: nsp(r.LastUsedAt), CreatedAt: r.CreatedAt,
		})
	}
	return out, nil
}

// UpdateSelf applies the /api/auth/me PUT (name and/or showDemoEndpoints).
func (a *Accounts) UpdateSelf(ctx context.Context, accountID string, name *string, showDemo *bool, now string) error {
	q := gen.New(a.db)
	if name != nil {
		if err := q.UpdateAccountName(ctx, gen.UpdateAccountNameParams{Name: *name, UpdatedAt: now, ID: accountID}); err != nil {
			return err
		}
	}
	if showDemo != nil {
		if err := q.UpdateAccountShowDemo(ctx, gen.UpdateAccountShowDemoParams{
			ShowDemoEndpoints: boolInt(*showDemo), UpdatedAt: now, ID: accountID,
		}); err != nil {
			return err
		}
	}
	return nil
}

// Delete hard-deletes an account and its owned data (admin action). Reuses the
// transactional cascade so a mid-delete crash can't half-remove it (W9).
func (a *Accounts) Delete(ctx context.Context, accountID string) error {
	return WithTx(ctx, a.db, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM webauthn_credentials WHERE account_id = ?`, accountID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM endpoints WHERE account_id = ?`, accountID); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `DELETE FROM accounts WHERE id = ?`, accountID)
		return err
	})
}

// SeedExport is the /api/accounts/export-seed payload.
type SeedExport struct {
	Passkeys  []SeedPasskey  `json:"passkeys"`
	Endpoints []SeedEndpoint `json:"endpoints"`
}

// SeedPasskey mirrors the config seedAdminPasskeys shape.
type SeedPasskey struct {
	CredentialID string   `json:"credentialId"`
	PublicKeyHex string   `json:"publicKeyHex"`
	Counter      int64    `json:"counter"`
	Transports   []string `json:"transports"`
	Label        string   `json:"label"`
}

// SeedEndpoint mirrors the config seedAdminEndpoints shape.
type SeedEndpoint struct {
	Label        string `json:"label"`
	Address      string `json:"address"`
	AgentForward bool   `json:"agentForward"`
}
