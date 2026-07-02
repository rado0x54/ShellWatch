// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// store.Accounts exposes account reads the request path needs (max-sessions
// gate); the full account-repo port lands with the admin/account routes.
package store

import (
	"context"
	"database/sql"

	"github.com/rado0x54/shellwatch/internal/store/gen"
)

// Accounts owns account reads.
type Accounts struct {
	db *sql.DB
}

func NewAccounts(db *sql.DB) *Accounts {
	return &Accounts{db: db}
}

// MaxSessions returns the account's concurrent-session cap (ok=false when the
// account is absent).
func (a *Accounts) MaxSessions(ctx context.Context, accountID string) (int, bool) {
	acc, err := gen.New(a.db).GetAccount(ctx, accountID)
	if err != nil {
		return 0, false
	}
	return int(acc.MaxSessions), true
}
