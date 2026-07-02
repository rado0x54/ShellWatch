// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
package store

import (
	"context"
	"database/sql"
)

// WithTx runs fn in a transaction, committing on success and rolling back on
// error or panic (docs/go-backend-architecture.md §5.6, fixes W9).
func WithTx(ctx context.Context, db *sql.DB, fn func(*sql.Tx) error) (err error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback()
			panic(p)
		}
		if err != nil {
			_ = tx.Rollback()
			return
		}
		err = tx.Commit()
	}()
	return fn(tx)
}
