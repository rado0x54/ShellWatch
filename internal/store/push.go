// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Web Push subscription store (port of push-subscription-repo.ts): one row per
// endpoint; re-subscribe by the same account rotates keys but keeps id/owner;
// an endpoint owned by another account is a conflict.
package store

import (
	"context"
	"database/sql"
	"errors"

	"github.com/rado0x54/shellwatch/internal/clock"
	"github.com/rado0x54/shellwatch/internal/store/gen"
)

// PushSubs owns the push_subscriptions table.
type PushSubs struct {
	db  *sql.DB
	clk clock.Clock
}

func NewPushSubs(db *sql.DB, clk clock.Clock) *PushSubs {
	if clk == nil {
		clk = clock.Real{}
	}
	return &PushSubs{db: db, clk: clk}
}

// UpsertResult reports the subscription id and whether the endpoint conflicted.
type UpsertResult struct {
	ID       string
	Conflict bool
}

// Upsert registers (or rotates) a subscription. newID mints a fresh id when
// the endpoint is new. Returns Conflict when the endpoint belongs to a
// different account.
func (p *PushSubs) Upsert(ctx context.Context, accountID, endpoint, p256dh, auth, newID string) (UpsertResult, error) {
	q := gen.New(p.db)
	existing, err := q.FindPushByEndpoint(ctx, endpoint)
	now := p.clk.Now().UTC().Format(isoMillis)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if err := q.InsertPushSub(ctx, gen.InsertPushSubParams{
			ID: newID, AccountID: accountID, Endpoint: endpoint, P256dh: p256dh, Auth: auth,
			CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			return UpsertResult{}, err
		}
		return UpsertResult{ID: newID}, nil
	case err != nil:
		return UpsertResult{}, err
	}
	if existing.AccountID != accountID {
		return UpsertResult{Conflict: true}, nil
	}
	if err := q.RotatePushSub(ctx, gen.RotatePushSubParams{
		P256dh: p256dh, Auth: auth, UpdatedAt: now, Endpoint: endpoint, AccountID: accountID,
	}); err != nil {
		return UpsertResult{}, err
	}
	return UpsertResult{ID: existing.ID}, nil
}

// Delete removes an account's subscription by endpoint (idempotent).
func (p *PushSubs) Delete(ctx context.Context, accountID, endpoint string) error {
	return gen.New(p.db).DeletePushByEndpoint(ctx, gen.DeletePushByEndpointParams{
		AccountID: accountID, Endpoint: endpoint,
	})
}
