// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// store.Endpoints owns the endpoints table (port of endpoint-repo.ts).
// Account-scoped by construction: every query carries account_id (W13).
package store

import (
	"context"
	"database/sql"
	"errors"

	"github.com/rado0x54/shellwatch/internal/clock"
	"github.com/rado0x54/shellwatch/internal/store/gen"
)

// Endpoint is the wire/domain shape of an SSH endpoint.
type Endpoint struct {
	ID               string
	AccountID        string
	Label            string
	Host             string
	Port             int64
	Username         string
	UserVerification string
	Description      *string
	AgentForward     bool
}

// Endpoints owns endpoints-table access.
type Endpoints struct {
	db  *sql.DB
	clk clock.Clock
}

func NewEndpoints(db *sql.DB, clk clock.Clock) *Endpoints {
	if clk == nil {
		clk = clock.Real{}
	}
	return &Endpoints{db: db, clk: clk}
}

func fromRow(id, accountID, label, host string, port int64, username, uv string, desc sql.NullString, agentForward int64) Endpoint {
	var d *string
	if desc.Valid {
		d = &desc.String
	}
	return Endpoint{
		ID: id, AccountID: accountID, Label: label, Host: host, Port: port,
		Username: username, UserVerification: uv, Description: d, AgentForward: agentForward != 0,
	}
}

// ListForAccount returns the account's own endpoints (demo endpoints are
// merged in the handler).
func (e *Endpoints) ListForAccount(ctx context.Context, accountID string) ([]Endpoint, error) {
	rows, err := gen.New(e.db).ListEndpointsForAccount(ctx, accountID)
	if err != nil {
		return nil, err
	}
	out := make([]Endpoint, 0, len(rows))
	for _, r := range rows {
		out = append(out, fromRow(r.ID, r.AccountID, r.Label, r.Host, r.Port, r.Username, r.UserVerification, r.Description, r.AgentForward))
	}
	return out, nil
}

// GetForAccount returns one endpoint scoped to the account (nil when absent).
func (e *Endpoints) GetForAccount(ctx context.Context, id, accountID string) (*Endpoint, error) {
	r, err := gen.New(e.db).GetEndpointForAccount(ctx, gen.GetEndpointForAccountParams{ID: id, AccountID: accountID})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	ep := fromRow(r.ID, r.AccountID, r.Label, r.Host, r.Port, r.Username, r.UserVerification, r.Description, r.AgentForward)
	return &ep, nil
}

// Create inserts an endpoint (id + defaults resolved by the caller).
func (e *Endpoints) Create(ctx context.Context, ep Endpoint) error {
	now := e.clk.Now().UTC().Format(isoMillis)
	return gen.New(e.db).InsertEndpoint(ctx, gen.InsertEndpointParams{
		ID: ep.ID, AccountID: ep.AccountID, Label: ep.Label, Host: ep.Host, Port: ep.Port,
		Username: ep.Username, UserVerification: ep.UserVerification,
		Description: nullString(ep.Description), AgentForward: boolInt(ep.AgentForward),
		CreatedAt: now, UpdatedAt: now,
	})
}

// Update writes a full endpoint row (the handler read-merges the patch).
// Returns false when no row matched (unknown id / not owned).
func (e *Endpoints) Update(ctx context.Context, ep Endpoint) (bool, error) {
	n, err := gen.New(e.db).UpdateEndpoint(ctx, gen.UpdateEndpointParams{
		Label: ep.Label, Host: ep.Host, Port: ep.Port, Username: ep.Username,
		UserVerification: ep.UserVerification, Description: nullString(ep.Description),
		AgentForward: boolInt(ep.AgentForward), UpdatedAt: e.clk.Now().UTC().Format(isoMillis),
		ID: ep.ID, AccountID: ep.AccountID,
	})
	return n > 0, err
}

// Delete removes an endpoint; returns false when nothing matched.
func (e *Endpoints) Delete(ctx context.Context, id, accountID string) (bool, error) {
	n, err := gen.New(e.db).DeleteEndpointForAccount(ctx, gen.DeleteEndpointForAccountParams{ID: id, AccountID: accountID})
	return n > 0, err
}

// ShowDemoEndpoints reports the account's demo-visibility toggle.
func (e *Endpoints) ShowDemoEndpoints(ctx context.Context, accountID string) (bool, error) {
	v, err := gen.New(e.db).GetShowDemoEndpoints(ctx, accountID)
	return v != 0, err
}

func nullString(s *string) sql.NullString {
	if s == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: *s, Valid: true}
}

func boolInt(b bool) int64 {
	if b {
		return 1
	}
	return 0
}
