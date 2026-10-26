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

// HostKeyPin is the display projection of a pinned SSH host key (#241).
type HostKeyPin struct {
	Type        string // SSH key type; "" for fingerprint-only pins
	Fingerprint string // SHA256:... fingerprint
	PinnedAt    string
	PinnedBy    string // credential id, or "manual" / "config" / "demo"
}

// HostKeyRecord is the raw pin a connection verifies against (#241).
type HostKeyRecord struct {
	Type        string
	Key         []byte // raw SSH wire public key; nil for fingerprint-only pins
	Fingerprint string // SHA256:... fingerprint
}

// ErrHostKeyPinned is returned by PinHostKey when a different key is already
// pinned (the compare-and-set lost against a conflicting pin).
var ErrHostKeyPinned = errors.New("a different host key is already pinned for this endpoint")

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
	HostKey          *HostKeyPin // nil when no host key is pinned
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

func fromRow(id, accountID, label, host string, port int64, username, uv string, desc sql.NullString, agentForward int64, hkType, hkFp, hkAt, hkBy sql.NullString) Endpoint {
	var d *string
	if desc.Valid {
		d = &desc.String
	}
	var pin *HostKeyPin
	if hkFp.Valid {
		pin = &HostKeyPin{Type: hkType.String, Fingerprint: hkFp.String, PinnedAt: hkAt.String, PinnedBy: hkBy.String}
	}
	return Endpoint{
		ID: id, AccountID: accountID, Label: label, Host: host, Port: port,
		Username: username, UserVerification: uv, Description: d, AgentForward: agentForward != 0,
		HostKey: pin,
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
		out = append(out, fromRow(r.ID, r.AccountID, r.Label, r.Host, r.Port, r.Username, r.UserVerification, r.Description, r.AgentForward,
			r.HostKeyType, r.HostKeyFingerprint, r.HostKeyPinnedAt, r.HostKeyPinnedBy))
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
	ep := fromRow(r.ID, r.AccountID, r.Label, r.Host, r.Port, r.Username, r.UserVerification, r.Description, r.AgentForward,
		r.HostKeyType, r.HostKeyFingerprint, r.HostKeyPinnedAt, r.HostKeyPinnedBy)
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
// A host or port change clears the pinned host key in the same statement
// (#241): the old pin must never vouch for a new address. Returns false when
// no row matched (unknown id / not owned).
func (e *Endpoints) Update(ctx context.Context, ep Endpoint) (bool, error) {
	n, err := gen.New(e.db).UpdateEndpoint(ctx, gen.UpdateEndpointParams{
		Label: ep.Label, Host: ep.Host, Port: ep.Port, Username: ep.Username,
		UserVerification: ep.UserVerification, Description: nullString(ep.Description),
		AgentForward: boolInt(ep.AgentForward), UpdatedAt: e.clk.Now().UTC().Format(isoMillis),
		ID: ep.ID, AccountID: ep.AccountID,
	})
	return n > 0, err
}

// Delete soft-deletes an endpoint (enabled=0, Node parity); returns false
// when nothing matched.
func (e *Endpoints) Delete(ctx context.Context, id, accountID string) (bool, error) {
	n, err := gen.New(e.db).DeleteEndpointForAccount(ctx, gen.DeleteEndpointForAccountParams{
		UpdatedAt: e.clk.Now().UTC().Format(isoMillis), ID: id, AccountID: accountID,
	})
	return n > 0, err
}

// GetHostKey returns the endpoint's pinned host key for connection-time
// verification (nil when unpinned). By id only: the endpoint was resolved
// account-scoped before any dial.
func (e *Endpoints) GetHostKey(ctx context.Context, id string) (*HostKeyRecord, error) {
	r, err := gen.New(e.db).GetEndpointHostKey(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil // unknown endpoint reads as unpinned; the dial fails on its own
	}
	if err != nil {
		return nil, err
	}
	if !r.HostKeyFingerprint.Valid {
		return nil, nil
	}
	return &HostKeyRecord{Type: r.HostKeyType.String, Key: r.HostKey, Fingerprint: r.HostKeyFingerprint.String}, nil
}

// PinHostKey compare-and-sets the endpoint's host key (#241): the write lands
// only when no pin exists. When a pin already exists it must equal the
// observed fingerprint (idempotent re-pin, e.g. two concurrent first
// connections to the same honest host) — otherwise ErrHostKeyPinned.
func (e *Endpoints) PinHostKey(ctx context.Context, id string, rec HostKeyRecord, pinnedBy string) error {
	q := gen.New(e.db)
	n, err := q.PinEndpointHostKey(ctx, gen.PinEndpointHostKeyParams{
		HostKeyType:        nz(rec.Type),
		HostKey:            rec.Key,
		HostKeyFingerprint: sql.NullString{String: rec.Fingerprint, Valid: true},
		HostKeyPinnedAt:    sql.NullString{String: e.clk.Now().UTC().Format(isoMillis), Valid: true},
		HostKeyPinnedBy:    nz(pinnedBy),
		UpdatedAt:          e.clk.Now().UTC().Format(isoMillis),
		ID:                 id,
	})
	if err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	existing, err := q.GetEndpointHostKey(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return errors.New("endpoint not found")
	}
	if err != nil {
		return err
	}
	if existing.HostKeyFingerprint.Valid && existing.HostKeyFingerprint.String == rec.Fingerprint {
		return nil // the same key won the race — nothing to do
	}
	return ErrHostKeyPinned
}

// ClearHostKey forgets the endpoint's pinned host key (account-scoped).
// Returns false when no pin existed (or the endpoint isn't owned).
func (e *Endpoints) ClearHostKey(ctx context.Context, id, accountID string) (bool, error) {
	n, err := gen.New(e.db).ClearEndpointHostKey(ctx, gen.ClearEndpointHostKeyParams{
		UpdatedAt: e.clk.Now().UTC().Format(isoMillis), ID: id, AccountID: accountID,
	})
	return n > 0, err
}

// AddressPinState is one endpoint matched by address for config-file pin
// provisioning (#241).
type AddressPinState struct {
	ID                string
	PinnedFingerprint string // "" when unpinned
}

// ListByAddress returns the account's enabled endpoints at an address tuple
// (config-file hostKey provisioning matches by address — seed endpoints carry
// no stable id).
func (e *Endpoints) ListByAddress(ctx context.Context, accountID, host string, port int64, username string) ([]AddressPinState, error) {
	rows, err := gen.New(e.db).ListEndpointsByAddress(ctx, gen.ListEndpointsByAddressParams{
		AccountID: accountID, Host: host, Port: port, Username: username,
	})
	if err != nil {
		return nil, err
	}
	out := make([]AddressPinState, 0, len(rows))
	for _, r := range rows {
		out = append(out, AddressPinState{ID: r.ID, PinnedFingerprint: r.HostKeyFingerprint.String})
	}
	return out, nil
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

func nz(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}

func boolInt(b bool) int64 {
	if b {
		return 1
	}
	return 0
}
