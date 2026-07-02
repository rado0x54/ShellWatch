// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// store.Credentials is the sole owner of the webauthn_credentials table
// (fixes W8). Ports the credential-store.ts insert + deduplicateLabel logic
// and the self-register account-create atom (self-register.ts), using a
// transaction where the Node code does (fixes W9 for this path).
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/rado0x54/shellwatch/internal/clock"
	"github.com/rado0x54/shellwatch/internal/store/gen"
)

// CredentialState values (CREDENTIAL_STATE).
const (
	CredentialStateActive              = "active"
	CredentialStatePendingConfirmation = "pending_confirmation"
)

// DecodedCredential is the DB-ready credential (mirrors the webauthn package's
// DecodedRegistration, kept dependency-free here to avoid an import cycle).
type DecodedCredential struct {
	CredentialID        string
	PublicKeyCOSE       []byte
	Counter             uint32
	Transports          []string
	BaseLabel           string
	AuthorizedKeysEntry string
}

// Credentials owns all webauthn_credentials access.
type Credentials struct {
	db  *sql.DB
	clk clock.Clock
}

func NewCredentials(db *sql.DB, clk clock.Clock) *Credentials {
	if clk == nil {
		clk = clock.Real{}
	}
	return &Credentials{db: db, clk: clk}
}

// HasPasskeys reports whether any credential exists (bootstrap detection).
func (c *Credentials) HasPasskeys(ctx context.Context) (bool, error) {
	n, err := gen.New(c.db).HasPasskeys(ctx)
	return n, err
}

// ActiveCredentialIDs returns base64url credential ids for excludeCredentials
// / allowCredentials scoping.
func (c *Credentials) ActiveCredentialIDs(ctx context.Context, accountID string) ([]string, error) {
	return gen.New(c.db).ListActiveCredentialIDsForAccount(ctx, accountID)
}

// AllActiveCredentialIDs returns every active, non-revoked credential id (the
// login provider's allowCredentials — not account-scoped).
func (c *Credentials) AllActiveCredentialIDs(ctx context.Context) ([]string, error) {
	return gen.New(c.db).ListAllActiveCredentialIDs(ctx)
}

// AuthCredential is a passkey usable for SSH auth (the OpenSSH line is derived
// at registration time).
type AuthCredential struct {
	RowID            string
	CredentialID     string
	PublicKeyOpenSSH string
	Label            string
}

// ActiveCredentialsForAuth returns the account's active passkeys with their
// OpenSSH public-key lines (the transport factory builds signers from these).
func (c *Credentials) ActiveCredentialsForAuth(ctx context.Context, accountID string) ([]AuthCredential, error) {
	rows, err := gen.New(c.db).ListActiveCredentialsForAuth(ctx, accountID)
	if err != nil {
		return nil, err
	}
	out := make([]AuthCredential, 0, len(rows))
	for _, r := range rows {
		if !r.PublicKeyOpenssh.Valid {
			continue // no OpenSSH line (non-ES256) -> not usable for SSH
		}
		out = append(out, AuthCredential{
			RowID: r.ID, CredentialID: r.CredentialID,
			PublicKeyOpenSSH: r.PublicKeyOpenssh.String, Label: r.Label,
		})
	}
	return out, nil
}

// FoundCredential is a credential row needed for assertion verification.
type FoundCredential struct {
	RowID         string
	AccountID     string
	CredentialID  string
	PublicKeyCOSE []byte
	Counter       uint32
	Revoked       bool
	State         string
}

// FindByCredentialID looks up a credential by its base64url id (nil, nil when
// absent).
func (c *Credentials) FindByCredentialID(ctx context.Context, credentialID string) (*FoundCredential, error) {
	row, err := gen.New(c.db).FindCredentialByCredentialID(ctx, credentialID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &FoundCredential{
		RowID: row.ID, AccountID: row.AccountID, CredentialID: row.CredentialID,
		PublicKeyCOSE: row.PublicKey, Counter: uint32(row.Counter),
		Revoked: row.Revoked != 0, State: row.State,
	}, nil
}

// PendingCredential is a credential row's confirm-relevant state.
type PendingCredential struct {
	RowID   string
	State   string
	Revoked bool
}

// FindForAccount looks up a credential by row id scoped to an account (the
// 404-not-403 disclosure convention: nil when not owned).
func (c *Credentials) FindForAccount(ctx context.Context, rowID, accountID string) (*PendingCredential, error) {
	row, err := gen.New(c.db).FindCredentialByIDAndAccount(ctx, gen.FindCredentialByIDAndAccountParams{
		ID: rowID, AccountID: accountID,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &PendingCredential{RowID: row.ID, State: row.State, Revoked: row.Revoked != 0}, nil
}

// SetState flips a credential's lifecycle state (confirm: pending -> active).
func (c *Credentials) SetState(ctx context.Context, rowID, state string) error {
	return gen.New(c.db).SetCredentialState(ctx, gen.SetCredentialStateParams{State: state, ID: rowID})
}

// AccountName returns an account's display name.
func (c *Credentials) AccountName(ctx context.Context, accountID string) (string, error) {
	acc, err := gen.New(c.db).GetAccount(ctx, accountID)
	if err != nil {
		return "", err
	}
	return acc.Name, nil
}

// UpdateCounter bumps a credential's signature counter + last_used_at.
func (c *Credentials) UpdateCounter(ctx context.Context, rowID string, counter uint32) error {
	return gen.New(c.db).UpdateCredentialCounter(ctx, gen.UpdateCredentialCounterParams{
		Counter:    int64(counter),
		LastUsedAt: sql.NullString{String: c.nowISO(), Valid: true},
		ID:         rowID,
	})
}

// Inserted is the result of a credential insert.
type Inserted struct {
	ID    string
	Label string
}

// Insert adds a verified credential in-account (register.ts insertCredentialRow),
// deduplicating the label. newUUID is injected so callers control id
// generation (Math/rand is unavailable in some contexts; tests want it too).
func (c *Credentials) Insert(ctx context.Context, accountID string, dec DecodedCredential, state, id string) (Inserted, error) {
	return c.insertTx(ctx, c.db, accountID, dec, state, id)
}

func (c *Credentials) insertTx(ctx context.Context, q gen.DBTX, accountID string, dec DecodedCredential, state, id string) (Inserted, error) {
	label, err := c.dedupeLabel(ctx, q, accountID, dec.BaseLabel)
	if err != nil {
		return Inserted{}, err
	}
	transports, _ := json.Marshal(dec.Transports)
	openssh := sql.NullString{}
	if dec.AuthorizedKeysEntry != "" {
		openssh = sql.NullString{String: dec.AuthorizedKeysEntry, Valid: true}
	}
	err = gen.New(q).InsertCredential(ctx, gen.InsertCredentialParams{
		ID:               id,
		AccountID:        accountID,
		CredentialID:     dec.CredentialID,
		PublicKey:        dec.PublicKeyCOSE,
		Counter:          int64(dec.Counter),
		Transports:       sql.NullString{String: string(transports), Valid: true},
		Label:            label,
		PublicKeyOpenssh: openssh,
		State:            state,
		CreatedAt:        c.nowISO(),
	})
	if err != nil {
		return Inserted{}, err
	}
	return Inserted{ID: id, Label: label}, nil
}

func (c *Credentials) dedupeLabel(ctx context.Context, q gen.DBTX, accountID, base string) (string, error) {
	labels, err := gen.New(q).ListActiveCredentialLabelsForAccount(ctx, accountID)
	if err != nil {
		return "", err
	}
	seen := make(map[string]bool, len(labels))
	for _, l := range labels {
		seen[l] = true
	}
	if !seen[base] {
		return base, nil
	}
	for suffix := 2; ; suffix++ {
		candidate := fmt.Sprintf("%s (%d)", base, suffix)
		if !seen[candidate] {
			return candidate, nil
		}
	}
}

// SelfRegisterResult is the outcome of the atomic account+credential create.
type SelfRegisterResult struct {
	AccountID       string
	CredentialRowID string
	Label           string
}

// SelfRegister creates (or adopts the seeded admin) account and inserts the
// first credential atomically (self-register.ts). newAccountID/newCredID are
// injected. Returns nil if self-registration is disabled and the system is
// already bootstrapped (the caller 403s).
func (c *Credentials) SelfRegister(ctx context.Context, name string, dec DecodedCredential, selfRegEnabled bool, newAccountID, newCredID string) (*SelfRegisterResult, error) {
	var res *SelfRegisterResult
	err := WithTx(ctx, c.db, func(tx *sql.Tx) error {
		q := gen.New(tx)
		// TOCTOU re-check inside the transaction.
		has, err := q.HasPasskeys(ctx)
		if err != nil {
			return err
		}
		bootstrapped := has
		if !selfRegEnabled && bootstrapped {
			return nil // res stays nil -> disabled
		}

		adminID, adminErr := q.GetAdminAccountID(ctx)
		hasAdmin := adminErr == nil

		var accountID string
		if !bootstrapped && hasAdmin {
			// Onboarding: adopt the seeded admin (its canonical name wins).
			accountID = adminID
		} else {
			accountID = newAccountID
			now := c.nowISO()
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO accounts (id, name, enabled, max_sessions, last_used_at, created_at, updated_at)
				 VALUES (?, ?, 1, 5, ?, ?, ?)`, accountID, name, now, now, now); err != nil {
				return err
			}
			if !hasAdmin {
				// First account becomes admin (INSERT OR IGNORE; singleton CHECK).
				if _, err := tx.ExecContext(ctx,
					`INSERT OR IGNORE INTO admin_account (singleton, account_id) VALUES (1, ?)`, accountID); err != nil {
					return err
				}
			}
		}

		ins, err := c.insertTx(ctx, tx, accountID, dec, CredentialStateActive, newCredID)
		if err != nil {
			return err
		}
		res = &SelfRegisterResult{AccountID: accountID, CredentialRowID: ins.ID, Label: ins.Label}
		return nil
	})
	return res, err
}

func (c *Credentials) nowISO() string {
	return c.clk.Now().UTC().Format(isoMillis)
}
