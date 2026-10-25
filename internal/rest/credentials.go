// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// WebAuthn credential management (/api/webauthn/credentials) REST (port of
// credentials.ts): list, rename (PATCH label), revoke (step-up gated). Pinned
// by credentials-list / credential-label / credential-revoke goldens.
package rest

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/rado0x54/shellwatch/internal/store"
	"github.com/rado0x54/shellwatch/internal/webauthn"
)

// sessionRevoker is the slice of the Hydra admin the revoke path needs.
type sessionRevoker interface {
	RevokeConsentSessions(ctx context.Context, subject, clientID string) error
	RevokeLoginSessions(ctx context.Context, subject string) error
}

// Credentials wires the credential-management routes.
type Credentials struct {
	Store *store.Credentials
	Admin sessionRevoker
	// StepUp gates the revoke route (RequireStepUp middleware).
	StepUp *webauthn.StepUpStore
}

func (c *Credentials) Mount(r chi.Router) {
	r.Get("/api/webauthn/credentials", c.list)
	r.Patch("/api/webauthn/credentials/{id}/label", c.label)
	r.With(c.StepUp.RequireStepUp(webauthn.ActionRevokePasskey)).
		Post("/api/webauthn/credentials/{id}/revoke", c.revoke)
}

func (c *Credentials) list(w http.ResponseWriter, r *http.Request) {
	creds, err := c.Store.ListForAccountFull(r.Context(), accountID(r))
	if err != nil {
		writeErr(w, 500, "internal error")
		return
	}
	out := make([]map[string]any, 0, len(creds))
	for _, cr := range creds {
		active := cr.State == "active"
		var authorizedKeys any
		if active && cr.PublicKeyOpenSSH != nil {
			authorizedKeys = *cr.PublicKeyOpenSSH
		}
		fingerprint := ""
		if cr.PublicKeyOpenSSH != nil {
			fingerprint = webauthn.FingerprintFromAuthorizedKeys(*cr.PublicKeyOpenSSH)
		}
		out = append(out, map[string]any{
			"id": cr.ID, "credentialId": cr.CredentialID, "label": cr.Label,
			"algorithm": webauthn.DetectAlgorithm(cr.PublicKeyCOSE), "fingerprint": fingerprint,
			"authorizedKeysEntry": authorizedKeys, "revoked": cr.Revoked, "state": cr.State,
			"createdAt": cr.CreatedAt, "lastUsedAt": cr.LastUsedAt,
		})
	}
	writeJSON(w, 200, map[string]any{
		"credentials": out,
		"sshdConfig":  webauthn.SshdConfigLine(),
	})
}

func (c *Credentials) label(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	acct := accountID(r)
	var body struct {
		Label string `json:"label"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	trimmed := strings.TrimSpace(body.Label)
	if trimmed == "" {
		writeErr(w, 400, "Label is required")
		return
	}
	// Ownership check.
	creds, err := c.Store.ListForAccountFull(r.Context(), acct)
	if err != nil {
		writeErr(w, 500, "internal error")
		return
	}
	if !ownsCredential(creds, id) {
		writeErr(w, 404, "Credential not found")
		return
	}
	conflict, err := c.Store.LabelConflict(r.Context(), acct, trimmed, id)
	if err != nil {
		writeErr(w, 500, "internal error")
		return
	}
	if conflict {
		writeErr(w, 409, "A passkey with this label already exists")
		return
	}
	if err := c.Store.SetLabel(r.Context(), id, acct, trimmed); err != nil {
		writeErr(w, 500, "internal error")
		return
	}
	writeJSON(w, 200, map[string]string{"status": "updated"})
}

func (c *Credentials) revoke(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	acct := accountID(r)
	var body struct {
		InvalidateSessions bool `json:"invalidateSessions"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)

	creds, err := c.Store.ListForAccountFull(r.Context(), acct)
	if err != nil {
		writeErr(w, 500, "internal error")
		return
	}
	var target *store.CredentialRow
	for i := range creds {
		if creds[i].ID == id {
			target = &creds[i]
			break
		}
	}
	if target == nil {
		writeErr(w, 404, "Credential not found")
		return
	}
	if target.Revoked {
		writeErr(w, 400, "Credential is already revoked")
		return
	}
	// Only active credentials count toward the last-login-factor guard.
	if target.State == "active" {
		n, err := c.Store.ActiveCount(r.Context(), acct)
		if err != nil {
			writeErr(w, 500, "internal error")
			return
		}
		if n <= 1 {
			writeErr(w, 400, "Cannot revoke the last active passkey")
			return
		}
	}
	if err := c.Store.Revoke(r.Context(), id); err != nil {
		writeErr(w, 500, "internal error")
		return
	}
	// Optionally sign out everywhere (Hydra keys by subject, so account-wide).
	// A Hydra hiccup here must not fail the already-committed revoke.
	sessionsInvalidated := false
	if body.InvalidateSessions {
		if err := c.Admin.RevokeConsentSessions(r.Context(), acct, ""); err == nil {
			if err := c.Admin.RevokeLoginSessions(r.Context(), acct); err == nil {
				sessionsInvalidated = true
			}
		}
	}
	writeJSON(w, 200, map[string]any{"status": "revoked", "sessionsInvalidated": sessionsInvalidated})
}

func ownsCredential(creds []store.CredentialRow, id string) bool {
	for _, c := range creds {
		if c.ID == id {
			return true
		}
	}
	return false
}
