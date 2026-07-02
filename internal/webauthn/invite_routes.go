// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Passkey-invite HTTP handlers (port of src/webauthn/invite.ts): mint/read
// the invite slot, the public token lookup + registration options + redeem
// (credential lands pending_confirmation), and the step-up-gated confirm.
// Pinned by the webauthn-invite-mint / webauthn-invite-redeem goldens.
package webauthn

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/rado0x54/shellwatch/internal/auth"
	"github.com/rado0x54/shellwatch/internal/store"
)

// mountInvite registers the invite routes (called from Deps.Mount when an
// Invites store is configured).
func (d *Deps) mountInvite(r chi.Router) {
	r.Post("/api/webauthn/invite", d.mintInvite)
	r.Get("/api/webauthn/invite", d.readInvite)
	r.With(d.StepUp.RequireStepUp(ActionConfirmPasskey)).
		Post("/api/webauthn/credentials/{id}/confirm", d.confirmCredential)

	r.Get("/api/passkey-invite/{token}", d.inviteByToken)
	r.Post("/api/passkey-invite/register/options", d.inviteRegisterOptions)
	r.Post("/api/passkey-invite/register", d.inviteRegister)
}

func publicInviteShape(slot InviteStoreSlot) map[string]any {
	return map[string]any{
		"expiresAt": slot.ExpiresAt,
		"createdAt": slot.CreatedAt,
		"token":     slot.Token,
	}
}

// InviteStoreSlot is the shape the handlers render (ISO-formatted times).
type InviteStoreSlot struct {
	Token     string
	ExpiresAt string
	CreatedAt string
}

func toPublicSlot(s InviteSlot) InviteStoreSlot {
	return InviteStoreSlot{
		Token:     s.Token,
		ExpiresAt: s.ExpiresAt.UTC().Format(isoMillis),
		CreatedAt: s.CreatedAt.UTC().Format(isoMillis),
	}
}

func (d *Deps) mintInvite(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFrom(r.Context())
	slot := d.Invites.Create(principal.AccountID, randomB64URL(32))
	writeJSON(w, 200, map[string]any{"invite": publicInviteShape(toPublicSlot(slot))})
}

func (d *Deps) readInvite(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFrom(r.Context())
	slot, ok := d.Invites.FindForAccount(principal.AccountID)
	if !ok {
		writeErr(w, 404, "No active invite")
		return
	}
	writeJSON(w, 200, map[string]any{"invite": publicInviteShape(toPublicSlot(slot))})
}

func (d *Deps) confirmCredential(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFrom(r.Context())
	id := chi.URLParam(r, "id")
	cred, err := d.Credentials.FindForAccount(r.Context(), id, principal.AccountID)
	if err != nil {
		writeErr(w, 500, "internal error")
		return
	}
	if cred == nil {
		writeErr(w, 404, "Credential not found")
		return
	}
	if cred.Revoked {
		writeErr(w, 400, "Credential is revoked")
		return
	}
	if cred.State == store.CredentialStateActive {
		writeErr(w, 400, "Credential is already active")
		return
	}
	if err := d.Credentials.SetState(r.Context(), id, store.CredentialStateActive); err != nil {
		writeErr(w, 500, "internal error")
		return
	}
	writeJSON(w, 200, map[string]string{"status": "active"})
}

func (d *Deps) inviteByToken(w http.ResponseWriter, r *http.Request) {
	slot, ok := d.Invites.FindByToken(chi.URLParam(r, "token"))
	if !ok {
		writeErr(w, 404, "Invite not found or expired")
		return
	}
	name, _ := d.Credentials.AccountName(r.Context(), slot.AccountID)
	writeJSON(w, 200, map[string]any{
		"accountName": nullable(name),
		"expiresAt":   slot.ExpiresAt.UTC().Format(isoMillis),
	})
}

func (d *Deps) inviteRegisterOptions(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token string `json:"token"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body.Token == "" {
		writeErr(w, 400, "Token is required")
		return
	}
	slot, ok := d.Invites.FindByToken(body.Token)
	if !ok {
		writeErr(w, 404, "Invite not found or expired")
		return
	}
	exclude, err := d.Credentials.ActiveCredentialIDs(r.Context(), slot.AccountID)
	if err != nil {
		writeErr(w, 500, "internal error")
		return
	}
	name, _ := d.Credentials.AccountName(r.Context(), slot.AccountID)
	if name == "" {
		name = "ShellWatch user"
	}
	opts := d.buildRegOptions(clampName(name, "user"), exclude)
	d.Challenges.Store(challengeID(&opts), opts.Challenge, PurposeRegisterInvite)
	writeJSON(w, 200, opts)
}

func (d *Deps) inviteRegister(w http.ResponseWriter, r *http.Request) {
	var withToken struct {
		Token       string          `json:"token"`
		ChallengeID string          `json:"challengeId"`
		Credential  json.RawMessage `json:"credential"`
	}
	_ = json.NewDecoder(r.Body).Decode(&withToken)

	if withToken.Token == "" {
		writeErr(w, 400, "Token is required")
		return
	}
	slot, ok := d.Invites.FindByToken(withToken.Token)
	if !ok {
		writeErr(w, 404, "Invite not found or expired")
		return
	}
	challenge := d.Challenges.Consume(withToken.ChallengeID, PurposeRegisterInvite)
	if challenge == "" {
		writeErr(w, 400, "Challenge expired or not found")
		return
	}
	dec, err := VerifyRegistration(withToken.Credential, challenge, d.RpID, d.TrustedOrigins)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	// Atomic supersede check: a concurrent mint can land during the async
	// verify above; refuse to consume a freshly superseded slot.
	if !d.Invites.ConsumeIfTokenMatches(slot.AccountID, withToken.Token) {
		writeErr(w, 409, "Invite was already used")
		return
	}
	ins, err := d.Credentials.Insert(r.Context(), slot.AccountID, toStoreCred(dec),
		store.CredentialStatePendingConfirmation, newUUID())
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{
		"status":      "registered",
		"label":       ins.Label,
		"fingerprint": nullable(FingerprintFromAuthorizedKeys(dec.AuthorizedKeysEntry)),
	})
}
