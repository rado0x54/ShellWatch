// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Pending-action REST (port of src/server/routes/actions.ts): the /sign/:id
// page reads GET /api/actions/:id, then POSTs the WebAuthn assertion to
// resolve (or empty to deny). Account-scoped; state conflicts 409.
package rest

import (
	"encoding/base64"
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/rado0x54/shellwatch/internal/approval"
	"github.com/rado0x54/shellwatch/internal/signing"
)

// Actions wires the pending-action routes.
type Actions struct {
	Store *approval.Store
}

func (a *Actions) Mount(r chi.Router) {
	r.Get("/api/actions/{actionId}", a.get)
	r.Post("/api/actions/{actionId}/resolve", a.resolve)
	r.Post("/api/actions/{actionId}/deny", a.deny)
}

func (a *Actions) lookup(w http.ResponseWriter, r *http.Request) *approval.Action {
	action := a.Store.Get(chi.URLParam(r, "actionId"))
	if action == nil {
		writeErr(w, 404, "Action not found")
		return nil
	}
	if action.AccountID != accountID(r) {
		writeErr(w, 403, "Access denied")
		return nil
	}
	return action
}

func (a *Actions) get(w http.ResponseWriter, r *http.Request) {
	action := a.lookup(w, r)
	if action == nil {
		return
	}
	writeJSON(w, 200, actionView(action))
}

func (a *Actions) resolve(w http.ResponseWriter, r *http.Request) {
	action := a.lookup(w, r)
	if action == nil {
		return
	}
	if action.Status != approval.StatusPending {
		writeErr(w, 409, "Action is already "+string(action.Status))
		return
	}
	switch action.Type {
	case approval.TypeWebAuthnSign:
		body := readRawBody(r)
		authData := b64urlField(body, "authenticatorData")
		sig := b64urlField(body, "signature")
		cdj := b64urlField(body, "clientDataJSON")
		if authData == nil || sig == nil || cdj == nil {
			writeErr(w, 400, "Missing required fields: authenticatorData, signature, clientDataJSON")
			return
		}
		// Defense-in-depth UV check (the SSH server is the real gate).
		if action.UserVerification == "required" && !signing.IsUserVerified(authData) {
			writeErr(w, 400, "User verification required")
			return
		}
		if !a.Store.ResolveSign(action.ID, signing.SignResponse{
			AuthenticatorData: authData, Signature: sig, ClientDataJSON: cdj,
		}) {
			writeErr(w, 409, "Action is already "+string(action.Status))
			return
		}
	case approval.TypeKeyApprove:
		if !a.Store.ResolveKey(action.ID) {
			writeErr(w, 409, "Action is already "+string(action.Status))
			return
		}
	}
	writeJSON(w, 200, map[string]any{"status": "resolved", "redirectTo": action.RedirectTo})
}

func (a *Actions) deny(w http.ResponseWriter, r *http.Request) {
	action := a.lookup(w, r)
	if action == nil {
		return
	}
	if action.Status != approval.StatusPending {
		writeErr(w, 409, "Action is already "+string(action.Status))
		return
	}
	a.Store.Deny(action.ID)
	writeJSON(w, 200, map[string]any{"status": "denied"})
}

// actionView is the client-safe projection (excludes resolve/reject closures).
func actionView(a *approval.Action) map[string]any {
	v := map[string]any{
		"id": a.ID, "accountId": a.AccountID, "type": string(a.Type), "status": string(a.Status),
		"createdAt": a.CreatedAt.UTC().Format(isoMillis), "expiresAt": a.ExpiresAt.UTC().Format(isoMillis),
		"context": a.Context,
	}
	if a.RedirectTo != "" {
		v["redirectTo"] = a.RedirectTo
	}
	switch a.Type {
	case approval.TypeWebAuthnSign:
		v["credentialId"] = a.CredentialID
		v["challenge"] = a.Challenge
		v["rpId"] = a.RpID
		v["userVerification"] = a.UserVerification
		if a.PasskeyLabel != "" {
			v["passkeyLabel"] = a.PasskeyLabel
		}
	case approval.TypeKeyApprove:
		v["keyLabel"] = a.KeyLabel
		v["keyFingerprint"] = a.KeyFingerprint
	}
	return v
}

func b64urlField(body map[string]json.RawMessage, key string) []byte {
	raw, ok := body[key]
	if !ok {
		return nil
	}
	s := jsonString(raw)
	if s == "" {
		return nil
	}
	d, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil
	}
	return d
}
