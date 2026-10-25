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
		// clientDataJSON arrives as the raw JSON string (the browser sends
		// TextDecoder().decode(...)), NOT base64url — it's parsed as JSON and
		// spliced verbatim into the OpenSSH webauthn-sk signature blob.
		cdj := rawStringField(body, "clientDataJSON")
		if authData == nil || sig == nil || cdj == nil {
			writeErr(w, 400, "Missing required fields: authenticatorData, signature, clientDataJSON")
			return
		}
		// Defense-in-depth UV check (the SSH server is the real gate).
		if action.UserVerification == "required" && !signing.IsUserVerified(authData) {
			writeErr(w, 400, "User verification required")
			return
		}
		if res := a.Store.ResolveSign(action.ID, signing.SignResponse{
			AuthenticatorData: authData, Signature: sig, ClientDataJSON: cdj,
		}); !res.Won {
			writeClaimConflict(w, res)
			return
		}
	case approval.TypeKeyApprove:
		if res := a.Store.ResolveKey(action.ID); !res.Won {
			writeClaimConflict(w, res)
			return
		}
	}
	// Node returns just { redirectTo } here (no status field) — match it.
	writeJSON(w, 200, map[string]any{"redirectTo": action.RedirectTo})
}

func (a *Actions) deny(w http.ResponseWriter, r *http.Request) {
	action := a.lookup(w, r)
	if action == nil {
		return
	}
	res := a.Store.Deny(action.ID)
	// Deny is idempotent over every no-signature outcome: whether this call
	// denied the action, it was already denied (double-click, concurrent
	// cancel), or it expired a moment earlier, what the user asked for — no
	// signature — holds, so all three answer 200. Only a state the store
	// asserted is ever reported: a lost race against a resolve answers 409
	// "completed", never "denied" for a signature that actually went through.
	if res.Won || (res.Found && (res.Status == approval.StatusDenied || res.Status == approval.StatusExpired)) {
		// Report the store-asserted status, not a flattened "denied": the
		// audit row and every other surface say "expired" for the expired
		// edge, and this response must agree with them.
		writeJSON(w, 200, map[string]any{"status": string(res.Status)})
		return
	}
	writeClaimConflict(w, res)
}

// writeClaimConflict renders a lost claim from the store's own answer: 409
// naming the terminal status the store asserted, or 404 when the action was
// swept in between — the exact outcome is gone then, and naming one
// ("resolved") would tell a denier a signature went through when it may not
// have.
func writeClaimConflict(w http.ResponseWriter, res approval.ClaimResult) {
	if !res.Found {
		writeErr(w, 404, "Action not found")
		return
	}
	writeErr(w, 409, "Action is already "+string(res.Status))
}

// actionView is the client-safe projection (excludes resolve/reject closures).
func actionView(a *approval.Action) map[string]any {
	v := map[string]any{
		"id": a.ID, "accountId": a.AccountID, "type": string(a.Type), "status": string(a.Status),
		// Epoch-ms integers (contract + store.ts:46-47) — countdown clients do
		// arithmetic on these.
		"createdAt": a.CreatedAt.UnixMilli(), "expiresAt": a.ExpiresAt.UnixMilli(),
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

// rawStringField returns a string body field's bytes verbatim (nil if missing
// or empty) — used for clientDataJSON, which is a raw JSON string, not base64url.
func rawStringField(body map[string]json.RawMessage, key string) []byte {
	raw, ok := body[key]
	if !ok {
		return nil
	}
	s := jsonString(raw)
	if s == "" {
		return nil
	}
	return []byte(s)
}
