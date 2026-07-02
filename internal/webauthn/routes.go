// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// WebAuthn ceremony HTTP handlers (port of self-register.ts, registration.ts,
// stepup.ts). Slice 2 covers registration (self + in-account) and step-up;
// the Hydra login provider and invite redemption land with their
// dependencies in later slices. Response envelopes are pinned by the
// webauthn-self-register / webauthn-register / webauthn-stepup-verify goldens.
package webauthn

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/rado0x54/shellwatch/internal/auth"
	"github.com/rado0x54/shellwatch/internal/store"
)

// Deps are the ceremony handlers' collaborators.
type Deps struct {
	Credentials    *store.Credentials
	Challenges     *ChallengeStore
	StepUp         *StepUpStore
	RpID           string
	TrustedOrigins []string
	SelfRegEnabled bool
}

// Mount registers the slice-2 ceremony routes on r. The bearer gate (global
// middleware) exempts the anonymous /api/auth/* endpoints and requires the
// `ui` scope for /api/webauthn/*.
func (d *Deps) Mount(r chi.Router) {
	r.Get("/api/auth/passkey-status", d.passkeyStatus)
	r.Post("/api/auth/register/options", d.selfRegisterOptions)
	r.Post("/api/auth/register", d.selfRegister)

	r.Post("/api/webauthn/register/options", d.inAccountRegisterOptions)
	r.With(d.StepUp.RequireStepUp(ActionRegisterPasskey)).
		Post("/api/webauthn/register", d.inAccountRegister)

	r.Post("/api/webauthn/stepup/options", d.stepUpOptions)
	r.Post("/api/webauthn/stepup/verify", d.stepUpVerify)
}

func (d *Deps) passkeyStatus(w http.ResponseWriter, r *http.Request) {
	has, err := d.Credentials.HasPasskeys(r.Context())
	if err != nil {
		writeErr(w, 500, "internal error")
		return
	}
	writeJSON(w, 200, map[string]bool{"hasPasskeys": has})
}

// --- registration options (shared shape) ---

type regOptions struct {
	Challenge              string           `json:"challenge"`
	Rp                     map[string]any   `json:"rp"`
	User                   map[string]any   `json:"user"`
	PubKeyCredParams       []map[string]any `json:"pubKeyCredParams"`
	AuthenticatorSelection map[string]any   `json:"authenticatorSelection"`
	Attestation            string           `json:"attestation"`
	ExcludeCredentials     []map[string]any `json:"excludeCredentials,omitempty"`
	ChallengeID            string           `json:"challengeId"`
}

func (d *Deps) buildRegOptions(userName string, exclude []string) regOptions {
	challenge := randomB64URL(32)
	excludeList := make([]map[string]any, 0, len(exclude))
	for _, id := range exclude {
		excludeList = append(excludeList, map[string]any{"id": id, "type": "public-key"})
	}
	return regOptions{
		Challenge:        challenge,
		Rp:               map[string]any{"name": "ShellWatch", "id": d.RpID},
		User:             map[string]any{"id": randomB64URL(16), "name": userName, "displayName": userName},
		PubKeyCredParams: []map[string]any{{"type": "public-key", "alg": -7}},
		AuthenticatorSelection: map[string]any{
			"residentKey": "preferred", "userVerification": "required",
		},
		Attestation:        "none",
		ExcludeCredentials: excludeList,
	}
}

func (d *Deps) selfRegisterOptions(w http.ResponseWriter, r *http.Request) {
	if !d.SelfRegEnabled {
		if has, _ := d.Credentials.HasPasskeys(r.Context()); has {
			writeErr(w, 403, "Self-registration is disabled")
			return
		}
	}
	var body struct {
		Name string `json:"name"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	opts := d.buildRegOptions(clampName(body.Name, "user"), nil)
	d.Challenges.Store(challengeID(&opts), opts.Challenge, PurposeSelfRegister)
	writeJSON(w, 200, opts)
}

func (d *Deps) inAccountRegisterOptions(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFrom(r.Context())
	var body struct {
		Label string `json:"label"`
		Name  string `json:"name"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	name := body.Name
	if name == "" {
		name = body.Label
	}
	exclude, err := d.Credentials.ActiveCredentialIDs(r.Context(), principal.AccountID)
	if err != nil {
		writeErr(w, 500, "internal error")
		return
	}
	opts := d.buildRegOptions(clampName(name, "user"), exclude)
	d.Challenges.Store(challengeID(&opts), opts.Challenge, PurposeRegisterInAccount)
	writeJSON(w, 200, opts)
}

// --- registration verify ---

type verifyBody struct {
	Name        string          `json:"name"`
	ChallengeID string          `json:"challengeId"`
	Credential  json.RawMessage `json:"credential"`
}

func (d *Deps) selfRegister(w http.ResponseWriter, r *http.Request) {
	if !d.SelfRegEnabled {
		if has, _ := d.Credentials.HasPasskeys(r.Context()); has {
			writeErr(w, 403, "Self-registration is disabled")
			return
		}
	}
	var body verifyBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, 400, "invalid body")
		return
	}
	if body.ChallengeID == "" || len(body.Credential) == 0 {
		writeErr(w, 400, "name, challengeId, and credential are required")
		return
	}
	challenge := d.Challenges.Consume(body.ChallengeID, PurposeSelfRegister)
	if challenge == "" {
		writeErr(w, 400, "Challenge expired or not found")
		return
	}
	dec, err := VerifyRegistration(body.Credential, challenge, d.RpID, d.TrustedOrigins)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	res, err := d.Credentials.SelfRegister(r.Context(), body.Name, toStoreCred(dec),
		d.SelfRegEnabled, newUUID(), newUUID())
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if res == nil {
		writeErr(w, 403, "Self-registration is disabled")
		return
	}
	writeJSON(w, 200, map[string]any{
		"verified":     true,
		"accountId":    res.AccountID,
		"id":           res.CredentialRowID,
		"credentialId": dec.CredentialID,
		"label":        res.Label,
	})
}

func (d *Deps) inAccountRegister(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFrom(r.Context())
	var body verifyBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, 400, "invalid body")
		return
	}
	challenge := d.Challenges.Consume(body.ChallengeID, PurposeRegisterInAccount)
	if challenge == "" {
		writeErr(w, 400, "Challenge expired or not found")
		return
	}
	dec, err := VerifyRegistration(body.Credential, challenge, d.RpID, d.TrustedOrigins)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	ins, err := d.Credentials.Insert(r.Context(), principal.AccountID, toStoreCred(dec),
		store.CredentialStateActive, newUUID())
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	var sshdConfig any
	if dec.AuthorizedKeysEntry != "" {
		sshdConfig = SshdConfigLine()
	}
	writeJSON(w, 200, map[string]any{
		"verified":            true,
		"credentialId":        dec.CredentialID,
		"id":                  ins.ID,
		"label":               ins.Label,
		"authorizedKeysEntry": nullable(dec.AuthorizedKeysEntry),
		"sshdConfig":          sshdConfig,
	})
}

// --- step-up ---

type authOptions struct {
	Challenge        string           `json:"challenge"`
	RpID             string           `json:"rpId"`
	UserVerification string           `json:"userVerification"`
	AllowCredentials []map[string]any `json:"allowCredentials"`
	ChallengeID      string           `json:"challengeId"`
	Action           string           `json:"action"`
}

func (d *Deps) stepUpOptions(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFrom(r.Context())
	var body struct {
		Action string `json:"action"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if !IsStepUpAction(body.Action) {
		writeErr(w, 400, "Invalid or missing action")
		return
	}
	creds, err := d.Credentials.ActiveCredentialIDs(r.Context(), principal.AccountID)
	if err != nil {
		writeErr(w, 500, "internal error")
		return
	}
	if len(creds) == 0 {
		writeErr(w, 400, "no_active_credentials")
		return
	}
	allow := make([]map[string]any, 0, len(creds))
	for _, id := range creds {
		allow = append(allow, map[string]any{"id": id, "type": "public-key"})
	}
	opts := authOptions{
		Challenge:        randomB64URL(32),
		RpID:             d.RpID,
		UserVerification: "required",
		AllowCredentials: allow,
		ChallengeID:      newUUID(),
		Action:           body.Action,
	}
	d.Challenges.Store(opts.ChallengeID, opts.Challenge, ActionToPurpose[body.Action])
	writeJSON(w, 200, opts)
}

func (d *Deps) stepUpVerify(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFrom(r.Context())
	var body struct {
		ChallengeID string          `json:"challengeId"`
		Credential  json.RawMessage `json:"credential"`
		Action      string          `json:"action"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, 400, "invalid body")
		return
	}
	if !IsStepUpAction(body.Action) {
		writeErr(w, 400, "Invalid or missing action")
		return
	}
	challenge := d.Challenges.Consume(body.ChallengeID, ActionToPurpose[body.Action])
	if challenge == "" {
		writeErr(w, 400, "Challenge expired or not found")
		return
	}

	// The asserted credential must belong to the caller AND be active.
	var assertion struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(body.Credential, &assertion)
	stored, err := d.Credentials.FindByCredentialID(r.Context(), assertion.ID)
	if err != nil || stored == nil || stored.AccountID != principal.AccountID ||
		stored.Revoked || stored.State != store.CredentialStateActive {
		writeErr(w, 400, "Unknown credential")
		return
	}

	res, err := VerifyAssertion(body.Credential, challenge, d.RpID, d.TrustedOrigins,
		stored.PublicKeyCOSE, stored.Counter)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if err := d.Credentials.UpdateCounter(r.Context(), stored.RowID, res.NewCounter); err != nil {
		writeErr(w, 400, err.Error())
		return
	}

	token := randomB64URL(32)
	exp := d.StepUp.Mint(token, principal.AccountID, body.Action)
	writeJSON(w, 200, map[string]any{
		"stepUpToken": token,
		"expiresAt":   exp.UTC().Format(isoMillis),
		"action":      body.Action,
	})
}

// --- helpers ---

const isoMillis = "2006-01-02T15:04:05.000Z"

func toStoreCred(d *DecodedRegistration) store.DecodedCredential {
	return store.DecodedCredential{
		CredentialID: d.CredentialID, PublicKeyCOSE: d.PublicKeyCOSE, Counter: d.Counter,
		Transports: d.Transports, BaseLabel: d.BaseLabel, AuthorizedKeysEntry: d.AuthorizedKeysEntry,
	}
}

func challengeID(o *regOptions) string {
	if o.ChallengeID == "" {
		o.ChallengeID = newUUID()
	}
	return o.ChallengeID
}

func clampName(name, fallback string) string {
	if name == "" {
		name = fallback
	}
	if len(name) > 64 {
		return name[:64]
	}
	return name
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

var (
	_ = context.Background
	_ = time.Now
)
