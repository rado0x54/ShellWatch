// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Login assertion helpers (port of src/webauthn/assertion.ts): the primitive
// "prove possession of an active passkey", shared by the Hydra login and
// consent providers. Login is not account-scoped — any active credential
// authenticates its owning account.
package webauthn

import (
	"context"

	"github.com/rado0x54/shellwatch/internal/store"
)

// LoginOptions builds assertion options + a login-purpose challenge over all
// active credentials. Returns ("", "", nil) when there are none.
func (d *Deps) LoginOptions(ctx context.Context) (options authOptions, ok bool, err error) {
	creds, err := d.Credentials.AllActiveCredentialIDs(ctx)
	if err != nil {
		return authOptions{}, false, err
	}
	if len(creds) == 0 {
		return authOptions{}, false, nil
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
	}
	d.Challenges.Store(opts.ChallengeID, opts.Challenge, PurposeLogin)
	return opts, true, nil
}

// LoginResult is a verified login assertion.
type LoginResult struct {
	AccountID string
	Status    int    // HTTP status on failure
	Error     string // non-empty on failure
}

// VerifyLogin verifies a login assertion, bumps the credential counter, and
// returns the owning account id (verifyPasskeyAssertion, login purpose). The
// asserting credential must be active + non-revoked.
func (d *Deps) VerifyLogin(ctx context.Context, challengeID, credentialID string, rawCredential []byte) LoginResult {
	challenge := d.Challenges.Consume(challengeID, PurposeLogin)
	if challenge == "" {
		return LoginResult{Status: 400, Error: "Challenge expired or not found"}
	}
	stored, err := d.Credentials.FindByCredentialID(ctx, credentialID)
	if err != nil || stored == nil {
		return LoginResult{Status: 400, Error: "Unknown credential"}
	}
	if stored.Revoked {
		return LoginResult{Status: 403, Error: "This passkey has been revoked"}
	}
	if stored.State != store.CredentialStateActive {
		return LoginResult{Status: 403, Error: "This passkey is awaiting confirmation on the original device"}
	}
	res, err := VerifyAssertion(rawCredential, challenge, d.RpID, d.TrustedOrigins,
		stored.PublicKeyCOSE, stored.Counter)
	if err != nil {
		return LoginResult{Status: 400, Error: err.Error()}
	}
	if err := d.Credentials.UpdateCounter(ctx, stored.RowID, res.NewCounter); err != nil {
		return LoginResult{Status: 400, Error: err.Error()}
	}
	return LoginResult{AccountID: stored.AccountID}
}
