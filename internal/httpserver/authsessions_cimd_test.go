// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Revoking a CIMD client (#242). A CIMD client_id IS a URL, so the caller has
// to percent-encode it into the route — and chi hands the segment back still
// encoded, which silently sent Hydra a client named "https%3A%2F%2F…".
package httpserver

import (
	"net/url"
	"strings"
	"testing"

	"github.com/rado0x54/shellwatch/internal/webauthn"
)

func TestRevokeDecodesAURLClientID(t *testing.T) {
	const clientID = "https://apps.example.com/.well-known/client.json"
	ts, db, fake, stepUp := authedApp(t, nil)
	exec(t, db, `INSERT INTO accounts (id,name,created_at,updated_at) VALUES (?,'Admin','2026-01-01T00:00:00.000Z','2026-01-01T00:00:00.000Z')`, acct)

	tok := "stepup-revoke-cimd"
	stepUp.Mint(tok, acct, webauthn.ActionRevokeSession)
	status, body := req(t, ts, "DELETE",
		"/api/auth/sessions/"+url.PathEscape(clientID), "", tok)
	if status != 200 {
		t.Fatalf("status = %d, body %v", status, body)
	}

	// Hydra must be asked to revoke the real client_id, not the encoded form.
	want := acct + "/" + clientID
	if len(fake.RevokedConsent) != 1 || fake.RevokedConsent[0] != want {
		t.Fatalf("admin saw %v, want [%q]", fake.RevokedConsent, want)
	}
	for _, got := range fake.RevokedConsent {
		if strings.Contains(got, "%2F") || strings.Contains(got, "%3A") {
			t.Errorf("revocation target is still percent-encoded: %q", got)
		}
	}
}
