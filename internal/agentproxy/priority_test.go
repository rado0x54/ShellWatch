// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
package agentproxy

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/rado0x54/shellwatch/internal/clock"
	"github.com/rado0x54/shellwatch/internal/store"
	"github.com/rado0x54/shellwatch/internal/webauthn"
	"github.com/rado0x54/shellwatch/internal/webauthntest"
)

// A new agent-proxy connection lists passkey identities in the account's
// priority order (#308); file keys (admin) always come first.
func TestAgentProxyIdentitiesFollowPriority(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open("sqlite::memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := store.Migrate(db); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO accounts (id,name,created_at,updated_at) VALUES ('acc','A','t','t')`); err != nil {
		t.Fatal(err)
	}
	creds := store.NewCredentials(db, clock.Real{})
	for _, row := range []string{"first", "second"} {
		fake, err := webauthntest.New(webauthntest.Options{RpID: "localhost", Origin: "https://localhost"})
		if err != nil {
			t.Fatal(err)
		}
		challenge := base64.RawURLEncoding.EncodeToString([]byte("reg-challenge-1234567890"))
		dec, err := webauthn.VerifyRegistration(fake.Register(challenge), challenge, "localhost", []string{"https://localhost"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := creds.Insert(ctx, "acc", store.DecodedCredential{
			CredentialID: dec.CredentialID, PublicKeyCOSE: dec.PublicKeyCOSE, BaseLabel: row,
			AuthorizedKeysEntry: dec.AuthorizedKeysEntry,
		}, store.CredentialStateActive, row); err != nil {
			t.Fatal(err)
		}
	}
	d := &Deps{Credentials: creds, FileKeys: staticSigners{}, RpID: "localhost"}
	labels := func() []string {
		ids, err := d.buildIdentities(ctx, "acc")
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, id := range ids {
			out = append(out, id.Label)
		}
		return out
	}
	if got := labels(); len(got) != 2 || got[0] != "first" || got[1] != "second" {
		t.Fatalf("initial identities = %v", got)
	}
	if err := creds.Reorder(ctx, "acc", []string{"second", "first"}); err != nil {
		t.Fatal(err)
	}
	if got := labels(); len(got) != 2 || got[0] != "second" || got[1] != "first" {
		t.Fatalf("after reorder identities = %v", got)
	}
}
