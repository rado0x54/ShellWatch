// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
package seed

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/rado0x54/shellwatch/internal/config"
	"github.com/rado0x54/shellwatch/internal/store"
)

func TestFromConfigSeedsAccountPasskeyEndpoint(t *testing.T) {
	db, err := store.Open("sqlite::memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := store.Migrate(db); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	cfg := &config.Config{}
	cfg.Security.RpID = "localhost"
	cfg.SeedAdminPasskeys = []config.SeedAdminPasskey{{
		CredentialID: "cred-seed-1",
		// A valid COSE ES256/P-256 key (converts to an OpenSSH sk line).
		PublicKeyHex: "a5010203262001215820dbaa06c66c0198fd9231537903c60e812920dc7725d4e32dc783ef3b7a676979225820" +
			"1c546c3a50605d17bae851b5ba9c5b334568d3f1105d5b5ad186f3d9f337cc3f",
		Counter: 0, Transports: []string{"internal"}, Label: "Seed Key",
	}}
	cfg.SeedAdminEndpoints = []config.SeedEndpoint{{
		Label: "Box", Address: "u@h:22", Parsed: config.EndpointAddress{Username: "u", Host: "h", Port: 22},
	}}

	n := 0
	newID := func() string { n++; return "id-" + string(rune('a'+n)) }
	res, err := FromConfig(ctx, db, cfg, newID, time.Date(2026, 7, 3, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if !res.SeededAdminAccount || !res.SeededAdminPasskey {
		t.Fatalf("expected account+passkey seeded, got %+v", res)
	}

	// Admin account + designation.
	var name string
	if err := db.QueryRowContext(ctx, `SELECT a.name FROM accounts a JOIN admin_account m ON m.account_id=a.id WHERE m.singleton=1`).Scan(&name); err != nil || name != "admin" {
		t.Fatalf("admin account: name=%q err=%v", name, err)
	}
	// Passkey active + OpenSSH line derived.
	var state, openssh string
	if err := db.QueryRowContext(ctx, `SELECT state, public_key_openssh FROM webauthn_credentials WHERE credential_id='cred-seed-1'`).Scan(&state, &openssh); err != nil {
		t.Fatal(err)
	}
	if state != "active" {
		t.Errorf("seeded passkey state = %q, want active", state)
	}
	if !strings.HasPrefix(openssh, "webauthn-sk-ecdsa-sha2-nistp256@openssh.com ") {
		t.Errorf("expected derived webauthn-sk OpenSSH line, got %q", openssh)
	}
	// Endpoint.
	var eps int
	db.QueryRowContext(ctx, `SELECT COUNT(*) FROM endpoints`).Scan(&eps)
	if eps != 1 {
		t.Errorf("endpoints seeded = %d, want 1", eps)
	}

	// Idempotent: a second run adds nothing.
	res2, err := FromConfig(ctx, db, cfg, newID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if res2.SeededAdminAccount || res2.SeededAdminPasskey {
		t.Errorf("second run should be a no-op, got %+v", res2)
	}
	var creds int
	db.QueryRowContext(ctx, `SELECT COUNT(*) FROM webauthn_credentials`).Scan(&creds)
	if creds != 1 {
		t.Errorf("passkey count after re-seed = %d, want 1", creds)
	}
}
