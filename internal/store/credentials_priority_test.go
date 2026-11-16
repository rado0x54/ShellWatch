// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
package store

import (
	"context"
	"database/sql"
	"reflect"
	"testing"

	"github.com/pressly/goose/v3"

	"github.com/rado0x54/shellwatch/internal/clock"
)

const prioAcct = "acct-prio"

func prioDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := Open("sqlite::memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := Migrate(db); err != nil {
		t.Fatal(err)
	}
	mustExec(t, db, `INSERT INTO accounts (id,name,created_at,updated_at) VALUES (?,'A','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')`, prioAcct)
	mustExec(t, db, `INSERT INTO accounts (id,name,created_at,updated_at) VALUES ('acct-other','B','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')`)
	return db
}

func mustExec(t *testing.T, db *sql.DB, q string, args ...any) {
	t.Helper()
	if _, err := db.Exec(q, args...); err != nil {
		t.Fatalf("exec %q: %v", q, err)
	}
}

func insertCred(t *testing.T, c *Credentials, id, state string) {
	t.Helper()
	if _, err := c.Insert(context.Background(), prioAcct, DecodedCredential{
		CredentialID: "cid-" + id, PublicKeyCOSE: []byte{1}, BaseLabel: id,
		AuthorizedKeysEntry: "sk-ecdsa-sha2-nistp256@openssh.com AAAA " + id,
	}, state, id); err != nil {
		t.Fatal(err)
	}
}

func authOrder(t *testing.T, c *Credentials) []string {
	t.Helper()
	creds, err := c.ActiveCredentialsForAuth(context.Background(), prioAcct)
	if err != nil {
		t.Fatal(err)
	}
	out := []string{}
	for _, cr := range creds {
		out = append(out, cr.RowID)
	}
	return out
}

func priorities(t *testing.T, db *sql.DB) map[string]*int64 {
	t.Helper()
	rows, err := db.Query(`SELECT id, priority FROM webauthn_credentials`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]*int64{}
	for rows.Next() {
		var id string
		var p sql.NullInt64
		if err := rows.Scan(&id, &p); err != nil {
			t.Fatal(err)
		}
		out[id] = nip(p)
	}
	return out
}

func TestCredentialPriorityLifecycle(t *testing.T) {
	ctx := context.Background()
	db := prioDB(t)
	c := NewCredentials(db, clock.Real{})

	insertCred(t, c, "a", CredentialStateActive)
	insertCred(t, c, "b", CredentialStateActive)
	insertCred(t, c, "p", CredentialStatePendingConfirmation)
	if got := authOrder(t, c); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Fatalf("initial order = %v", got)
	}
	if p := priorities(t, db)["p"]; p != nil {
		t.Fatalf("pending credential has priority %d", *p)
	}

	if err := c.Reorder(ctx, prioAcct, []string{"b", "a"}); err != nil {
		t.Fatal(err)
	}
	if got := authOrder(t, c); !reflect.DeepEqual(got, []string{"b", "a"}) {
		t.Fatalf("after reorder = %v", got)
	}

	// Activation after a reorder lands at the bottom; so does a new one.
	if err := c.Activate(ctx, "p"); err != nil {
		t.Fatal(err)
	}
	insertCred(t, c, "n", CredentialStateActive)
	if got := authOrder(t, c); !reflect.DeepEqual(got, []string{"b", "a", "p", "n"}) {
		t.Fatalf("after activation + insert = %v", got)
	}

	// Revoking clears the priority; the rest keep their relative order.
	if err := c.Revoke(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	if p := priorities(t, db)["a"]; p != nil {
		t.Fatalf("revoked credential kept priority %d", *p)
	}
	if got := authOrder(t, c); !reflect.DeepEqual(got, []string{"b", "p", "n"}) {
		t.Fatalf("after revoke = %v", got)
	}

	// The full listing puts active passkeys first, in priority order.
	list, err := c.ListForAccountFull(ctx, prioAcct)
	if err != nil {
		t.Fatal(err)
	}
	ids := []string{}
	for _, cr := range list {
		ids = append(ids, cr.ID)
	}
	if !reflect.DeepEqual(ids, []string{"b", "p", "n", "a"}) {
		t.Fatalf("list order = %v", ids)
	}
}

func TestReorderRejectsInvalidLists(t *testing.T) {
	ctx := context.Background()
	db := prioDB(t)
	c := NewCredentials(db, clock.Real{})
	insertCred(t, c, "a", CredentialStateActive)
	insertCred(t, c, "b", CredentialStateActive)
	insertCred(t, c, "p", CredentialStatePendingConfirmation)
	insertCred(t, c, "r", CredentialStateActive)
	if err := c.Revoke(ctx, "r"); err != nil {
		t.Fatal(err)
	}
	mustExec(t, db, `INSERT INTO webauthn_credentials (id,account_id,credential_id,public_key,label,state,created_at,priority) VALUES ('f','acct-other','cid-f',x'01','f','active','2026-01-01T00:00:00Z',0)`)

	cases := []struct {
		name string
		ids  []string
	}{
		{"empty", []string{}},
		{"missing", []string{"a"}},
		{"extra pending", []string{"a", "b", "p"}},
		{"revoked", []string{"a", "b", "r"}},
		{"foreign", []string{"a", "b", "f"}},
		{"foreign swap", []string{"a", "f"}},
		{"duplicate", []string{"a", "a"}},
		{"duplicate full", []string{"b", "a", "a"}},
		{"unknown", []string{"a", "zzz"}},
	}
	before := priorities(t, db)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := c.Reorder(ctx, prioAcct, tc.ids)
			if !IsInvalidOrder(err) {
				t.Fatalf("Reorder(%v) err = %v, want ErrInvalidOrder", tc.ids, err)
			}
			if after := priorities(t, db); !reflect.DeepEqual(before, after) {
				t.Fatalf("priorities changed on rejection")
			}
		})
	}
}

// TestPriorityMigrationBackfill applies 00006 over rows created before it:
// per account, active non-revoked credentials get 0..n-1 by (created_at, id).
func TestPriorityMigrationBackfill(t *testing.T) {
	db, err := Open("sqlite::memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	goose.SetBaseFS(migrations)
	goose.SetLogger(goose.NopLogger())
	if err := goose.SetDialect("sqlite3"); err != nil {
		t.Fatal(err)
	}
	if err := goose.UpTo(db, "migrations", 5); err != nil {
		t.Fatal(err)
	}
	mustExec(t, db, `INSERT INTO accounts (id,name,created_at,updated_at) VALUES ('x','X','t','t'), ('y','Y','t','t')`)
	ins := func(id, acct, created, state string, revoked int) {
		mustExec(t, db, `INSERT INTO webauthn_credentials (id,account_id,credential_id,public_key,label,state,revoked,created_at) VALUES (?,?,?,x'01',?,?,?,?)`,
			id, acct, "cid-"+id, id, state, revoked, created)
	}
	ins("x3", "x", "2026-03-01", "active", 0)
	ins("x1", "x", "2026-01-01", "active", 0)
	ins("x2b", "x", "2026-02-01", "active", 0)
	ins("x2a", "x", "2026-02-01", "active", 0) // same created_at: id breaks the tie
	ins("xp", "x", "2026-01-15", "pending_confirmation", 0)
	ins("xr", "x", "2026-01-10", "active", 1)
	ins("y1", "y", "2026-05-01", "active", 0)
	if err := Migrate(db); err != nil {
		t.Fatal(err)
	}
	got := priorities(t, db)
	want := map[string]*int64{
		"x1": ptr(0), "x2a": ptr(1), "x2b": ptr(2), "x3": ptr(3),
		"xp": nil, "xr": nil, "y1": ptr(0),
	}
	if !reflect.DeepEqual(got, want) {
		for k, v := range got {
			if v == nil {
				t.Logf("%s: nil", k)
			} else {
				t.Logf("%s: %d", k, *v)
			}
		}
		t.Fatal("backfill mismatch")
	}
}

func ptr(v int64) *int64 { return &v }
