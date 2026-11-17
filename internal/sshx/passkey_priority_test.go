// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Passkey priority order (#308): every signing path reads the account's
// passkeys once, in priority order. An endpoint that accepts two passkeys
// prompts for the higher-priority one first; after a reorder a NEW
// connection prompts for the other first, and an already open session's
// forwarding agent keeps the order it started with.
package sshx

import (
	"bytes"
	"context"
	"encoding/base64"
	"testing"
	"time"

	"golang.org/x/crypto/ssh/agent"

	"github.com/rado0x54/shellwatch/internal/approval"
	"github.com/rado0x54/shellwatch/internal/clock"
	"github.com/rado0x54/shellwatch/internal/signing"
	"github.com/rado0x54/shellwatch/internal/store"
	"github.com/rado0x54/shellwatch/internal/terminal"
	"github.com/rado0x54/shellwatch/internal/webauthntest"
)

type priorityFixture struct {
	creds       *store.Credentials
	actions     *approval.Store
	params      PasskeyFactoryParams
	fp          terminal.FactoryParams
	fakes       map[string]*webauthntest.Authenticator // by credential id
	pubByRow    map[string][]byte                      // row id -> marshalled ssh pubkey
	actionCount int
}

func newPriorityFixture(t *testing.T) *priorityFixture {
	t.Helper()
	const rpID = "localhost"
	db, err := store.Open("sqlite::memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := store.Migrate(db); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO accounts (id,name,created_at,updated_at) VALUES ('acc','A','t','t')`); err != nil {
		t.Fatal(err)
	}
	f := &priorityFixture{
		creds: store.NewCredentials(db, clock.Real{}), fakes: map[string]*webauthntest.Authenticator{},
		pubByRow: map[string][]byte{},
	}
	f.actions = approval.NewStore(clock.Real{}, func() string {
		f.actionCount++
		return "act-" + string(rune('0'+f.actionCount))
	})
	broker := approval.NewBroker(f.actions, func() string { return "https://sw.example" })
	f.params = PasskeyFactoryParams{
		BrokerFunc: func() SignBroker { return broker }, Credentials: f.creds, RpID: rpID,
	}
	f.fp = terminal.FactoryParams{
		Endpoint: terminal.EndpointRef{ID: "e1", AccountID: "acc", Host: "h", Port: 22,
			Username: "u", UserVerification: "required"},
	}
	for _, row := range []string{"first", "second"} {
		fake, err := webauthntest.New(webauthntest.Options{RpID: rpID, Origin: "https://localhost"})
		if err != nil {
			t.Fatal(err)
		}
		dec := registerFake(t, fake, rpID)
		if _, err := f.creds.Insert(context.Background(), "acc", store.DecodedCredential{
			CredentialID: dec.CredentialID, PublicKeyCOSE: dec.PublicKeyCOSE, BaseLabel: row,
			AuthorizedKeysEntry: dec.AuthorizedKeysEntry,
		}, store.CredentialStateActive, row); err != nil {
			t.Fatal(err)
		}
		f.fakes[dec.CredentialID] = fake
		pub, err := parseWebauthnPublicKey(dec.AuthorizedKeysEntry)
		if err != nil {
			t.Fatal(err)
		}
		f.pubByRow[row] = pub.Marshal()
	}
	return f
}

// firstPrompt builds a fresh connection's signers and returns the passkey
// label of the first sign prompt raised (the signer the AuthCallback hands to
// x/crypto first), answering it with the matching fake authenticator.
func (f *priorityFixture) firstPrompt(t *testing.T) string {
	t.Helper()
	signers, err := f.params.buildSigners(context.Background(), f.fp, "conn", nil, &HostKeyState{})
	if err != nil {
		t.Fatal(err)
	}
	if len(signers) != 2 {
		t.Fatalf("signers = %d, want 2", len(signers))
	}
	want := "act-" + string(rune('0'+f.actionCount+1))
	got := make(chan string, 1)
	go func() {
		a := pollAction(f.actions, want)
		if a == nil {
			got <- ""
			return
		}
		got <- a.PasskeyLabel
		raw, _ := base64.StdEncoding.DecodeString(a.Challenge)
		authData, sig, cdj := splitAssertion(f.fakes[a.CredentialID].Authenticate(base64.RawURLEncoding.EncodeToString(raw)))
		f.actions.ResolveSign(want, signing.SignResponse{AuthenticatorData: authData, Signature: sig, ClientDataJSON: cdj})
	}()
	if _, err := signers[0].Sign(nil, []byte("payload")); err != nil {
		t.Fatalf("sign: %v", err)
	}
	select {
	case label := <-got:
		return label
	case <-time.After(3 * time.Second):
		t.Fatal("no prompt raised")
		return ""
	}
}

func (f *priorityFixture) agentOrder(t *testing.T, keys []*agent.Key) []string {
	t.Helper()
	var out []string
	for _, k := range keys {
		for row, pub := range f.pubByRow {
			if bytes.Equal(k.Blob, pub) {
				out = append(out, row)
			}
		}
	}
	return out
}

func TestPasskeyPriorityOrdersPrompts(t *testing.T) {
	f := newPriorityFixture(t)
	ctx := context.Background()

	if got := f.firstPrompt(t); got != "first" {
		t.Fatalf("first prompt = %q, want the higher-priority passkey", got)
	}
	openAgent := f.params.buildForwardingAgent(f.fp, "conn-open", nil)

	if err := f.creds.Reorder(ctx, "acc", []string{"second", "first"}); err != nil {
		t.Fatal(err)
	}
	if got := f.firstPrompt(t); got != "second" {
		t.Fatalf("after reorder, first prompt = %q, want second", got)
	}

	// A new session's forwarding agent lists identities in the new order;
	// the already open one keeps the order it was created with.
	newKeys, err := f.params.buildForwardingAgent(f.fp, "conn-new", nil).List()
	if err != nil {
		t.Fatal(err)
	}
	if got := f.agentOrder(t, newKeys); len(got) != 2 || got[0] != "second" {
		t.Fatalf("new forwarding agent order = %v", got)
	}
	oldKeys, err := openAgent.List()
	if err != nil {
		t.Fatal(err)
	}
	if got := f.agentOrder(t, oldKeys); len(got) != 2 || got[0] != "first" {
		t.Fatalf("open forwarding agent order = %v, want unchanged", got)
	}
}
