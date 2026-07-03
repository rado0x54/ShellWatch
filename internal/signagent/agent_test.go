// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
package signagent

import (
	"context"
	"crypto/ed25519"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/rado0x54/shellwatch/internal/approval"
	"github.com/rado0x54/shellwatch/internal/signing"
)

type fakeBroker struct {
	signCtx    approval.Context
	approveCtx approval.Context
	signed     bool
	approved   bool
}

func (f *fakeBroker) RequestSign(_ context.Context, _ string, _ signing.SignRequest, ctx approval.Context, _ string) (signing.SignResponse, error) {
	f.signed = true
	f.signCtx = ctx
	return signing.SignResponse{AuthenticatorData: []byte{0x04}, Signature: []byte("s"), ClientDataJSON: []byte("{}")}, nil
}

func (f *fakeBroker) RequestKeyApproval(_ context.Context, _, _, _, _ string, ctx approval.Context) error {
	f.approved = true
	f.approveCtx = ctx
	return nil
}

func TestAgentRoutesFileKeyThroughApproval(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	signer, _ := ssh.NewSignerFromKey(priv)
	fb := &fakeBroker{}
	a := New(context.Background(), []Identity{{Signer: signer, Label: "file key"}}, fb,
		"acc", "conn", approval.Context{Source: "agent-forwarding", SessionID: "sess_1"})

	keys, _ := a.List()
	if len(keys) != 1 {
		t.Fatalf("List: got %d keys", len(keys))
	}
	if _, err := a.Sign(signer.PublicKey(), []byte("data")); err != nil {
		t.Fatal(err)
	}
	if !fb.approved || fb.approveCtx.Source != "agent-forwarding" || fb.approveCtx.SessionID != "sess_1" {
		t.Errorf("file-key sign should route through RequestKeyApproval with agent-forwarding ctx: %+v", fb.approveCtx)
	}
}

func TestPasskeyIdentitySignRoutesToBroker(t *testing.T) {
	// A minimal webauthn-sk authorized_keys line (blob content is opaque here).
	line := "sk-ecdsa-sha2-nistp256@openssh.com AAAAInNrLWVjZHNhAAAACG5pc3RwMjU2 test"
	id, err := PasskeyIdentity(line, "cred-1", "YubiKey", "localhost")
	if err != nil {
		t.Fatal(err)
	}
	if !id.IsPasskey || id.CredentialID != "cred-1" {
		t.Fatalf("PasskeyIdentity: %+v", id)
	}
	fb := &fakeBroker{}
	a := New(context.Background(), []Identity{id}, fb, "acc", "conn",
		approval.Context{Source: "agent-forwarding"})
	// The downstream BuildSSHSignature is exercised elsewhere; here we only care
	// that the passkey sign was routed to the broker with the forwarding context.
	_, _ = a.Sign(id.PublicKey, []byte("data"))
	if !fb.signed || fb.signCtx.Source != "agent-forwarding" {
		t.Errorf("passkey sign should route through RequestSign with agent-forwarding ctx: %+v", fb.signCtx)
	}
}
