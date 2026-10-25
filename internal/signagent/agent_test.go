// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
package signagent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

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

func (f *fakeBroker) RequestKeyApproval(_ context.Context, p approval.KeyApproval) error {
	f.approved = true
	f.approveCtx = p.Context
	return nil
}

func TestAgentRoutesFileKeyThroughApproval(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	signer, _ := ssh.NewSignerFromKey(priv)
	fb := &fakeBroker{}
	a := New(context.Background(), Params{
		Identities: []Identity{{Signer: signer, Label: "file key"}}, Broker: fb,
		AccountID: "acc", ConnectionID: "conn",
		ActionCtx: approval.Context{Source: "agent-forwarding", SessionID: "sess_1"},
	})

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
	a := New(context.Background(), Params{
		Identities: []Identity{id}, Broker: fb, AccountID: "acc", ConnectionID: "conn",
		ActionCtx: approval.Context{Source: "agent-forwarding"},
	})
	// The downstream BuildSSHSignature is exercised elsewhere; here we only care
	// that the passkey sign was routed to the broker with the forwarding context.
	_, _ = a.Sign(id.PublicKey, []byte("data"))
	if !fb.signed || fb.signCtx.Source != "agent-forwarding" {
		t.Errorf("passkey sign should route through RequestSign with agent-forwarding ctx: %+v", fb.signCtx)
	}
}

// Regression: SignWithFlags used to discard the rsa-sha2 flags, handing back
// an ssh-rsa/SHA-1 signature that OpenSSH >= 8.8 rejects by default — RSA
// file keys failed even after human approval. Flags must map to the
// rsa-sha2-256/512 algorithms; keys with a single algorithm are unaffected.
func TestSignWithFlagsHonorsRsaSha2(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	fb := &fakeBroker{}
	a := New(context.Background(), Params{
		Identities: []Identity{{Signer: signer, Label: "rsa key"}}, Broker: fb,
		AccountID: "acc", ConnectionID: "conn", ActionCtx: approval.Context{Source: "agent-proxy"},
	})

	data := []byte("payload")
	sig, err := a.SignWithFlags(signer.PublicKey(), data, agent.SignatureFlagRsaSha256)
	if err != nil {
		t.Fatal(err)
	}
	if sig.Format != ssh.KeyAlgoRSASHA256 {
		t.Fatalf("signature format %q, want %q", sig.Format, ssh.KeyAlgoRSASHA256)
	}
	if !fb.approved {
		t.Fatal("flagged sign skipped the human approval")
	}
	if err := verifyWithAlgo(signer.PublicKey(), data, sig); err != nil {
		t.Fatalf("rsa-sha2-256 signature invalid: %v", err)
	}

	sig512, err := a.SignWithFlags(signer.PublicKey(), data, agent.SignatureFlagRsaSha512)
	if err != nil {
		t.Fatal(err)
	}
	if sig512.Format != ssh.KeyAlgoRSASHA512 {
		t.Fatalf("signature format %q, want %q", sig512.Format, ssh.KeyAlgoRSASHA512)
	}
}

func verifyWithAlgo(pub ssh.PublicKey, data []byte, sig *ssh.Signature) error {
	return pub.Verify(data, sig)
}
