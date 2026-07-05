// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// File-key connection auth is human-in-the-loop (H2) and admin-only + DB
// enabled + on-disk (H3).
package sshx

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/rado0x54/shellwatch/internal/approval"
	"github.com/rado0x54/shellwatch/internal/clock"
	"github.com/rado0x54/shellwatch/internal/signing"
	"github.com/rado0x54/shellwatch/internal/store"
	"github.com/rado0x54/shellwatch/internal/terminal"
)

type emptyCreds struct{}

func (emptyCreds) ActiveCredentialsForAuth(context.Context, string) ([]store.AuthCredential, error) {
	return nil, nil
}

type fakeKeyProvider map[string]ssh.Signer

func (f fakeKeyProvider) SignerFor(fp string) (ssh.Signer, bool) {
	s, ok := f[fp]
	return s, ok
}

type fakeKeyLister []store.SSHKeyFull

func (f fakeKeyLister) ListFull(context.Context) ([]store.SSHKeyFull, error) { return f, nil }

func newTestSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func fileKeyParams(t *testing.T, isAdmin bool, actionStore *approval.Store) (PasskeyFactoryParams, ssh.Signer) {
	t.Helper()
	signer := newTestSigner(t)
	fp := ssh.FingerprintSHA256(signer.PublicKey())
	broker := approval.NewBroker(actionStore, func() string { return "https://sw.example" })
	return PasskeyFactoryParams{
		BrokerFunc:  func() SignBroker { return broker },
		Credentials: emptyCreds{},
		FileKeys:    fakeKeyProvider{fp: signer},
		Keys: fakeKeyLister{
			{ID: "k1", Label: "Deploy Key", Type: "file", Fingerprint: fp, Enabled: true},
			{ID: "k2", Label: "Disabled Key", Type: "file", Fingerprint: "SHA256:disabled", Enabled: false},
			{ID: "k3", Label: "Gone Key", Type: "file", Fingerprint: "SHA256:notondisk", Enabled: true},
		},
		IsAdmin: func(context.Context, string) bool { return isAdmin },
		RpID:    "localhost",
	}, signer
}

func endpointFP() terminal.FactoryParams {
	return terminal.FactoryParams{
		Endpoint: terminal.EndpointRef{ID: "e1", AccountID: "acc", Host: "h", Port: 22,
			Username: "root", UserVerification: "required"},
		Trigger: terminal.Trigger{Kind: terminal.SourceUI},
	}
}

func TestFileKeysNotOfferedToNonAdmin(t *testing.T) {
	actionStore := approval.NewStore(clock.Real{}, func() string { return "act" })
	p, _ := fileKeyParams(t, false, actionStore)
	signers, err := p.buildSigners(context.Background(), endpointFP(), "conn-1", p.fileKeysFor(context.Background(), "acc"))
	if err != nil {
		t.Fatal(err)
	}
	if len(signers) != 0 {
		t.Fatalf("non-admin got %d file-key signer(s), want 0", len(signers))
	}
}

func TestFileKeySelectionAdminEnabledOnDisk(t *testing.T) {
	actionStore := approval.NewStore(clock.Real{}, func() string { return "act" })
	p, _ := fileKeyParams(t, true, actionStore)
	signers, err := p.buildSigners(context.Background(), endpointFP(), "conn-1", p.fileKeysFor(context.Background(), "acc"))
	if err != nil {
		t.Fatal(err)
	}
	// Only the enabled + on-disk key survives (disabled + missing filtered).
	if len(signers) != 1 {
		t.Fatalf("expected 1 signer, got %d", len(signers))
	}
	fk, ok := signers[0].(*approvedFileKeySigner)
	if !ok {
		t.Fatalf("signer is %T, want *approvedFileKeySigner", signers[0])
	}
	if fk.label != "Deploy Key" || fk.accountID != "acc" || fk.connectionID != "conn-1" {
		t.Errorf("signer wiring: %+v", fk)
	}
	if fk.actionCtx.Source != "endpoint-auth" || fk.actionCtx.EndpointAddress != "root@h:22" {
		t.Errorf("action context: %+v", fk.actionCtx)
	}
}

func TestFileKeySignRequiresApproval(t *testing.T) {
	actionStore := approval.NewStore(clock.Real{}, func() string { return "act" })
	p, signer := fileKeyParams(t, true, actionStore)
	signers, _ := p.buildSigners(context.Background(), endpointFP(), "conn-1", p.fileKeysFor(context.Background(), "acc"))
	fk := signers[0].(*approvedFileKeySigner)

	// Approve path: the pending key-approve action resolves -> real signature.
	go func() {
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			if a := actionStore.Get("act"); a != nil {
				if a.Type != approval.TypeKeyApprove || a.KeyLabel != "Deploy Key" {
					return // wrong action shape; Sign will hang + test fails
				}
				actionStore.ResolveKey("act")
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()
	data := []byte("payload")
	sig, err := fk.Sign(rand.Reader, data)
	if err != nil {
		t.Fatalf("approved sign failed: %v", err)
	}
	if err := signer.PublicKey().Verify(data, sig); err != nil {
		t.Fatalf("signature invalid after approval: %v", err)
	}
}

// stubKeyBroker rejects every request with a fixed error.
type stubKeyBroker struct{ err error }

func (s stubKeyBroker) RequestSign(context.Context, string, signing.SignRequest, approval.Context, string) (signing.SignResponse, error) {
	return signing.SignResponse{}, s.err
}
func (s stubKeyBroker) RequestKeyApproval(context.Context, string, string, string, string, approval.Context) error {
	return s.err
}

// An unanswered prompt (60s TTL expiry) must skip to the next key, not abort
// the whole publickey method — with file keys ordered before passkeys, a hard
// error here would make an ignored prompt kill connections that should
// proceed via passkey (composite-ssh-agent.ts:146-151).
func TestFileKeyExpiryFallsThroughAsSkip(t *testing.T) {
	signer := newTestSigner(t)
	fk := &approvedFileKeySigner{signer: signer, broker: stubKeyBroker{err: approval.ErrExpired}, label: "k"}
	data := []byte("payload")
	sig, err := fk.Sign(rand.Reader, data)
	if err != nil {
		t.Fatalf("expiry must skip, not error: %v", err)
	}
	if err := signer.PublicKey().Verify(data, sig); err == nil {
		t.Fatal("expiry produced a valid signature")
	}
}

func TestFileKeyContextDeathAborts(t *testing.T) {
	signer := newTestSigner(t)
	fk := &approvedFileKeySigner{signer: signer, broker: stubKeyBroker{err: context.Canceled}, label: "k"}
	if _, err := fk.Sign(rand.Reader, []byte("payload")); err == nil {
		t.Fatal("cancelled dial context must abort, not skip")
	}
}

func TestFileKeyDenyFallsThroughAsSkip(t *testing.T) {
	actionStore := approval.NewStore(clock.Real{}, func() string { return "act" })
	p, signer := fileKeyParams(t, true, actionStore)
	signers, _ := p.buildSigners(context.Background(), endpointFP(), "conn-1", p.fileKeysFor(context.Background(), "acc"))
	fk := signers[0].(*approvedFileKeySigner)

	go func() {
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			if actionStore.Get("act") != nil {
				actionStore.Deny("act")
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()
	data := []byte("payload")
	sig, err := fk.Sign(rand.Reader, data)
	if err != nil {
		t.Fatalf("deny must skip, not error: %v", err)
	}
	// The skip signature must NOT verify — it exists to make the server move
	// to the next identity.
	if err := signer.PublicKey().Verify(data, sig); err == nil {
		t.Fatal("deny produced a valid signature")
	}
}
