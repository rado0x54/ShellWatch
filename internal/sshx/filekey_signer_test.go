// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// File-key connection auth is human-in-the-loop (H2) and admin-only + DB
// enabled + on-disk (H3).
package sshx

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"slices"
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

// unwrapFileKeySigner peels the algorithm-preserving wrappers off the
// approval gate (newApprovedFileKeySigner) for white-box assertions.
func unwrapFileKeySigner(t *testing.T, s ssh.Signer) *approvedFileKeySigner {
	t.Helper()
	switch v := s.(type) {
	case *approvedFileKeySigner:
		return v
	case *approvedFileKeyAlgoSigner:
		return v.approvedFileKeySigner
	case *approvedFileKeyMultiSigner:
		return v.approvedFileKeySigner
	}
	t.Fatalf("signer is %T, want an approved file-key signer", s)
	return nil
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
	fk := unwrapFileKeySigner(t, signers[0])
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
	fk := signers[0]

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
func (s stubKeyBroker) RequestKeyApproval(context.Context, approval.KeyApproval) error {
	return s.err
}

// An unanswered prompt (60s TTL expiry) surfaces as the broker's error; with
// file keys ordered before passkeys, Connect's per-key auth (auth.go) then
// moves on to the passkey instead of killing the connection
// (composite-ssh-agent.ts:146-151).
func TestFileKeyExpiryReturnsError(t *testing.T) {
	signer := newTestSigner(t)
	fk := &approvedFileKeySigner{signer: signer, broker: stubKeyBroker{err: approval.ErrExpired}, label: "k"}
	if _, err := fk.Sign(rand.Reader, []byte("payload")); !errors.Is(err, approval.ErrExpired) {
		t.Fatalf("expiry must return ErrExpired, got %v", err)
	}
}

func TestFileKeyContextDeathAborts(t *testing.T) {
	signer := newTestSigner(t)
	fk := &approvedFileKeySigner{signer: signer, broker: stubKeyBroker{err: context.Canceled}, label: "k"}
	if _, err := fk.Sign(rand.Reader, []byte("payload")); err == nil {
		t.Fatal("cancelled dial context must abort, not skip")
	}
}

func TestFileKeyDenyReturnsError(t *testing.T) {
	actionStore := approval.NewStore(clock.Real{}, func() string { return "act" })
	p, _ := fileKeyParams(t, true, actionStore)
	signers, _ := p.buildSigners(context.Background(), endpointFP(), "conn-1", p.fileKeysFor(context.Background(), "acc"))
	fk := signers[0]

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
	if _, err := fk.Sign(rand.Reader, []byte("payload")); !errors.Is(err, approval.ErrDenied) {
		t.Fatalf("deny must return ErrDenied, got %v", err)
	}
}

// The approval wrapper must preserve x/crypto's AlgorithmSigner /
// MultiAlgorithmSigner type-assertions: wrapped as a plain Signer, an RSA
// file key is forced down to ssh-rsa/SHA-1, which OpenSSH >= 8.8 rejects by
// default — auth would fail even after the human approved (review finding).
func TestFileKeySignerPreservesRSAAlgorithms(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	wrapped := newApprovedFileKeySigner(&approvedFileKeySigner{signer: signer, broker: stubKeyBroker{err: nil}, label: "rsa"})

	as, ok := wrapped.(ssh.AlgorithmSigner)
	if !ok {
		t.Fatalf("wrapped RSA signer is %T — not an AlgorithmSigner, x/crypto would downgrade to ssh-rsa/SHA-1", wrapped)
	}
	data := []byte("payload")
	sig, err := as.SignWithAlgorithm(rand.Reader, data, ssh.KeyAlgoRSASHA256)
	if err != nil {
		t.Fatalf("SignWithAlgorithm: %v", err)
	}
	if sig.Format != ssh.KeyAlgoRSASHA256 {
		t.Fatalf("signature format %q, want %q", sig.Format, ssh.KeyAlgoRSASHA256)
	}
	if ms, ok := wrapped.(ssh.MultiAlgorithmSigner); ok {
		if !slices.Contains(ms.Algorithms(), ssh.KeyAlgoRSASHA256) {
			t.Fatalf("Algorithms() = %v, missing %s", ms.Algorithms(), ssh.KeyAlgoRSASHA256)
		}
	}
}

// A denied approval must gate the algorithm-signing path exactly like Sign.
func TestFileKeySignWithAlgorithmRequiresApproval(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	wrapped := newApprovedFileKeySigner(&approvedFileKeySigner{signer: signer, broker: stubKeyBroker{err: approval.ErrDenied}, label: "rsa"})
	as := wrapped.(ssh.AlgorithmSigner)
	if _, err := as.SignWithAlgorithm(rand.Reader, []byte("payload"), ssh.KeyAlgoRSASHA256); !errors.Is(err, approval.ErrDenied) {
		t.Fatalf("denied SignWithAlgorithm must return ErrDenied, got %v", err)
	}
}
