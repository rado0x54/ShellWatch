// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Endpoint passkey-auth factory (Phase 4 slice 3, W1 completion). The full
// connection against a webauthn-sk key can only be verified by real OpenSSH
// (x/crypto can't parse the type server-side — the #69999 gap the Phase 0
// spike covered). So this proves the factory wiring in-process: it builds one
// approval-gated WebAuthnSigner per credential with the endpoint-auth context,
// and signing fires a human-approval request whose resolution yields a valid
// SSH signature.
package sshx

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/rado0x54/shellwatch/internal/approval"
	"github.com/rado0x54/shellwatch/internal/clock"
	"github.com/rado0x54/shellwatch/internal/signing"
	"github.com/rado0x54/shellwatch/internal/store"
	"github.com/rado0x54/shellwatch/internal/terminal"
	"github.com/rado0x54/shellwatch/internal/webauthn"
	"github.com/rado0x54/shellwatch/internal/webauthntest"
)

type fakeCredSource struct{ cred store.AuthCredential }

func (f fakeCredSource) ActiveCredentialsForAuth(context.Context, string) ([]store.AuthCredential, error) {
	return []store.AuthCredential{f.cred}, nil
}

func TestPasskeyFactoryBuildsApprovalGatedSigners(t *testing.T) {
	const rpID = "localhost"
	fake, err := webauthntest.New(webauthntest.Options{RpID: rpID, Origin: "https://localhost"})
	if err != nil {
		t.Fatal(err)
	}
	dec := registerFake(t, fake, rpID)

	actionStore := approval.NewStore(clock.Real{}, func() string { return "act" })
	broker := approval.NewBroker(actionStore, func() string { return "https://sw.example" })
	p := PasskeyFactoryParams{
		BrokerFunc:  func() SignBroker { return broker },
		Credentials: fakeCredSource{cred: store2Cred(dec)},
		RpID:        rpID,
	}

	fp := terminal.FactoryParams{
		Endpoint: terminal.EndpointRef{ID: "e1", AccountID: "acc", Host: "h", Port: 2222,
			Username: "ubuntu", UserVerification: "required"},
		Trigger: terminal.Trigger{Kind: terminal.SourceMCP, Reason: "deploy", SourceIP: "1.2.3.4"},
	}
	signers, err := p.buildSigners(context.Background(), fp, "conn-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(signers) != 1 {
		t.Fatalf("expected 1 signer, got %d", len(signers))
	}
	wa, ok := signers[0].(*WebAuthnSigner)
	if !ok {
		t.Fatalf("signer is %T, want *WebAuthnSigner", signers[0])
	}
	if wa.PublicKey().Type() != signing.WebAuthnSKAlgo {
		t.Errorf("pubkey type: %s", wa.PublicKey().Type())
	}
	if wa.ActionCtx.Source != "endpoint-auth" || wa.ActionCtx.EndpointAddress != "ubuntu@h:2222" {
		t.Errorf("action context: %+v", wa.ActionCtx)
	}
	if wa.CredentialID != dec.CredentialID || wa.ConnectionID != "conn-1" || wa.UVPolicy != "required" {
		t.Errorf("signer wiring: %+v", wa)
	}

	// Signing fires a human-approval request; resolving it yields a valid sig.
	go func() {
		a := pollAction(actionStore, "act")
		if a == nil {
			return
		}
		if a.Context.Source != "endpoint-auth" || a.Context.MCPReason != "deploy" {
			return
		}
		rawData, _ := base64.StdEncoding.DecodeString(a.Challenge)
		challenge := base64.RawURLEncoding.EncodeToString(rawData)
		authData, sig, cdj := splitAssertion(fake.Authenticate(challenge))
		actionStore.ResolveSign("act", signing.SignResponse{AuthenticatorData: authData, Signature: sig, ClientDataJSON: cdj})
	}()

	data := []byte("ssh-signing-payload")
	sshSig, err := wa.Sign(nil, data)
	if err != nil {
		t.Fatalf("approval-gated sign failed: %v", err)
	}
	if sshSig.Format != signing.WebAuthnSKAlgo {
		t.Errorf("signature format: %s", sshSig.Format)
	}
	verifyWebauthnSKSignature(t, fake.ECDSAPublicKey(), rpID, sshSig.Blob, sshSig.Rest)
}

func registerFake(t *testing.T, fake *webauthntest.Authenticator, rpID string) *webauthn.DecodedRegistration {
	t.Helper()
	challenge := base64.RawURLEncoding.EncodeToString([]byte("reg-challenge-1234567890"))
	dec, err := webauthn.VerifyRegistration(fake.Register(challenge), challenge, rpID, []string{"https://localhost"})
	if err != nil {
		t.Fatalf("register fake: %v", err)
	}
	return dec
}

func store2Cred(dec *webauthn.DecodedRegistration) store.AuthCredential {
	return store.AuthCredential{
		RowID: "row1", CredentialID: dec.CredentialID,
		PublicKeyOpenSSH: dec.AuthorizedKeysEntry, Label: "Test Passkey",
	}
}

func pollAction(s *approval.Store, id string) *approval.Action {
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if a := s.Get(id); a != nil {
			return a
		}
		time.Sleep(2 * time.Millisecond)
	}
	return nil
}

func splitAssertion(raw []byte) (authData, sig, cdj []byte) {
	var m struct {
		Response struct {
			ClientDataJSON    string `json:"clientDataJSON"`
			AuthenticatorData string `json:"authenticatorData"`
			Signature         string `json:"signature"`
		} `json:"response"`
	}
	_ = json.Unmarshal(raw, &m)
	authData, _ = base64.RawURLEncoding.DecodeString(m.Response.AuthenticatorData)
	sig, _ = base64.RawURLEncoding.DecodeString(m.Response.Signature)
	cdj, _ = base64.RawURLEncoding.DecodeString(m.Response.ClientDataJSON)
	return
}
