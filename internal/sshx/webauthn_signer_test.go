// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// End-to-end proof of the human-in-the-loop signing chain (Phase 4 slice 2):
// a WebAuthnSigner blocks on the broker, a human "approves" (the fake
// authenticator produces a real WebAuthn assertion), and the resulting
// ssh.Signature is cryptographically valid over the SSH signing payload.
//
// The Phase 0 spike already proved this wire format is accepted by real
// OpenSSH 10.3; this test proves the broker+signer+fake-auth chain produces a
// valid signature in that format, deterministically and without a live sshd.
package sshx

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"math/big"
	"testing"
	"time"

	"github.com/rado0x54/shellwatch/internal/approval"
	"github.com/rado0x54/shellwatch/internal/clock"
	"github.com/rado0x54/shellwatch/internal/signing"
	"github.com/rado0x54/shellwatch/internal/webauthntest"
)

func TestWebAuthnSignerEndToEnd(t *testing.T) {
	const rpID = "localhost"
	const origin = "https://localhost"
	fake, err := webauthntest.New(webauthntest.Options{RpID: rpID, Origin: origin})
	if err != nil {
		t.Fatal(err)
	}

	var idCounter int
	store := approval.NewStore(clock.Real{}, func() string {
		idCounter++
		return "act-1"
	})
	broker := approval.NewBroker(store, func() string { return "https://sw.example" })

	signer := &WebAuthnSigner{
		Broker: broker, AccountID: "acc", CredentialID: fake.CredentialID(),
		RpID: rpID, UVPolicy: "required",
		ActionCtx: approval.Context{Source: "endpoint-auth"},
	}

	data := []byte("the-ssh-signing-payload-bytes")

	// Sign blocks until the action is resolved.
	type result struct {
		blob, rest []byte
		format     string
		err        error
	}
	resCh := make(chan result, 1)
	go func() {
		sig, err := signer.Sign(nil, data)
		if err != nil {
			resCh <- result{err: err}
			return
		}
		resCh <- result{blob: sig.Blob, rest: sig.Rest, format: sig.Format}
	}()

	// Human approval: the browser decodes the action's std-base64 challenge to
	// bytes and the WebAuthn ceremony re-encodes it as base64url in
	// clientDataJSON. Replicate that exactly.
	action := waitForAction(t, store, "act-1")
	rawData, err := base64.StdEncoding.DecodeString(action.Challenge)
	if err != nil {
		t.Fatalf("action challenge not std-base64: %v", err)
	}
	b64urlChallenge := base64.RawURLEncoding.EncodeToString(rawData)
	assertion := fake.Authenticate(b64urlChallenge)

	authData, sig, cdj := parseAssertionResponse(t, assertion)
	if !store.ResolveSign("act-1", signing.SignResponse{
		AuthenticatorData: authData, Signature: sig, ClientDataJSON: cdj,
	}) {
		t.Fatal("ResolveSign returned false")
	}

	res := <-resCh
	if res.err != nil {
		t.Fatalf("Sign errored: %v", res.err)
	}
	if res.format != signing.WebAuthnSKAlgo {
		t.Fatalf("signature format: %s", res.format)
	}

	// The SSH signing payload the browser committed to must equal `data`.
	if b64urlChallenge != base64.RawURLEncoding.EncodeToString(data) {
		t.Fatal("challenge is not base64url of the signing payload")
	}

	// Cryptographic verification: rebuild authData the way OpenSSH does (from
	// the Rest's flags+counter and the rpId), then ECDSA-verify the Blob's R,S
	// over sha256(authData || sha256(clientDataJSON)).
	verifyWebauthnSKSignature(t, fake.ECDSAPublicKey(), rpID, res.blob, res.rest)
}

func TestWebAuthnSignerDenyPropagates(t *testing.T) {
	store := approval.NewStore(clock.Real{}, func() string { return "act-deny" })
	broker := approval.NewBroker(store, func() string { return "https://sw.example" })
	signer := &WebAuthnSigner{Broker: broker, AccountID: "acc", RpID: "localhost",
		ActionCtx: approval.Context{Source: "endpoint-auth"}}

	errCh := make(chan error, 1)
	go func() {
		_, err := signer.Sign(nil, []byte("data"))
		errCh <- err
	}()
	waitForAction(t, store, "act-deny")
	store.Deny("act-deny")
	if err := <-errCh; err != approval.ErrDenied {
		t.Fatalf("expected ErrDenied, got %v", err)
	}
}

func waitForAction(t *testing.T, store *approval.Store, id string) *approval.Action {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if a := store.Get(id); a != nil {
			return a
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("action never created")
	return nil
}

// parseAssertionResponse decodes the @simplewebauthn AuthenticationResponseJSON
// the fake authenticator produces.
func parseAssertionResponse(t *testing.T, raw []byte) (authData, sig, cdj []byte) {
	t.Helper()
	var m struct {
		Response struct {
			ClientDataJSON    string `json:"clientDataJSON"`
			AuthenticatorData string `json:"authenticatorData"`
			Signature         string `json:"signature"`
		} `json:"response"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	authData = b64urlDecode(t, m.Response.AuthenticatorData)
	sig = b64urlDecode(t, m.Response.Signature)
	cdj = b64urlDecode(t, m.Response.ClientDataJSON)
	return
}

func verifyWebauthnSKSignature(t *testing.T, pub *ecdsa.PublicKey, rpID string, blob, rest []byte) {
	t.Helper()
	// Blob = mpint R || mpint S.
	r, s := parseTwoMpints(t, blob)

	// Rest = flags(1) || counter(4) || string origin || string clientDataJSON || string extensions.
	if len(rest) < 5 {
		t.Fatal("rest too short")
	}
	flags := rest[0]
	counter := rest[1:5]
	p := rest[5:]
	_, p = readSSHString(t, p) // origin
	cdj, _ := readSSHString(t, p)

	// authData = sha256(rpId) || flags || counter (no extensions).
	rpHash := sha256.Sum256([]byte(rpID))
	authData := append(append(append([]byte{}, rpHash[:]...), flags), counter...)

	cdjHash := sha256.Sum256(cdj)
	digest := sha256.Sum256(append(append([]byte{}, authData...), cdjHash[:]...))
	if !ecdsa.Verify(pub, digest[:], r, s) {
		t.Fatal("webauthn-sk signature failed ECDSA verification")
	}
	_ = binary.BigEndian
}

func parseTwoMpints(t *testing.T, blob []byte) (*big.Int, *big.Int) {
	t.Helper()
	first, rest := readSSHString(t, blob)
	second, _ := readSSHString(t, rest)
	return new(big.Int).SetBytes(first), new(big.Int).SetBytes(second)
}

func readSSHString(t *testing.T, b []byte) (val, rest []byte) {
	t.Helper()
	if len(b) < 4 {
		t.Fatal("truncated ssh string")
	}
	n := binary.BigEndian.Uint32(b[:4])
	if int(n) > len(b)-4 {
		t.Fatal("ssh string length overflow")
	}
	return b[4 : 4+n], b[4+n:]
}

func b64urlDecode(t *testing.T, s string) []byte {
	t.Helper()
	d, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("b64url decode: %v", err)
	}
	return d
}
