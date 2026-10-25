// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Agent-proxy integration (Phase 4 slice 4): a real ssh/agent client over the
// framed WebSocket lists identities and performs an approval-gated file-key
// sign end-to-end. File-key signatures are verifiable in-process; the passkey
// path reuses the broker+signer chain proven in sshx.
package agentproxy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/rado0x54/shellwatch/internal/approval"
	"github.com/rado0x54/shellwatch/internal/auth"
	"github.com/rado0x54/shellwatch/internal/clock"
	"github.com/rado0x54/shellwatch/internal/store"
)

// staticSigners implements FileKeySource.
type staticSigners struct{ signers []ssh.Signer }

func (s staticSigners) Signers() ([]ssh.Signer, error) { return s.signers, nil }

// noCreds implements the Credentials dependency with no passkeys.
// (route.Deps.Credentials is *store.Credentials; the test needs a DB, so we
// use an in-memory store below instead of a fake.)

func TestAgentProxyListAndFileKeySign(t *testing.T) {
	// A throwaway ed25519 file key the proxy offers + signs with.
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}

	actionStore := approval.NewStore(clock.Real{}, func() string { return "act" })
	broker := approval.NewBroker(actionStore, func() string { return "https://sw.example" })

	deps := &Deps{
		Broker:      broker,
		Credentials: emptyCreds{},
		FileKeys:    staticSigners{signers: []ssh.Signer{signer}},
		RpID:        "localhost",
	}

	// Serve /agent-proxy behind a fake gate that injects an authenticated
	// principal (the real bearer gate is exercised in httpserver tests).
	handler := auth.WithPrincipal(deps.Handler(), auth.Principal{AccountID: "acc", Scopes: []string{"agent"}})
	ts := httptest.NewServer(handler)
	defer ts.Close()

	// Approver: resolve the key-approve action when it appears.
	go func() {
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			if a := actionStore.Get("act"); a != nil {
				actionStore.ResolveKey("act")
				return
			}
			time.Sleep(2 * time.Millisecond)
		}
	}()

	url := "ws" + strings.TrimPrefix(ts.URL, "http") + "/agent-proxy"
	wsc, _, err := websocket.Dial(context.Background(), url, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer wsc.Close(websocket.StatusNormalClosure, "")
	wsc.SetReadLimit(-1)

	rw := newWSReadWriter(context.Background(), wsc)
	client := agent.NewClient(rw)

	keys, err := client.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(keys) != 1 || keys[0].Format != signer.PublicKey().Type() {
		t.Fatalf("unexpected identities: %+v", keys)
	}

	data := []byte("agent-sign-payload")
	sig, err := client.Sign(signer.PublicKey(), data)
	if err != nil {
		t.Fatalf("approval-gated sign: %v", err)
	}
	// File-key signature is verifiable in-process.
	if err := signer.PublicKey().Verify(data, sig); err != nil {
		t.Fatalf("signature verification: %v", err)
	}
}

// emptyCreds satisfies CredentialLister with no passkeys (this test exercises
// the file-key path; the passkey signing chain is proven in sshx).
type emptyCreds struct{}

func (emptyCreds) ActiveCredentialsForAuth(context.Context, string) ([]store.AuthCredential, error) {
	return nil, nil
}
