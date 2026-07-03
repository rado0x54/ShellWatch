// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Package signagent is the read-only ssh/agent.Agent whose every sign — file
// key or passkey — is routed through the pending-action broker for human
// approval. Shared by the agent-proxy WebSocket (source="agent-proxy") and the
// terminal SSH connection's agent forwarding (source="agent-forwarding").
package signagent

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/rado0x54/shellwatch/internal/approval"
	"github.com/rado0x54/shellwatch/internal/signing"
)

// Identity is one key the agent offers.
type Identity struct {
	// Signer is set for file keys (signed directly after approval).
	Signer ssh.Signer
	// Passkey fields (webauthn-sk): PublicKey is presented; signing goes
	// through the broker.
	PublicKey    ssh.PublicKey
	IsPasskey    bool
	CredentialID string
	Label        string
	RpID         string
}

// Broker is the slice of the pending-action broker the agent needs (satisfied
// by *approval.Broker and the sshx.SignBroker facade).
type Broker interface {
	RequestSign(ctx context.Context, accountID string, req signing.SignRequest, actionCtx approval.Context, redirectTo string) (signing.SignResponse, error)
	RequestKeyApproval(ctx context.Context, accountID, keyLabel, keyFingerprint, connectionID string, actionCtx approval.Context) error
}

// Agent is the broker-backed read-only ssh/agent.Agent.
type Agent struct {
	ctx          context.Context
	identities   []Identity
	broker       Broker
	accountID    string
	connectionID string
	actionCtx    approval.Context
	// signMu serializes approvals: agent forwarding serves each auth-agent
	// channel in its own goroutine (x/crypto's ForwardToAgent), so without this
	// a remote offering several keys would pop every approval toast at once.
	// One pending approval at a time; a deny falls through to the next key.
	signMu sync.Mutex
}

// New builds a broker-backed agent. actionCtx carries the source (agent-proxy /
// agent-forwarding) and endpoint/session metadata surfaced on the /sign page.
func New(ctx context.Context, identities []Identity, broker Broker, accountID, connectionID string, actionCtx approval.Context) *Agent {
	return &Agent{ctx: ctx, identities: identities, broker: broker, accountID: accountID, connectionID: connectionID, actionCtx: actionCtx}
}

var _ agent.Agent = (*Agent)(nil)

func (a *Agent) List() ([]*agent.Key, error) {
	keys := make([]*agent.Key, 0, len(a.identities))
	for _, id := range a.identities {
		pub := id.PublicKey
		if pub == nil && id.Signer != nil {
			pub = id.Signer.PublicKey()
		}
		if pub == nil {
			continue
		}
		keys = append(keys, &agent.Key{Format: pub.Type(), Blob: pub.Marshal(), Comment: id.Label})
	}
	return keys, nil
}

func (a *Agent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	id := a.match(key)
	if id == nil {
		return nil, fmt.Errorf("agent: key not found")
	}
	// One approval prompt at a time across concurrent forwarded channels.
	a.signMu.Lock()
	defer a.signMu.Unlock()
	if id.IsPasskey {
		resp, err := a.broker.RequestSign(a.ctx, a.accountID, signing.SignRequest{
			CredentialID: id.CredentialID, DataToSign: data, RpID: id.RpID, PasskeyLabel: id.Label,
			ConnectionID: a.connectionID,
		}, a.actionCtx, "")
		if err != nil {
			return nil, err
		}
		return signing.BuildSSHSignature(resp)
	}
	fp := ssh.FingerprintSHA256(id.Signer.PublicKey())
	if err := a.broker.RequestKeyApproval(a.ctx, a.accountID, id.Label, fp, a.connectionID, a.actionCtx); err != nil {
		return nil, err
	}
	return id.Signer.Sign(nil, data)
}

// match finds the identity for an offered key, tolerating the OpenSSH 10.3
// webauthn-sk -> sk-ecdsa canonicalization (the offered blob may be the sk form).
func (a *Agent) match(key ssh.PublicKey) *Identity {
	want := key.Marshal()
	for i := range a.identities {
		id := &a.identities[i]
		pub := id.PublicKey
		if pub == nil && id.Signer != nil {
			pub = id.Signer.PublicKey()
		}
		if pub == nil {
			continue
		}
		if bytes.Equal(pub.Marshal(), want) {
			return id
		}
		if id.IsPasskey && bytes.Equal(canonicalizeSK(pub.Marshal()), canonicalizeSK(want)) {
			return id
		}
	}
	return nil
}

func canonicalizeSK(blob []byte) []byte {
	const wa = "webauthn-sk-ecdsa-sha2-nistp256@openssh.com"
	const sk = "sk-ecdsa-sha2-nistp256@openssh.com"
	if len(blob) < 4 {
		return blob
	}
	typeLen := int(blob[0])<<24 | int(blob[1])<<16 | int(blob[2])<<8 | int(blob[3])
	if typeLen+4 > len(blob) {
		return blob
	}
	if string(blob[4:4+typeLen]) != wa {
		return blob
	}
	rest := blob[4+typeLen:]
	out := make([]byte, 0, 4+len(sk)+len(rest))
	out = append(out, byte(len(sk)>>24), byte(len(sk)>>16), byte(len(sk)>>8), byte(len(sk)))
	out = append(out, sk...)
	out = append(out, rest...)
	return out
}

func (a *Agent) SignWithFlags(key ssh.PublicKey, data []byte, _ agent.SignatureFlags) (*ssh.Signature, error) {
	return a.Sign(key, data)
}

func (a *Agent) Add(agent.AddedKey) error       { return errReadOnly }
func (a *Agent) Remove(ssh.PublicKey) error     { return errReadOnly }
func (a *Agent) RemoveAll() error               { return errReadOnly }
func (a *Agent) Lock([]byte) error              { return errReadOnly }
func (a *Agent) Unlock([]byte) error            { return errReadOnly }
func (a *Agent) Signers() ([]ssh.Signer, error) { return nil, errReadOnly }
func (a *Agent) Extension(string, []byte) ([]byte, error) {
	return nil, agent.ErrExtensionUnsupported
}

var errReadOnly = fmt.Errorf("agent is read-only")

// PasskeyIdentity builds an Identity from a stored OpenSSH webauthn-sk line.
func PasskeyIdentity(authorizedKeysLine, credentialID, label, rpID string) (Identity, error) {
	fields := strings.Fields(authorizedKeysLine)
	if len(fields) < 2 {
		return Identity{}, fmt.Errorf("invalid authorized_keys line")
	}
	blob, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		return Identity{}, err
	}
	return Identity{
		PublicKey: skPublicKey{blob: blob}, IsPasskey: true,
		CredentialID: credentialID, Label: label, RpID: rpID,
	}, nil
}

type skPublicKey struct{ blob []byte }

func (k skPublicKey) Type() string    { return signing.WebAuthnSKAlgo }
func (k skPublicKey) Marshal() []byte { return k.blob }
func (k skPublicKey) Verify([]byte, *ssh.Signature) error {
	return fmt.Errorf("server-side verification only")
}
