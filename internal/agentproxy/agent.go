// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
package agentproxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/rado0x54/shellwatch/internal/approval"
	"github.com/rado0x54/shellwatch/internal/signing"
)

// Identity is one key the proxy agent offers.
type Identity struct {
	// Signer is set for file keys (the proxy signs after approval).
	Signer ssh.Signer
	// Passkey fields (webauthn-sk): PublicKey is presented; signing goes
	// through the broker.
	PublicKey    ssh.PublicKey
	IsPasskey    bool
	CredentialID string
	Label        string
	RpID         string
}

// brokerAgent is the read-only ssh/agent.Agent served over the WS. Every sign
// — file key or passkey — is routed through the pending-action broker.
type brokerAgent struct {
	ctx          context.Context
	identities   []Identity
	broker       *approval.Broker
	accountID    string
	connectionID string
	actionCtx    approval.Context
}

var _ agent.Agent = (*brokerAgent)(nil)

func (a *brokerAgent) List() ([]*agent.Key, error) {
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

func (a *brokerAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	id := a.match(key)
	if id == nil {
		return nil, fmt.Errorf("agent: key not found")
	}
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
	// File key: human approval, then the proxy signs.
	fp := ssh.FingerprintSHA256(id.Signer.PublicKey())
	if err := a.broker.RequestKeyApproval(a.ctx, a.accountID, id.Label, fp, a.connectionID, a.actionCtx); err != nil {
		return nil, err
	}
	return id.Signer.Sign(nil, data)
}

// match finds the identity for an offered key, tolerating the OpenSSH 10.3
// webauthn-sk -> sk-ecdsa canonicalization (the offered blob may be the sk
// form; we compare the canonicalized bytes).
func (a *brokerAgent) match(key ssh.PublicKey) *Identity {
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

// canonicalizeSK swaps a leading webauthn-sk-* type string to sk-* so the two
// forms compare equal (OpenSSH 10.3 sends the sk form in SIGN_REQUEST).
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
	typ := string(blob[4 : 4+typeLen])
	if typ != wa {
		return blob
	}
	rest := blob[4+typeLen:]
	out := make([]byte, 0, 4+len(sk)+len(rest))
	out = append(out, byte(len(sk)>>24), byte(len(sk)>>16), byte(len(sk)>>8), byte(len(sk)))
	out = append(out, sk...)
	out = append(out, rest...)
	return out
}

func (a *brokerAgent) SignWithFlags(key ssh.PublicKey, data []byte, _ agent.SignatureFlags) (*ssh.Signature, error) {
	return a.Sign(key, data)
}

// Read-only agent: mutation + lock operations are unsupported.
func (a *brokerAgent) Add(agent.AddedKey) error       { return errReadOnly }
func (a *brokerAgent) Remove(ssh.PublicKey) error     { return errReadOnly }
func (a *brokerAgent) RemoveAll() error               { return errReadOnly }
func (a *brokerAgent) Lock([]byte) error              { return errReadOnly }
func (a *brokerAgent) Unlock([]byte) error            { return errReadOnly }
func (a *brokerAgent) Signers() ([]ssh.Signer, error) { return nil, errReadOnly }
func (a *brokerAgent) Extension(string, []byte) ([]byte, error) {
	return nil, agent.ErrExtensionUnsupported
}

var errReadOnly = fmt.Errorf("agent is read-only")

// passkeyIdentity builds an Identity from a stored OpenSSH webauthn-sk line.
func passkeyIdentity(authorizedKeysLine, credentialID, label, rpID string) (Identity, error) {
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

// skPublicKey presents a stored webauthn-sk blob as an ssh.PublicKey.
type skPublicKey struct{ blob []byte }

func (k skPublicKey) Type() string    { return signing.WebAuthnSKAlgo }
func (k skPublicKey) Marshal() []byte { return k.blob }
func (k skPublicKey) Verify([]byte, *ssh.Signature) error {
	return fmt.Errorf("server-side verification only")
}

var _ = sha256.Sum256
