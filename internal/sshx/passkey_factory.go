// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Passkey-capable transport factory (completes the create-factory.ts
// decomposition, W1). Builds one WebAuthnSigner per account passkey — each
// wired to the broker with an endpoint-auth context — plus the file-key
// signers, and dials offering all of them. This is where a session open
// against a passkey endpoint triggers a human approval prompt.
package sshx

import (
	"context"
	"fmt"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/rado0x54/shellwatch/internal/approval"
	"github.com/rado0x54/shellwatch/internal/signagent"
	"github.com/rado0x54/shellwatch/internal/store"
	"github.com/rado0x54/shellwatch/internal/terminal"
)

// CredentialSource yields an account's active passkeys for SSH auth.
type CredentialSource interface {
	ActiveCredentialsForAuth(ctx context.Context, accountID string) ([]store.AuthCredential, error)
}

// PasskeyFactoryParams configure the passkey-capable factory.
type PasskeyFactoryParams struct {
	// BrokerFunc yields the sign broker lazily — the broker depends on the WS
	// hub, which depends on the manager, which depends on this factory, so the
	// broker is resolved at session-open time, not at construction.
	BrokerFunc  func() SignBroker
	Credentials CredentialSource
	FileKeys    SignerSource // optional (admin-only file keys)
	RpID        string
	// Origin placed in the WebAuthn ceremony; the browser overrides it, but
	// the signer records it for the clientDataJSON the assertion carries.
	Origin string
	// NewConnectionID mints per-connection ids so a dead connection's stranded
	// approvals can be cancelled (broker.CancelForConnection).
	NewConnectionID func() string
}

// NewPasskeyFactory builds a TransportFactory that authenticates with the
// account's passkeys (approval-gated) and, when present, file keys.
func NewPasskeyFactory(p PasskeyFactoryParams) terminal.TransportFactory {
	return func(ctx context.Context, fp terminal.FactoryParams) (terminal.Transport, error) {
		connID := "conn"
		if p.NewConnectionID != nil {
			connID = p.NewConnectionID()
		}
		signers, err := p.buildSigners(ctx, fp, connID)
		if err != nil {
			return nil, err
		}
		if len(signers) == 0 {
			return nil, fmt.Errorf("no credentials available for endpoint %s", fp.Endpoint.ID)
		}
		var fwdAgent agent.Agent
		if fp.Endpoint.AgentForward {
			fwdAgent = p.buildForwardingAgent(ctx, fp, connID)
		}
		return Connect(ctx, ConnectParams{
			Host: fp.Endpoint.Host, Port: fp.Endpoint.Port, Username: fp.Endpoint.Username,
			Signers: signers, AgentForward: fp.Endpoint.AgentForward, ForwardingAgent: fwdAgent,
		})
	}
}

func (p PasskeyFactoryParams) buildSigners(ctx context.Context, fp terminal.FactoryParams, connID string) ([]ssh.Signer, error) {
	var signers []ssh.Signer

	creds, err := p.Credentials.ActiveCredentialsForAuth(ctx, fp.Endpoint.AccountID)
	if err != nil {
		return nil, err
	}
	actionCtx := approval.Context{
		Source:          "endpoint-auth",
		EndpointLabel:   fp.Endpoint.Label,
		EndpointAddress: fmt.Sprintf("%s@%s:%d", fp.Endpoint.Username, fp.Endpoint.Host, fp.Endpoint.Port),
		TriggerKind:     string(fp.Trigger.Kind),
		SourceIP:        fp.Trigger.SourceIP,
		MCPReason:       fp.Trigger.Reason,
		MCPClientName:   fp.Trigger.MCPClientName,
		MCPClientVer:    fp.Trigger.MCPClientVer,
	}
	for _, c := range creds {
		pub, err := parseWebauthnPublicKey(c.PublicKeyOpenSSH)
		if err != nil {
			continue // unparseable line -> skip this credential
		}
		signers = append(signers, &WebAuthnSigner{
			Pub: pub, Broker: p.BrokerFunc(), AccountID: fp.Endpoint.AccountID,
			CredentialID: c.CredentialID, RpID: p.RpID, Origin: p.Origin,
			UVPolicy: fp.Endpoint.UserVerification, PasskeyLabel: c.Label,
			ConnectionID: connID, ActionCtx: actionCtx, Ctx: ctx,
		})
	}

	// File keys (admin) are offered after passkeys.
	if p.FileKeys != nil {
		fileSigners, err := p.FileKeys.Signers()
		if err == nil {
			signers = append(signers, fileSigners...)
		}
	}
	return signers, nil
}

// buildForwardingAgent assembles the broker-backed agent served over the
// remote's forwarded auth-agent channel. Same identities as connection auth
// (passkeys + file keys), but signs carry source="agent-forwarding" + the
// session id so the /sign page attributes forwarded signs correctly.
//
// NOTE: the sign-wait context is context.Background(), NOT the passed ctx.
// Forwarded signs happen long after the connection handshake — whenever the
// remote uses the agent — but ctx here is the session-create (request) context,
// which is already cancelled by then. Using it made every forwarded sign fail
// immediately with "context canceled". Stranded approvals are bounded by the
// 60s action TTL (and the per-connection cancel when the session tears down).
func (p PasskeyFactoryParams) buildForwardingAgent(_ context.Context, fp terminal.FactoryParams, connID string) agent.Agent {
	ctx := context.Background()
	var identities []signagent.Identity
	if p.FileKeys != nil {
		if fileSigners, err := p.FileKeys.Signers(); err == nil {
			for _, s := range fileSigners {
				identities = append(identities, signagent.Identity{Signer: s, Label: "file key"})
			}
		}
	}
	if creds, err := p.Credentials.ActiveCredentialsForAuth(ctx, fp.Endpoint.AccountID); err == nil {
		for _, c := range creds {
			id, err := signagent.PasskeyIdentity(c.PublicKeyOpenSSH, c.CredentialID, c.Label, p.RpID)
			if err == nil {
				identities = append(identities, id)
			}
		}
	}
	if len(identities) == 0 {
		return nil
	}
	actionCtx := approval.Context{
		Source:          "agent-forwarding",
		EndpointLabel:   fp.Endpoint.Label,
		EndpointAddress: fmt.Sprintf("%s@%s:%d", fp.Endpoint.Username, fp.Endpoint.Host, fp.Endpoint.Port),
		SessionID:       fp.SessionID,
	}
	return signagent.New(ctx, identities, p.BrokerFunc(), fp.Endpoint.AccountID, connID, actionCtx)
}
