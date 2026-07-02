// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
package agentproxy

import (
	"context"
	"net/http"

	"github.com/coder/websocket"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/rado0x54/shellwatch/internal/approval"
	"github.com/rado0x54/shellwatch/internal/auth"
	"github.com/rado0x54/shellwatch/internal/store"
	"github.com/rado0x54/shellwatch/internal/util"
)

// FileKeySource yields the file-key signers offered on the proxy.
type FileKeySource interface {
	Signers() ([]ssh.Signer, error)
}

// CredentialLister yields an account's active passkeys (satisfied by
// *store.Credentials; an interface so tests can inject fakes).
type CredentialLister interface {
	ActiveCredentialsForAuth(ctx context.Context, accountID string) ([]store.AuthCredential, error)
}

// Deps wire the agent-proxy route.
type Deps struct {
	Broker      *approval.Broker
	Credentials CredentialLister
	FileKeys    FileKeySource
	RpID        string
	// NewConnectionID mints a per-connection id (stranded-approval cancel).
	NewConnectionID func() string
}

// Handler upgrades /agent-proxy to WebSocket and serves the SSH agent protocol.
// The bearer gate (upstream) already authorized the `agent` scope.
func (d *Deps) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := auth.PrincipalFrom(r.Context())
		if !ok {
			http.Error(w, "unauthenticated", http.StatusUnauthorized)
			return
		}
		wsc, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		wsc.SetReadLimit(-1)
		ctx := r.Context()

		connID := "conn"
		if d.NewConnectionID != nil {
			connID = d.NewConnectionID()
		}

		identities, err := d.buildIdentities(ctx, principal.AccountID)
		if err != nil {
			wsc.Close(websocket.StatusInternalError, "identity lookup failed")
			return
		}

		ba := &brokerAgent{
			ctx: ctx, identities: identities, broker: d.Broker,
			accountID: principal.AccountID, connectionID: connID,
			actionCtx: approval.Context{
				Source:         "agent-proxy",
				SourceIP:       clientIP(r),
				ClientHostname: util.SanitizeClientReported(r.Header.Get("X-ShellWatch-Hostname")),
				ClientOS:       util.SanitizeClientReported(r.Header.Get("X-ShellWatch-OS")),
				ClientVersion:  util.SanitizeClientReported(r.Header.Get("X-ShellWatch-Version")),
			},
		}

		// Cancel stranded approvals when the connection ends.
		defer d.Broker.Store().CancelForConnection(connID, "agent-proxy connection closed")

		rw := newWSReadWriter(ctx, wsc)
		_ = agent.ServeAgent(ba, rw) // returns on I/O error (client disconnect)
		wsc.Close(websocket.StatusNormalClosure, "")
	}
}

func (d *Deps) buildIdentities(ctx context.Context, accountID string) ([]Identity, error) {
	var out []Identity
	// File keys (admin) — offered with approval-gated signing.
	if d.FileKeys != nil {
		signers, err := d.FileKeys.Signers()
		if err == nil {
			for _, s := range signers {
				out = append(out, Identity{Signer: s, Label: "file key"})
			}
		}
	}
	// Passkeys.
	creds, err := d.Credentials.ActiveCredentialsForAuth(ctx, accountID)
	if err != nil {
		return nil, err
	}
	for _, c := range creds {
		id, err := passkeyIdentity(c.PublicKeyOpenSSH, c.CredentialID, c.Label, d.RpID)
		if err != nil {
			continue
		}
		out = append(out, id)
	}
	return out, nil
}

func clientIP(r *http.Request) string {
	host := r.RemoteAddr
	for i := len(host) - 1; i >= 0; i-- {
		if host[i] == ':' {
			return host[:i]
		}
	}
	return host
}

var _ = context.Background
