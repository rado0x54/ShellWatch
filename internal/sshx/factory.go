// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Transport factory (port of the file-key path in create-factory.ts). Builds
// signers for an endpoint and dials. The god-function is decomposed: signer
// selection lives here, the pending-action/broker signer path is added in
// Phase 4 (spec §5.8/§5.11, W1). File keys are admin-only in the Node backend;
// that scoping is enforced by the caller (the account-role check moves in with
// the account repo).
package sshx

import (
	"context"
	"fmt"

	"golang.org/x/crypto/ssh"

	"github.com/rado0x54/shellwatch/internal/terminal"
)

// SignerSource yields the file-key signers available for a connection.
type SignerSource interface {
	Signers() ([]ssh.Signer, error)
}

// NewFileKeyFactory returns a TransportFactory that authenticates with file
// keys from src. Endpoints with no usable signer fail to connect (the passkey
// path is Phase 4).
func NewFileKeyFactory(src SignerSource) terminal.TransportFactory {
	return func(ctx context.Context, p terminal.FactoryParams) (terminal.Transport, error) {
		signers, err := src.Signers()
		if err != nil {
			return nil, err
		}
		if len(signers) == 0 {
			return nil, fmt.Errorf("no file keys available for endpoint %s", p.Endpoint.ID)
		}
		return Connect(ctx, ConnectParams{
			Host:         p.Endpoint.Host,
			Port:         p.Endpoint.Port,
			Username:     p.Endpoint.Username,
			Signers:      signers,
			AgentForward: p.Endpoint.AgentForward,
		})
	}
}
