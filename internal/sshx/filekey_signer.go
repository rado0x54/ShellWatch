// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// approvedFileKeySigner gates every file-key sign behind a key-approve pending
// action (port of composite-ssh-agent.ts:136-152 / onFileKeySignRequest): a
// terminal connection authenticating with an admin file key must surface a
// human approval prompt + audit row, exactly like the agent-proxy and
// agent-forwarding paths already do. Any rejection — deny, TTL expiry,
// connection-cancel — falls through to the next offered key (skip signature,
// composite-ssh-agent.ts:146-151); only a dead dial context aborts.
package sshx

import (
	"context"
	"errors"
	"io"

	"golang.org/x/crypto/ssh"

	"github.com/rado0x54/shellwatch/internal/approval"
	"github.com/rado0x54/shellwatch/internal/signing"
)

type approvedFileKeySigner struct {
	signer       ssh.Signer
	broker       SignBroker
	accountID    string
	label        string
	connectionID string
	actionCtx    approval.Context
	ctx          context.Context
}

var _ ssh.Signer = (*approvedFileKeySigner)(nil)

func (s *approvedFileKeySigner) PublicKey() ssh.PublicKey { return s.signer.PublicKey() }

func (s *approvedFileKeySigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	ctx := s.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	fp := ssh.FingerprintSHA256(s.signer.PublicKey())
	if err := s.broker.RequestKeyApproval(ctx, s.accountID, s.label, fp, s.connectionID, s.actionCtx); err != nil {
		// x/crypto/ssh treats a signer error as fatal to the whole publickey
		// method — a hard error here would stop the passkey offered after this
		// key from ever being tried. Node skips on every rejection (deny,
		// expiry, store destroy); only context death aborts.
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}
		return signing.SkipSignature(), nil
	}
	return s.signer.Sign(rand, data)
}
