// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// approvedFileKeySigner gates every file-key sign behind a key-approve pending
// action (port of composite-ssh-agent.ts:136-152 / onFileKeySignRequest): a
// terminal connection authenticating with an admin file key must surface a
// human approval prompt + audit row, exactly like the agent-proxy and
// agent-forwarding paths already do. Any rejection — deny, TTL expiry,
// connection-cancel — is a plain signer error; Connect offers each key as its
// own publickey method (auth.go), so x/crypto falls through to the next key
// (composite-ssh-agent.ts:146-151) and a dead dial context aborts.
package sshx

import (
	"context"
	"io"

	"golang.org/x/crypto/ssh"

	"github.com/rado0x54/shellwatch/internal/approval"
)

type approvedFileKeySigner struct {
	signer       ssh.Signer
	broker       SignBroker
	accountID    string
	label        string
	connectionID string
	actionCtx    approval.Context
	redirectTo   string
	ctx          context.Context
}

var _ ssh.Signer = (*approvedFileKeySigner)(nil)

// newApprovedFileKeySigner wraps s preserving the AlgorithmSigner /
// MultiAlgorithmSigner capabilities x/crypto type-asserts (same pattern as
// wrapRecording in auth.go): wrapped as a plain Signer, an RSA key would be
// forced down to ssh-rsa/SHA-1, which OpenSSH >= 8.8 rejects by default —
// auth would fail even after the human approved.
func newApprovedFileKeySigner(s *approvedFileKeySigner) ssh.Signer {
	if ms, ok := s.signer.(ssh.MultiAlgorithmSigner); ok {
		return &approvedFileKeyMultiSigner{approvedFileKeyAlgoSigner{s, ms}, ms}
	}
	if as, ok := s.signer.(ssh.AlgorithmSigner); ok {
		return &approvedFileKeyAlgoSigner{s, as}
	}
	return s
}

func (s *approvedFileKeySigner) PublicKey() ssh.PublicKey { return s.signer.PublicKey() }

// approve blocks on the human key-approve action; any rejection is returned
// as a plain signer error (x/crypto falls through to the next key).
func (s *approvedFileKeySigner) approve() error {
	ctx := s.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	fp := ssh.FingerprintSHA256(s.signer.PublicKey())
	return s.broker.RequestKeyApproval(ctx, approval.KeyApproval{
		AccountID: s.accountID, KeyLabel: s.label, KeyFingerprint: fp, ConnectionID: s.connectionID,
		Context: s.actionCtx, RedirectTo: s.redirectTo,
	})
}

func (s *approvedFileKeySigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	if err := s.approve(); err != nil {
		return nil, err
	}
	return s.signer.Sign(rand, data)
}

type approvedFileKeyAlgoSigner struct {
	*approvedFileKeySigner
	as ssh.AlgorithmSigner
}

func (s *approvedFileKeyAlgoSigner) SignWithAlgorithm(rand io.Reader, data []byte, algorithm string) (*ssh.Signature, error) {
	if err := s.approve(); err != nil {
		return nil, err
	}
	return s.as.SignWithAlgorithm(rand, data, algorithm)
}

type approvedFileKeyMultiSigner struct {
	approvedFileKeyAlgoSigner
	ms ssh.MultiAlgorithmSigner
}

func (s *approvedFileKeyMultiSigner) Algorithms() []string { return s.ms.Algorithms() }
