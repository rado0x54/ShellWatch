// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// SFTP capability of the SSH transport (#263). SSH multiplexes channels, so
// the file tools open the sftp subsystem on the session's already-approved
// connection: no new signature, no new approval. The subsystem runs as the
// SSH login user with its own working directory — it does not share the PTY's
// shell state.
package sshx

import (
	"context"
	"fmt"
	"io"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"github.com/rado0x54/shellwatch/internal/terminal"
)

var _ terminal.FileTransport = (*sshTransport)(nil)

// channelCloser makes sftp.Client.Close close the whole SSH channel rather
// than only half-closing its write side: a stalled sftp-server would otherwise
// keep pending requests (and the channel) alive indefinitely.
type channelCloser struct {
	io.WriteCloser
	session *ssh.Session
}

func (c channelCloser) Close() error {
	_ = c.WriteCloser.Close()
	return c.session.Close()
}

// OpenSFTP opens a new sftp subsystem channel on the session's connection.
// ctx bounds channel setup and the version handshake; cancelling it closes
// the half-open channel. Closing the returned client closes only that
// channel, never the PTY.
func (t *sshTransport) OpenSFTP(ctx context.Context) (*sftp.Client, error) {
	t.mu.Lock()
	closed := t.closed
	t.mu.Unlock()
	if closed {
		return nil, fmt.Errorf("SSH connection is not open")
	}

	type result struct {
		client  *sftp.Client
		session *ssh.Session
		err     error
	}
	// sessCh hands the session to the canceller as soon as it exists, so a
	// handshake stalled inside NewClientPipe can still be torn down.
	sessCh := make(chan *ssh.Session, 1)
	done := make(chan result, 1)
	go func() {
		session, err := t.client.NewSession()
		if err != nil {
			done <- result{err: fmt.Errorf("open sftp channel: %w", err)}
			return
		}
		sessCh <- session
		stdin, err := session.StdinPipe()
		if err != nil {
			session.Close()
			done <- result{err: err}
			return
		}
		stdout, err := session.StdoutPipe()
		if err != nil {
			session.Close()
			done <- result{err: err}
			return
		}
		if err := session.RequestSubsystem("sftp"); err != nil {
			session.Close()
			done <- result{err: fmt.Errorf("remote host refused the sftp subsystem: %w", err)}
			return
		}
		client, err := sftp.NewClientPipe(stdout, channelCloser{WriteCloser: stdin, session: session})
		if err != nil {
			session.Close()
			done <- result{err: fmt.Errorf("sftp handshake: %w", err)}
			return
		}
		done <- result{client: client, session: session}
	}()

	select {
	case r := <-done:
		return r.client, r.err
	case <-ctx.Done():
		// Abandon the setup: close the channel if it exists (unblocking the
		// handshake) and reap whatever the goroutine still produces.
		go func() {
			for {
				select {
				case s := <-sessCh:
					_ = s.Close() // unblocks a stalled handshake; keep reaping
				case r := <-done:
					if r.client != nil {
						_ = r.client.Close()
					}
					return
				}
			}
		}()
		return nil, ctx.Err()
	}
}
