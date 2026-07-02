// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Package sshx is the x/crypto/ssh transport (port of src/transport/, the
// spec's §5.11). It implements terminal.Transport: dial with signers, request
// a PTY, start an interactive shell, pump stdout+stderr as Events, resize via
// window-change, close. The webauthn/passkey signer path (blocking on the
// pending-action broker) lands in Phase 4; slice 3 does file-key auth.
package sshx

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/rado0x54/shellwatch/internal/terminal"
)

const (
	ptyTerm = "xterm-256color"
	ptyCols = 80
	ptyRows = 24
	// connectionTimeout is Node's WEBAUTHN_CONNECTION_TIMEOUT: a single 90s
	// window covering dial + auth, sized for a human passkey touch. File-key
	// auth resolves instantly, but the constant is shared.
	connectionTimeout = 90 * time.Second
)

// sshTransport implements terminal.Transport over one ssh.Session.
type sshTransport struct {
	client  *ssh.Client
	session *ssh.Session
	stdin   io.WriteCloser
	events  chan terminal.Event

	mu     sync.Mutex
	closed bool
}

func (t *sshTransport) Events() <-chan terminal.Event { return t.events }

func (t *sshTransport) Write(data []byte) error {
	t.mu.Lock()
	closed := t.closed
	t.mu.Unlock()
	if closed {
		return fmt.Errorf("SSH stream is not open")
	}
	_, err := t.stdin.Write(data)
	return err
}

func (t *sshTransport) Resize(cols, rows int) error {
	return t.session.WindowChange(rows, cols)
}

func (t *sshTransport) Close() error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil
	}
	t.closed = true
	t.mu.Unlock()
	_ = t.session.Close()
	return t.client.Close()
}

// pipe forwards a reader to the event channel until EOF.
func (t *sshTransport) pipe(r io.Reader, wg *sync.WaitGroup) {
	defer wg.Done()
	buf := make([]byte, 32*1024)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			t.emit(terminal.Event{Data: append([]byte(nil), buf[:n]...)})
		}
		if err != nil {
			return
		}
	}
}

func (t *sshTransport) emit(ev terminal.Event) {
	t.mu.Lock()
	closed := t.closed
	t.mu.Unlock()
	if !closed {
		t.events <- ev
	}
}

// ConnectParams configure a dial.
type ConnectParams struct {
	Host         string
	Port         int
	Username     string
	Signers      []ssh.Signer
	AgentForward bool // reserved for Phase 4 (auth-agent@openssh.com)
	// HostKeyCallback defaults to InsecureIgnoreHostKey (ShellWatch brokers to
	// operator-configured hosts; host-key pinning is tracked separately).
	HostKeyCallback ssh.HostKeyCallback
}

// Connect dials, opens a PTY shell, and returns a terminal.Transport. The
// data pump runs until both streams EOF, then a single Closed event ends the
// session's pump goroutine.
func Connect(ctx context.Context, p ConnectParams) (terminal.Transport, error) {
	hostKey := p.HostKeyCallback
	if hostKey == nil {
		hostKey = ssh.InsecureIgnoreHostKey()
	}
	cfg := &ssh.ClientConfig{
		User:            p.Username,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(p.Signers...)},
		HostKeyCallback: hostKey,
		Timeout:         connectionTimeout,
	}

	addr := net.JoinHostPort(p.Host, strconv.Itoa(p.Port))
	dialer := net.Dialer{Timeout: connectionTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("SSH connection to %s failed: %w", addr, err)
	}
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("SSH handshake to %s failed: %w", addr, err)
	}
	client := ssh.NewClient(sshConn, chans, reqs)

	session, err := client.NewSession()
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("open session on %s: %w", p.Host, err)
	}
	modes := ssh.TerminalModes{ssh.ECHO: 1}
	if err := session.RequestPty(ptyTerm, ptyRows, ptyCols, modes); err != nil {
		session.Close()
		client.Close()
		return nil, fmt.Errorf("request pty on %s: %w", p.Host, err)
	}
	stdin, err := session.StdinPipe()
	if err != nil {
		session.Close()
		client.Close()
		return nil, err
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		session.Close()
		client.Close()
		return nil, err
	}
	stderr, err := session.StderrPipe()
	if err != nil {
		session.Close()
		client.Close()
		return nil, err
	}
	if err := session.Shell(); err != nil {
		session.Close()
		client.Close()
		return nil, fmt.Errorf("start shell on %s: %w", p.Host, err)
	}

	t := &sshTransport{client: client, session: session, stdin: stdin, events: make(chan terminal.Event, 64)}

	var wg sync.WaitGroup
	wg.Add(2)
	go t.pipe(stdout, &wg)
	go t.pipe(stderr, &wg)
	go func() {
		wg.Wait()          // both streams EOF
		_ = session.Wait() // reap the remote command
		t.mu.Lock()
		already := t.closed
		t.closed = true
		t.mu.Unlock()
		if !already {
			t.events <- terminal.Event{Closed: true}
		}
		close(t.events)
		_ = client.Close()
	}()

	return t, nil
}
