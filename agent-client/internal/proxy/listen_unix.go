// SPDX-License-Identifier: MIT
//go:build !windows

package proxy

import (
	"fmt"
	"net"
	"os"
	"time"
)

// listenSocket binds a Unix domain socket at path with 0600 permissions.
// The chmod is load-bearing: net.Listen honors the process umask, which on
// some distros leaves the socket world-readable — anyone on the box could
// then talk to the agent and ask it to sign things.
func listenSocket(path string) (net.Listener, error) {
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		l.Close()
		return nil, fmt.Errorf("chmod socket: %w", err)
	}
	return l, nil
}

// cleanStaleSocket removes a socket file if it exists but no one is listening.
// Surfaces a clear error when another process already owns the path so the
// supervisor's restart loop doesn't busy-spin against a live conflict.
func cleanStaleSocket(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	}
	conn, err := net.DialTimeout("unix", path, time.Second)
	if err == nil {
		conn.Close()
		return fmt.Errorf("another process is listening on %s", path)
	}
	return os.Remove(path)
}

// removeSocketFile deletes the socket on shutdown so the next run starts clean.
func removeSocketFile(path string) {
	_ = os.Remove(path)
}
