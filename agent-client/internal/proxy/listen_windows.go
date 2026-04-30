//go:build windows

package proxy

import (
	"fmt"
	"net"

	"github.com/Microsoft/go-winio"
)

// pipeSecurityDescriptor restricts the agent pipe to the same set of principals
// OpenSSH for Windows uses for its own ssh-agent pipe: owner (creator), local
// system, and the Administrators group. Without this, the winio default DACL
// would allow read by Everyone — too loose for a key-signing oracle.
const pipeSecurityDescriptor = "O:BAG:SYD:P(A;;GA;;;BA)(A;;GA;;;SY)(A;;GA;;;OW)"

// listenSocket binds a named pipe at path and returns a net.Listener.
// Windows OpenSSH connects to pipes (\\.\pipe\<name>), not Unix sockets — so
// even on Windows 10+ where AF_UNIX exists, the proxy must speak pipes for
// ssh.exe to find it.
func listenSocket(path string) (net.Listener, error) {
	cfg := &winio.PipeConfig{
		SecurityDescriptor: pipeSecurityDescriptor,
	}
	l, err := winio.ListenPipe(path, cfg)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", path, err)
	}
	return l, nil
}

// cleanStaleSocket is a no-op on Windows — named pipes are kernel objects with
// no filesystem artifact, so there's nothing to clean up between runs. If
// another process already owns the pipe, listenSocket itself will fail.
func cleanStaleSocket(path string) error {
	return nil
}

// removeSocketFile is a no-op on Windows for the same reason.
func removeSocketFile(path string) {}