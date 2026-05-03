// SPDX-License-Identifier: MIT
//go:build windows

package proxy

import (
	"fmt"
	"net"

	"github.com/Microsoft/go-winio"
)

// pipeSecurityDescriptor restricts the agent pipe to the calling user, Local
// System, and the Administrators group. Without an explicit DACL the winio
// default would allow read by Everyone — too loose for a key-signing oracle.
//
// Deliberately omits an O: (owner) component: setting the owner to anything
// other than the caller's own SID requires SeRestorePrivilege, which a regular
// interactive user doesn't hold. CreateNamedPipeW would then reject the SD
// with ERROR_INVALID_OWNER at bind time. The OpenSSH ssh-agent service gets
// away with O:BA only because it runs as LocalSystem. With no O: specified
// the kernel sets the owner to the caller, which makes (A;;GA;;;OW) resolve
// to "the running user" — exactly what we want.
const pipeSecurityDescriptor = "D:P(A;;GA;;;OW)(A;;GA;;;SY)(A;;GA;;;BA)"

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