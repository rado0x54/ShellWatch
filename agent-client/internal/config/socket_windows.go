// SPDX-License-Identifier: MIT
//go:build windows

package config

// DefaultWindowsAgentPipe matches the path OpenSSH for Windows uses for its
// own ssh-agent. Listening here means a stock ssh.exe / ssh-add / git can
// find the proxy with no SSH_AUTH_SOCK in the environment — useful since
// the Windows ssh-agent service either isn't running or is disabled on
// machines that prefer this proxy.
const DefaultWindowsAgentPipe = `\\.\pipe\openssh-ssh-agent`

func defaultSocketPath() string {
	return DefaultWindowsAgentPipe
}
