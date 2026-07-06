// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Server instructions (port of the instructions block in src/mcp/server.ts):
// a live endpoint list + workflow / session-lifecycle / sudo guidance the
// client model reads at initialize time. One deliberate divergence: Node's
// "Notifications:" section is omitted — the go-sdk cannot send custom
// notification methods (M1 is blocked on that), and promising notifications
// that never arrive would make agents wait instead of polling read_output.
package mcp

import (
	"fmt"
	"strings"

	"github.com/rado0x54/shellwatch/internal/agent"
)

func buildInstructions(endpoints []agent.EndpointInfo) string {
	lines := make([]string, 0, len(endpoints))
	for _, e := range endpoints {
		head := fmt.Sprintf("- %s: %s (%s@%s:%d)", e.ID, e.Label, e.Username, e.Host, e.Port)
		if e.Description != nil && *e.Description != "" {
			head += "\n  description: " + *e.Description
		}
		lines = append(lines, head)
	}
	endpointList := strings.Join(lines, "\n")

	return strings.Join([]string{
		"ShellWatch is an SSH session broker. You can create terminal sessions to remote servers, send commands, and read output.",
		"",
		"Available endpoints:",
		endpointList,
		"",
		"Workflow:",
		"1. Create a session with shellwatch_create_session (pick an endpoint ID from above)",
		`2. Send commands with shellwatch_send_keys (e.g., keys: ["text:ls -la", "enter"])`,
		"3. Read the result with shellwatch_read_output (use afterOffset for incremental reads)",
		"4. Keep the session open for follow-up commands — do NOT close it after each command",
		"5. Only close with shellwatch_close_session when you are certain no more interactions are needed",
		"",
		"Session lifecycle:",
		"- Sessions are automatically closed when your MCP connection ends — you do not need to close them manually",
		"- Keep sessions open between commands so the human observer can see your work and send follow-ups",
		"- Creating a new session for every command is wasteful — reuse your existing session",
		"",
		"sudo:",
		"- Do NOT pass -n (non-interactive). The human operator can attach to your session and type the password directly, so a [sudo] password: prompt is not a failure mode.",
		"- If you see a [sudo] password: prompt, ask the operator (in your reply) to enter the password in the session, then continue once read_output shows the prompt has cleared.",
		"- Do NOT chain sudo commands with && or || (e.g., `sudo cmd1 && sudo cmd2`). When a prompt appears the operator can't tell which command it belongs to. Send each sudo command separately so every prompt is unambiguous.",
		"- Sudo auth may go through a PAM module the operator satisfies out-of-band (push notification, hardware token, etc.) and can take tens of seconds — possibly falling back to a password prompt if the out-of-band step is declined or times out. A stalled prompt is not failure: keep polling read_output until the prompt clears or you see an explicit denial.",
	}, "\n")
}
