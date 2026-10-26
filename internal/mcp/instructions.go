// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Server instructions: a live endpoint list + workflow / session-lifecycle /
// sudo guidance, returned by server/discover and by the legacy initialize
// answer. Waiting for output is read_output waitMs (any era) or the
// shellwatch://sessions resources over subscriptions/listen (2026-07-28).
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
		"Waiting for output:",
		"- Pass waitMs to shellwatch_read_output (up to 30000) to long-poll: it returns as soon as output past afterOffset arrives, so you never need tight polling loops",
		"- Alternatively (protocol >= 2026-07-28), subscribe to shellwatch://sessions/<sessionId> via subscriptions/listen and re-read on notifications/resources/updated",
		"",
		"Session lifecycle:",
		"- Sessions persist across your requests (they belong to your OAuth client) and close on shellwatch_close_session, the remote end hanging up, or the server's idle timeout",
		"- Keep sessions open between commands so the human observer can see your work and send follow-ups",
		"- Creating a new session for every command is wasteful — list your existing sessions with shellwatch_list_sessions and reuse them",
		"",
		"sudo:",
		"- Do NOT pass -n (non-interactive). The human operator can attach to your session and type the password directly, so a [sudo] password: prompt is not a failure mode.",
		"- If you see a [sudo] password: prompt, ask the operator (in your reply) to enter the password in the session, then continue once read_output shows the prompt has cleared.",
		"- Do NOT chain sudo commands with && or || (e.g., `sudo cmd1 && sudo cmd2`). When a prompt appears the operator can't tell which command it belongs to. Send each sudo command separately so every prompt is unambiguous.",
		"- Sudo auth may go through a PAM module the operator satisfies out-of-band (push notification, hardware token, etc.) and can take tens of seconds — possibly falling back to a password prompt if the out-of-band step is declined or times out. A stalled prompt is not failure: keep polling read_output until the prompt clears or you see an explicit denial.",
	}, "\n")
}
