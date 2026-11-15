// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// The shellwatch-agent's OAuth Client ID Metadata Document (#256).
//
// The agent has no registration step: its client_id is the fixed URL
// AgentClientID, and every ShellWatch authorization server resolves it through
// the CIMD front door like any other URL client_id. The document is embedded
// and served by the binary, so the canonical copy is the one app.shellwatch.ai
// serves. Self-hosted instances serve the same bytes, but only the
// app.shellwatch.ai URL is ever used as a client_id: a self-hosted server
// fetches it from there on the agent's first login and once per cache TTL.
//
// The document is a wire contract with agent-client/internal/oauth: the URL,
// the loopback callback path and the `agent` scope must stay in sync (pinned
// by agentclient_test.go).
package hydra

import (
	_ "embed"
	"net/http"
)

// AgentClientID is the shellwatch-agent's client_id. Changing it orphans every
// stored agent credential, so it must stay stable.
const AgentClientID = "https://app.shellwatch.ai/.well-known/shellwatch-agent-client.json"

// AgentClientMetadataPath is where the document is served on every instance.
const AgentClientMetadataPath = "/.well-known/shellwatch-agent-client.json"

// agentClientMetadataMaxAge is the Cache-Control max-age the document is
// served with. Fetchers clamp it into their own window ([5m, 24h] by default).
const agentClientMetadataMaxAge = "public, max-age=86400"

//go:embed agent-client-metadata.json
var agentClientMetadata []byte

func serveAgentClientMetadata(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", agentClientMetadataMaxAge)
	_, _ = w.Write(agentClientMetadata)
}
