// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Package util holds small shared helpers. SanitizeClientReported ports
// src/util/sanitize-client-info.ts: clean client-reported identity strings
// that cross a trust boundary into approval payloads (agent-proxy handshake
// headers, MCP initialize clientInfo).
package util

import "strings"

// ClientHeaderMaxLen bounds a sanitized value (CLIENT_HEADER_MAX_LEN).
const ClientHeaderMaxLen = 128

// SanitizeClientReported strips ASCII control chars (incl. newlines, tabs,
// DEL) and clamps length; empty result -> "". Idempotent.
func SanitizeClientReported(raw string) string {
	var b strings.Builder
	for _, r := range raw {
		if r <= 0x1f || r == 0x7f {
			continue
		}
		b.WriteRune(r)
		if b.Len() >= ClientHeaderMaxLen {
			break
		}
	}
	out := b.String()
	if len(out) > ClientHeaderMaxLen {
		out = out[:ClientHeaderMaxLen]
	}
	return out
}
