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
// DEL) and clamps length to ClientHeaderMaxLen bytes; empty result -> "".
// Idempotent.
func SanitizeClientReported(raw string) string {
	var b strings.Builder
	for _, r := range raw {
		if isControl(r) {
			continue
		}
		if b.Len()+len(string(r)) > ClientHeaderMaxLen {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}

// SanitizeFreeText cleans text a person typed on an untrusted client (a
// ticket's reason, #306), or a value shown next to it: ASCII control chars
// are stripped, the result is capped at maxChars characters (runes, so the
// limit matches an HTML maxlength for non-Latin text and never splits a
// UTF-8 sequence), and surrounding whitespace is trimmed, so a value of only
// spaces counts as empty.
func SanitizeFreeText(raw string, maxChars int) string {
	var b strings.Builder
	n := 0
	for _, r := range raw {
		if isControl(r) {
			continue
		}
		if n == maxChars {
			break
		}
		b.WriteRune(r)
		n++
	}
	return strings.TrimSpace(b.String())
}

func isControl(r rune) bool { return r <= 0x1f || r == 0x7f }
