// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Package util holds small shared helpers. SanitizeClientReported ports
// src/util/sanitize-client-info.ts: clean client-reported identity strings
// that cross a trust boundary into approval payloads (agent-proxy handshake
// headers, MCP initialize clientInfo).
package util

import (
	"strings"
	"unicode"
)

// ClientHeaderMaxLen bounds a sanitized value (CLIENT_HEADER_MAX_LEN).
const ClientHeaderMaxLen = 128

// SanitizeClientReported strips control and invisible format characters
// (see isControl) and clamps length to ClientHeaderMaxLen bytes; empty
// result -> "".
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
// ticket's reason, #306), or a value shown next to it: control and invisible
// format characters are stripped (see isControl), the result is capped at
// maxChars characters (runes, so the limit matches an HTML maxlength for
// non-Latin text and never splits a UTF-8 sequence), and surrounding
// whitespace is trimmed, so a value of only spaces counts as empty.
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

// isControl reports characters stripped from client-reported text. Besides
// ASCII and C1 controls (newlines, tabs, DEL, U+0080–U+009F) these are the
// invisible Unicode characters that can rearrange or hide text where it is
// shown to a human: format characters (bidi overrides and isolates such as
// U+202E and U+2066–U+2069, zero-width spaces and joiners, BOM) and the
// line/paragraph separators. A guest's reason sits next to the confirmation
// code on the approval prompt; it must read as what it is.
func isControl(r rune) bool {
	return r <= 0x1f || (r >= 0x7f && r <= 0x9f) ||
		unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029'
}
