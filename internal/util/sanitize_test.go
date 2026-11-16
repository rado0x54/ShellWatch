// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
package util

import (
	"strings"
	"testing"
)

func TestSanitizeClientReported(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"curl/8.0", "curl/8.0"},
		{"a\nb\tc\x7f", "abc"},
		{"  spaced  ", "  spaced  "}, // header values are not trimmed
		{strings.Repeat("x", 200), strings.Repeat("x", ClientHeaderMaxLen)},
		// The byte cap never splits a multi-byte rune: 64 × "é" is 128 bytes.
		{strings.Repeat("é", 70), strings.Repeat("é", 64)},
	} {
		if got := SanitizeClientReported(c.in); got != c.want {
			t.Errorf("SanitizeClientReported(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSanitizeFreeText(t *testing.T) {
	for _, c := range []struct {
		in   string
		max  int
		want string
	}{
		{"fix the printer", 200, "fix the printer"},
		{"  \n\t  ", 200, ""}, // whitespace only counts as empty
		{" a\nb ", 200, "ab"},
		// The cap counts characters, not bytes: 150 Cyrillic letters (300
		// bytes) and 150 emoji (600 bytes) both fit a 200-character cap.
		{strings.Repeat("ж", 150), 200, strings.Repeat("ж", 150)},
		{strings.Repeat("🖨", 150), 200, strings.Repeat("🖨", 150)},
		{strings.Repeat("ж", 250), 200, strings.Repeat("ж", 200)},
	} {
		if got := SanitizeFreeText(c.in, c.max); got != c.want {
			t.Errorf("SanitizeFreeText(%q, %d) = %q, want %q", c.in, c.max, got, c.want)
		}
	}
}
