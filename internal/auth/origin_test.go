// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
package auth

import "testing"

func TestOriginAllowed(t *testing.T) {
	cases := []struct {
		name, external, origin string
		want                   bool
	}{
		{"exact", "https://sw.example.com", "https://sw.example.com", true},
		{"external has default port", "https://sw.example.com:443", "https://sw.example.com", true},
		{"origin has default port", "https://sw.example.com", "https://sw.example.com:443", true},
		{"http default port", "http://localhost:80/", "http://localhost", true},
		{"case folded", "https://SW.Example.com", "HTTPS://sw.example.COM", true},
		{"external path ignored", "https://sw.example.com/app/", "https://sw.example.com", true},
		{"dev vite origin", "http://localhost:3001", "http://localhost:3001", true},
		{"ipv6", "http://[::1]:3000", "http://[::1]:3000", true},
		{"sibling subdomain", "https://sw.example.com", "https://demo.example.com", false},
		{"parent domain", "https://sw.example.com", "https://example.com", false},
		{"suffix trick", "https://sw.example.com", "https://sw.example.com.evil.net", false},
		{"foreign", "https://sw.example.com", "https://evil.net", false},
		{"scheme mismatch", "https://sw.example.com", "http://sw.example.com", false},
		{"port mismatch", "http://localhost:3001", "http://localhost:3000", false},
		{"null", "https://sw.example.com", "null", false},
		{"missing", "https://sw.example.com", "", false},
		{"origin with path", "https://sw.example.com", "https://sw.example.com/x", false},
		{"bad external", "not a url", "https://sw.example.com", false},
	}
	for _, c := range cases {
		if got := OriginAllowed(c.external, c.origin); got != c.want {
			t.Errorf("%s: OriginAllowed(%q, %q) = %v, want %v", c.name, c.external, c.origin, got, c.want)
		}
	}
}
