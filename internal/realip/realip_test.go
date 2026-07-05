// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
package realip

import (
	"net/http/httptest"
	"testing"
)

func TestClientIP(t *testing.T) {
	cases := []struct {
		name       string
		trustProxy any
		remote     string
		xff        string
		want       string
	}{
		{"false ignores XFF", false, "127.0.0.1:9999", "203.0.113.7", "127.0.0.1"},
		{"nil ignores XFF", nil, "127.0.0.1:9999", "203.0.113.7", "127.0.0.1"},
		{"true trusts all -> leftmost", true, "127.0.0.1:9999", "203.0.113.7, 10.0.0.1", "203.0.113.7"},
		{"true no XFF -> peer", true, "192.0.2.4:1", "", "192.0.2.4"},
		{"loopback preset trusts local proxy", "loopback", "127.0.0.1:9999", "203.0.113.7", "203.0.113.7"},
		{"loopback preset stops at untrusted hop", "loopback", "127.0.0.1:9999", "203.0.113.7, 198.51.100.2", "198.51.100.2"},
		{"CIDR string", "10.0.0.0/8", "10.1.2.3:44", "203.0.113.7", "203.0.113.7"},
		{"CIDR not matching peer -> peer", "10.0.0.0/8", "192.0.2.4:44", "203.0.113.7", "192.0.2.4"},
		{"hop count 1", 1, "127.0.0.1:9999", "203.0.113.7, 10.0.0.1", "10.0.0.1"},
		{"hop count 2", 2, "127.0.0.1:9999", "203.0.113.7, 10.0.0.1", "203.0.113.7"},
		{"array of presets", []any{"loopback", "uniquelocal"}, "192.168.1.1:80", "203.0.113.7", "203.0.113.7"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = tc.remote
			if tc.xff != "" {
				req.Header.Set("X-Forwarded-For", tc.xff)
			}
			if got := New(tc.trustProxy).ClientIP(req); got != tc.want {
				t.Errorf("ClientIP = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestFromRequestFallsBackToPeer(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.0.2.9:1234"
	if got := FromRequest(req); got != "192.0.2.9" {
		t.Errorf("FromRequest = %q", got)
	}
}
