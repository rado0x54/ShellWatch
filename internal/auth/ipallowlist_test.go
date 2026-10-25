// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
package auth

import "testing"

func TestIPChecker(t *testing.T) {
	c := NewIPChecker([]string{"127.0.0.1/32", "::1/128", "10.0.0.0/8"})
	cases := []struct {
		ip   string
		want bool
	}{
		{"127.0.0.1", true},
		{"::1", true},
		{"10.5.6.7", true},
		{"10.255.255.255", true},
		{"192.168.1.1", false},
		{"11.0.0.1", false},
		{"::ffff:127.0.0.1", true}, // IPv4-mapped IPv6 of an allowed addr
		{"fe80::1%eth0", false},    // zone-scoped, not in range
		{"not-an-ip", false},
	}
	for _, tc := range cases {
		if got := c.Allowed(tc.ip); got != tc.want {
			t.Errorf("Allowed(%q) = %v, want %v", tc.ip, got, tc.want)
		}
	}
}

func TestIPCheckerDefaultsRejectRemote(t *testing.T) {
	c := NewIPChecker([]string{"127.0.0.1/32", "::1/128"})
	if c.Allowed("203.0.113.5") {
		t.Error("remote IP should be rejected under localhost-only default")
	}
}
