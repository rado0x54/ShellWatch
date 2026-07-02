// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// CIDR-based IP allowlist for /mcp (port of src/server/auth/ip-allowlist.ts).
// Go's net package handles IPv4, IPv6, and IPv4-mapped IPv6 natively, so this
// is a thin wrapper over net.ParseCIDR + IPNet.Contains. Defaults to localhost
// (127.0.0.1/32, ::1/128). The auth model documents /mcp as scope mcp + this.
package auth

import (
	"net"
	"net/http"
)

// IPChecker reports whether a peer IP is in the allowlist.
type IPChecker struct {
	nets []*net.IPNet
}

// NewIPChecker parses the CIDR allowlist (invalid entries are skipped).
func NewIPChecker(allowedNetworks []string) *IPChecker {
	c := &IPChecker{}
	for _, cidr := range allowedNetworks {
		if _, n, err := net.ParseCIDR(cidr); err == nil {
			c.nets = append(c.nets, n)
		}
	}
	return c
}

// Allowed reports whether ip (a host string) is in range.
func (c *IPChecker) Allowed(ip string) bool {
	parsed := net.ParseIP(stripZone(ip))
	if parsed == nil {
		return false
	}
	for _, n := range c.nets {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}

// Middleware rejects requests whose peer IP isn't allowed (403). Apply to /mcp.
func (c *IPChecker) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		if !c.Allowed(host) {
			http.Error(w, `{"error":"Forbidden"}`, http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func stripZone(ip string) string {
	for i := 0; i < len(ip); i++ {
		if ip[i] == '%' {
			return ip[:i]
		}
	}
	return ip
}
