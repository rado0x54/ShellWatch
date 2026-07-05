// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Package realip resolves the client IP under server.trustProxy (port of
// Fastify's trustProxy / proxy-addr semantics, consumed as request.ip in
// Node). The resolved IP is stashed in the request context by Middleware and
// read by every consumer (audit sourceIp, /mcp allowlist, rate limiting) via
// FromRequest — so trustProxy is honored in exactly one place.
//
// trustProxy values (schema.ts): false (default, never trust X-Forwarded-For),
// true (trust all proxies), N (trust N hops), CIDR/preset string or list
// ("loopback", "linklocal", "uniquelocal", "10.0.0.0/8", comma-separated).
package realip

import (
	"context"
	"net"
	"net/http"
	"strings"
)

// Resolver computes the effective client IP for a request.
type Resolver struct {
	trustAll bool
	hops     int
	nets     []*net.IPNet
}

var presets = map[string][]string{
	"loopback":    {"127.0.0.0/8", "::1/128"},
	"linklocal":   {"169.254.0.0/16", "fe80::/10"},
	"uniquelocal": {"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"},
}

// New builds a Resolver from the parsed trustProxy config value.
func New(trustProxy any) *Resolver {
	r := &Resolver{}
	switch v := trustProxy.(type) {
	case bool:
		r.trustAll = v
	case int:
		r.hops = v
	case int64:
		r.hops = int(v)
	case uint64:
		r.hops = int(v)
	case float64:
		r.hops = int(v)
	case string:
		for _, part := range strings.Split(v, ",") {
			r.addEntry(strings.TrimSpace(part))
		}
	case []any:
		for _, e := range v {
			if s, ok := e.(string); ok {
				r.addEntry(strings.TrimSpace(s))
			}
		}
	case []string:
		for _, s := range v {
			r.addEntry(strings.TrimSpace(s))
		}
	}
	return r
}

func (r *Resolver) addEntry(entry string) {
	if entry == "" {
		return
	}
	if cidrs, ok := presets[entry]; ok {
		for _, c := range cidrs {
			if _, n, err := net.ParseCIDR(c); err == nil {
				r.nets = append(r.nets, n)
			}
		}
		return
	}
	if _, n, err := net.ParseCIDR(entry); err == nil {
		r.nets = append(r.nets, n)
		return
	}
	// Bare IP -> single-host network.
	if ip := net.ParseIP(entry); ip != nil {
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		r.nets = append(r.nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
	}
}

func (r *Resolver) trusted(ip string) bool {
	if r.trustAll {
		return true
	}
	parsed := net.ParseIP(stripZone(ip))
	if parsed == nil {
		return false
	}
	for _, n := range r.nets {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}

// ClientIP resolves the effective client IP (proxy-addr walk): start at the
// socket peer; while the current hop is trusted, step left through
// X-Forwarded-For. With a hop count, take exactly that many steps.
func (r *Resolver) ClientIP(req *http.Request) string {
	peer := remoteHost(req)
	xff := forwardedChain(req)

	if r.hops > 0 {
		// Trust exactly N hops from the peer.
		idx := len(xff) - r.hops
		if idx < 0 {
			idx = 0
		}
		if len(xff) == 0 {
			return peer
		}
		return xff[idx]
	}
	if !r.trustAll && len(r.nets) == 0 {
		return peer // trustProxy: false
	}
	current := peer
	for i := len(xff) - 1; i >= 0; i-- {
		if !r.trusted(current) {
			return current
		}
		current = xff[i]
	}
	return current
}

func forwardedChain(req *http.Request) []string {
	var out []string
	for _, h := range req.Header.Values("X-Forwarded-For") {
		for _, part := range strings.Split(h, ",") {
			if p := strings.TrimSpace(part); p != "" {
				out = append(out, p)
			}
		}
	}
	return out
}

func remoteHost(req *http.Request) string {
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return req.RemoteAddr
	}
	return host
}

func stripZone(ip string) string {
	if i := strings.IndexByte(ip, '%'); i >= 0 {
		return ip[:i]
	}
	return ip
}

type ipKey struct{}

// Middleware resolves the client IP once per request and stores it in the
// context for FromRequest consumers.
func (r *Resolver) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		ctx := context.WithValue(req.Context(), ipKey{}, r.ClientIP(req))
		next.ServeHTTP(w, req.WithContext(ctx))
	})
}

// FromRequest returns the resolved client IP, falling back to the socket peer
// when the middleware didn't run (tests, direct handler use).
func FromRequest(req *http.Request) string {
	if ip, ok := req.Context().Value(ipKey{}).(string); ok && ip != "" {
		return ip
	}
	return remoteHost(req)
}
