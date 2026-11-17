// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
package auth

import (
	"net/url"
	"strings"
)

// NormalizeOrigin reduces a URL to its origin, scheme://host[:port]:
// lowercased, the scheme's default port dropped. ok is false for anything
// that is not an http(s) URL with a host (including the opaque "null"
// origin). For an Origin header value (isHeader) a path, query, fragment or
// userinfo also fails, since browsers never send one; server.externalUrl may
// carry a path, which is ignored.
func NormalizeOrigin(raw string, isHeader bool) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || u.Opaque != "" {
		return "", false
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", false
	}
	if isHeader && (u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "") {
		return "", false
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return "", false
	}
	port := u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port != "" {
		host += ":" + port
	}
	return scheme + "://" + host, true
}

// OriginAllowed reports whether a request's Origin header exactly equals the
// configured external URL's origin (#306: the guest routes' CSWSH and
// login-CSRF defence). Missing, "null" or any other origin is refused. The
// expected origin comes from server.externalUrl only — never from r.Host
// (a reverse proxy may rewrite it) or the connection's scheme (TLS is
// terminated upstream).
func OriginAllowed(externalURL, origin string) bool {
	want, ok := NormalizeOrigin(externalURL, false)
	if !ok {
		return false
	}
	got, ok := NormalizeOrigin(origin, true)
	return ok && got == want
}

// OriginHost is the host part of an origin for logging ("" when unparsable).
func OriginHost(origin string) string {
	u, err := url.Parse(origin)
	if err != nil {
		return ""
	}
	return u.Host
}
