// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Port of src/utils/endpoint-address.ts — parse/format [user@]host[:port]
// with defaults username "shellwatch" and port 22, incl. [IPv6]:port.
package config

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

const (
	defaultUsername = "shellwatch"
	defaultPort     = 22
)

var digitsRe = regexp.MustCompile(`^\d+$`)

// ParseEndpointAddress parses "[user@]host[:port]" (IPv6 in brackets).
func ParseEndpointAddress(address string) (EndpointAddress, error) {
	trimmed := strings.TrimSpace(address)
	if trimmed == "" {
		return EndpointAddress{}, fmt.Errorf("endpoint address cannot be empty")
	}

	username := defaultUsername
	rest := trimmed
	if at := strings.Index(rest, "@"); at != -1 {
		username = rest[:at]
		if username == "" {
			return EndpointAddress{}, fmt.Errorf("invalid endpoint address: empty username in %q", address)
		}
		rest = rest[at+1:]
	}

	host := ""
	port := defaultPort
	if strings.HasPrefix(rest, "[") {
		close := strings.Index(rest, "]")
		if close == -1 {
			return EndpointAddress{}, fmt.Errorf("invalid endpoint address: unclosed bracket in %q", address)
		}
		host = rest[1:close]
		after := rest[close+1:]
		switch {
		case strings.HasPrefix(after, ":"):
			p, err := parsePort(after[1:], address)
			if err != nil {
				return EndpointAddress{}, err
			}
			port = p
		case after != "":
			return EndpointAddress{}, fmt.Errorf("invalid endpoint address: unexpected characters after bracket in %q", address)
		}
	} else {
		if colon := strings.LastIndex(rest, ":"); colon != -1 && digitsRe.MatchString(rest[colon+1:]) {
			p, err := parsePort(rest[colon+1:], address)
			if err != nil {
				return EndpointAddress{}, err
			}
			host, port = rest[:colon], p
		} else {
			host = rest
		}
	}

	if host == "" {
		return EndpointAddress{}, fmt.Errorf("invalid endpoint address: empty host in %q", address)
	}
	return EndpointAddress{Username: username, Host: host, Port: port}, nil
}

func parsePort(s, original string) (int, error) {
	p, err := strconv.Atoi(s)
	if err != nil || p < 1 || p > 65535 {
		return 0, fmt.Errorf("invalid endpoint address: port out of range in %q", original)
	}
	return p, nil
}

// FormatEndpointAddress renders "user@host[:port]", always including the
// username and omitting the default port (endpoint-address.ts).
func FormatEndpointAddress(ep EndpointAddress) string {
	if ep.Port != defaultPort {
		return fmt.Sprintf("%s@%s:%d", ep.Username, ep.Host, ep.Port)
	}
	return ep.Username + "@" + ep.Host
}
