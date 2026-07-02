// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const minimalConfig = `
security:
  rpId: localhost
  trustedWebauthnOrigins:
    - http://localhost:3000
server:
  externalUrl: http://localhost:3000
hydra:
  publicUrl: http://localhost:4444
  adminUrl: http://localhost:4445
seedAdminEndpoints:
  - label: Dev Box
    address: ubuntu@dev.example.com:2222
`

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadDefaultsAndDerivations(t *testing.T) {
	cfg, err := Load(writeConfig(t, minimalConfig))
	if err != nil {
		t.Fatal(err)
	}
	// schema.ts defaults
	if cfg.Server.Port != 3000 {
		t.Errorf("port default: got %d", cfg.Server.Port)
	}
	if cfg.Server.TrustProxy != false {
		t.Errorf("trustProxy default: got %v", cfg.Server.TrustProxy)
	}
	if got := cfg.Security.AllowedNetworks; len(got) != 2 || got[0] != "127.0.0.1/32" || got[1] != "::1/128" {
		t.Errorf("allowedNetworks default: got %v", got)
	}
	if cfg.Security.RateLimit.LoginOptions.Max != 20 || cfg.Security.RateLimit.SelfRegister.WindowMinutes != 15 {
		t.Errorf("rateLimit defaults: got %+v", cfg.Security.RateLimit)
	}
	if cfg.Notifications.Mcp.DebounceMs != 100 {
		t.Errorf("debounceMs default: got %d", cfg.Notifications.Mcp.DebounceMs)
	}
	if cfg.AgentSocket.ProxyEnabled {
		t.Error("proxyEnabled must default to false")
	}
	if cfg.Hydra.Spa.ClientID != "shellwatch-web" || *cfg.Hydra.IntrospectionCacheTtlMs != 60_000 {
		t.Errorf("hydra defaults: %+v", cfg.Hydra)
	}
	if len(cfg.Hydra.Dcr.AllowedScopes) != 2 || len(cfg.Hydra.Dcr.RedirectURIPatterns) != 2 {
		t.Errorf("dcr defaults: %+v", cfg.Hydra.Dcr)
	}
	// loader.ts derivations
	if cfg.Hydra.Spa.RedirectURI != "http://localhost:3000/auth/callback" {
		t.Errorf("spa redirectUri derivation: got %q", cfg.Hydra.Spa.RedirectURI)
	}
	if !filepath.IsAbs(cfg.KeyDirectory) || filepath.Base(cfg.KeyDirectory) != "keys" {
		t.Errorf("keyDirectory resolution: got %q", cfg.KeyDirectory)
	}
	// address transform
	ep := cfg.SeedAdminEndpoints[0]
	if ep.Parsed.Username != "ubuntu" || ep.Parsed.Host != "dev.example.com" || ep.Parsed.Port != 2222 {
		t.Errorf("address parse: got %+v", ep.Parsed)
	}
	if !ep.AgentForwardEnabled() {
		t.Error("agentForward must default to true")
	}
}

func TestLoadRejectsMissingRequired(t *testing.T) {
	_, err := Load(writeConfig(t, "server:\n  externalUrl: http://x.example\nhydra:\n  publicUrl: http://h:4444\n  adminUrl: http://h:4445\n"))
	if err == nil {
		t.Fatal("expected validation error")
	}
	for _, want := range []string{"security.rpId is required", "trustedWebauthnOrigins requires at least one"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %q, got:\n%v", want, err)
		}
	}
}

func TestParseEndpointAddressForms(t *testing.T) {
	cases := []struct {
		in   string
		want EndpointAddress
	}{
		{"host", EndpointAddress{"shellwatch", "host", 22}},
		{"host:2200", EndpointAddress{"shellwatch", "host", 2200}},
		{"user@host", EndpointAddress{"user", "host", 22}},
		{"user@host:2200", EndpointAddress{"user", "host", 2200}},
		{"user@[::1]:2200", EndpointAddress{"user", "::1", 2200}},
		// Bug-compatible with endpoint-address.ts: a bare IPv6 with a numeric
		// last segment splits as host:port (use brackets to avoid); only a
		// non-numeric last segment survives unsplit.
		{"user@2001:db8::1", EndpointAddress{"user", "2001:db8:", 1}},
		{"user@fe80::abcd", EndpointAddress{"user", "fe80::abcd", 22}},
	}
	for _, c := range cases {
		got, err := ParseEndpointAddress(c.in)
		if err != nil {
			t.Errorf("%q: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("%q: got %+v want %+v", c.in, got, c.want)
		}
	}
	for _, bad := range []string{"", "@host", "user@", "host:99999", "[::1", "user@[::1]x"} {
		if _, err := ParseEndpointAddress(bad); err == nil {
			t.Errorf("%q: expected error", bad)
		}
	}
	if got := FormatEndpointAddress(EndpointAddress{"u", "h", 22}); got != "u@h" {
		t.Errorf("format default port: %q", got)
	}
	if got := FormatEndpointAddress(EndpointAddress{"u", "h", 2200}); got != "u@h:2200" {
		t.Errorf("format explicit port: %q", got)
	}
}
