// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

func TestMcpSessionTimeoutConfig(t *testing.T) {
	// Absent -> fine (the setting no longer exists, #243).
	if _, err := Load(writeConfig(t, minimalConfig)); err != nil {
		t.Fatal(err)
	}

	// Any present value -> hard error with a migration hint.
	for _, v := range []string{"0", "30"} {
		_, err := Load(writeConfig(t, minimalConfig+"\nmcp:\n  sessionTimeoutMinutes: "+v+"\n"))
		if err == nil || !strings.Contains(err.Error(), "mcp.sessionTimeoutMinutes: removed") {
			t.Errorf("value %s: expected removal error, got %v", v, err)
		}
	}
}

func TestSessionsConfig(t *testing.T) {
	cfg, err := Load(writeConfig(t, minimalConfig))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Sessions.IdleTimeout() != 30*time.Minute || cfg.Sessions.CleanupInterval() != time.Minute {
		t.Errorf("defaults: got idle=%v cleanup=%v", cfg.Sessions.IdleTimeout(), cfg.Sessions.CleanupInterval())
	}

	// Fractional values are accepted (test deployments drive the idle path fast).
	cfg, err = Load(writeConfig(t, minimalConfig+"\nsessions:\n  idleTimeoutMinutes: 0.05\n  cleanupIntervalSeconds: 0.5\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Sessions.IdleTimeout() != 3*time.Second || cfg.Sessions.CleanupInterval() != 500*time.Millisecond {
		t.Errorf("fractional: got idle=%v cleanup=%v", cfg.Sessions.IdleTimeout(), cfg.Sessions.CleanupInterval())
	}

	for _, bad := range []string{
		"idleTimeoutMinutes: -1", "idleTimeoutMinutes: 1441",
		"cleanupIntervalSeconds: -5", "cleanupIntervalSeconds: 3601",
	} {
		_, err := Load(writeConfig(t, minimalConfig+"\nsessions:\n  "+bad+"\n"))
		if err == nil || !strings.Contains(err.Error(), "sessions.") {
			t.Errorf("sessions %q: expected validation error, got %v", bad, err)
		}
	}
}

func TestTrustProxyForms(t *testing.T) {
	// minimalConfig already has a server block (duplicate keys are a YAML
	// error), so rebuild it with a trustProxy entry.
	noServer := strings.Replace(minimalConfig, "server:\n  externalUrl: http://localhost:3000\n", "", 1)
	base := noServer + "\nserver:\n  externalUrl: http://localhost:3000\n  trustProxy: "

	cfg, err := Load(writeConfig(t, base+"\n    - 10.0.0.0/8\n"))
	if err != nil {
		t.Fatal(err)
	}
	if list, ok := cfg.Server.TrustProxy.([]any); !ok || len(list) != 1 || list[0] != "10.0.0.0/8" {
		t.Errorf("CIDR list: got %#v", cfg.Server.TrustProxy)
	}

	// Hop counts are rejected at load (they cannot validate the immediate peer).
	_, err = Load(writeConfig(t, base+"1\n"))
	if err == nil || !strings.Contains(err.Error(), "trustProxy") {
		t.Errorf("hop count: expected a trustProxy validation error, got %v", err)
	}
}

// Host-key config values (#241): a full OpenSSH line, a bare SHA256:
// fingerprint, and rejection of anything else.
func TestParseHostKey(t *testing.T) {
	hk, err := ParseHostKey("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPLKV/zrLbSGFbSEOz6h3NwcnZ2TV1lLgcdB2z/+xwj7 comment")
	if err != nil || hk.Type != "ssh-ed25519" || len(hk.Key) == 0 || !strings.HasPrefix(hk.Fingerprint, "SHA256:") {
		t.Fatalf("public-key line: %+v err=%v", hk, err)
	}
	hk, err = ParseHostKey("SHA256:0Sf9Z6PSKJix1OTfTbJn9ZMumizbbeKkZN8wCRchemk")
	if err != nil || hk.Type != "" || hk.Key != nil || hk.Fingerprint != "SHA256:0Sf9Z6PSKJix1OTfTbJn9ZMumizbbeKkZN8wCRchemk" {
		t.Fatalf("fingerprint pin: %+v err=%v", hk, err)
	}
	for _, bad := range []string{"", "not-a-key", "md5:abc"} {
		if _, err := ParseHostKey(bad); err == nil {
			t.Errorf("ParseHostKey(%q) should fail", bad)
		}
	}
}

// A seed endpoint's hostKey is parsed at load time; an invalid one fails the
// config load with a pointed error.
func TestSeedEndpointHostKeyParsing(t *testing.T) {
	dir := t.TempDir()
	write := func(hostKey string) string {
		p := filepath.Join(dir, "config.yaml")
		body := `server:
  externalUrl: http://localhost:3000
security:
  rpId: localhost
  trustedWebauthnOrigins: ["http://localhost:3000"]
hydra:
  publicUrl: http://localhost:4444
  adminUrl: http://localhost:4445
seedAdminEndpoints:
  - label: Box
    address: u@h:22
    hostKey: "` + hostKey + `"
`
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	cfg, err := Load(write("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPLKV/zrLbSGFbSEOz6h3NwcnZ2TV1lLgcdB2z/+xwj7"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SeedAdminEndpoints[0].ParsedHostKey == nil || cfg.SeedAdminEndpoints[0].ParsedHostKey.Type != "ssh-ed25519" {
		t.Fatalf("hostKey not parsed: %+v", cfg.SeedAdminEndpoints[0].ParsedHostKey)
	}

	if _, err := Load(write("garbage")); err == nil || !strings.Contains(err.Error(), "hostKey") {
		t.Fatalf("invalid hostKey must fail the load: %v", err)
	}
}

// hydraConfig renders a valid config whose hydra block carries extra keys
// (minimalConfig ends with a list, so keys cannot just be appended).
func hydraConfig(extra string) string {
	return `
security:
  rpId: localhost
  trustedWebauthnOrigins:
    - http://localhost:3000
server:
  externalUrl: http://localhost:3000
hydra:
  publicUrl: http://localhost:4444
  adminUrl: http://localhost:4445
` + extra + `
seedAdminEndpoints:
  - label: Dev Box
    address: ubuntu@dev.example.com:2222
`
}

// A CA bundle that exists but holds no certificate must fail at load, not when
// the first client behind that CA tries to authorize.
func TestCimdExtraCaBundleValidation(t *testing.T) {
	dir := t.TempDir()
	junk := filepath.Join(dir, "junk.pem")
	if err := os.WriteFile(junk, []byte("not a certificate\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Load(writeConfig(t, hydraConfig("  cimd:\n    extraCaBundlePath: "+junk)))
	if err == nil || !strings.Contains(err.Error(), "no PEM certificates found") {
		t.Fatalf("want a no-certificates error, got %v", err)
	}

	// A real bundle loads.
	real := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(real, []byte(testCAPem), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(writeConfig(t, hydraConfig("  cimd:\n    extraCaBundlePath: "+real)))
	if err != nil {
		t.Fatalf("valid bundle rejected: %v", err)
	}
	if cfg.Hydra.Cimd.ExtraCaBundlePath != real {
		t.Errorf("extraCaBundlePath = %q", cfg.Hydra.Cimd.ExtraCaBundlePath)
	}
}

func TestCimdConfig(t *testing.T) {
	cfg, err := Load(writeConfig(t, minimalConfig))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Hydra.Cimd.Enabled == nil || !*cfg.Hydra.Cimd.Enabled {
		t.Error("hydra.cimd.enabled must default to true")
	}
	if cfg.Hydra.Cimd.CacheMinSeconds != 300 || cfg.Hydra.Cimd.CacheMaxSeconds != 86400 {
		t.Errorf("cache bounds: got %d/%d, want 300/86400",
			cfg.Hydra.Cimd.CacheMinSeconds, cfg.Hydra.Cimd.CacheMaxSeconds)
	}
	if cfg.Hydra.Cimd.AllowLoopbackDocuments {
		t.Error("allowLoopbackDocuments must default to false (draft §8.6 forbids it in production)")
	}

	// An explicit false is preserved, not re-defaulted.
	cfg, err = Load(writeConfig(t, hydraConfig("  cimd:\n    enabled: false")))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Hydra.Cimd.Enabled == nil || *cfg.Hydra.Cimd.Enabled {
		t.Error("hydra.cimd.enabled: an explicit false must be preserved")
	}

	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{"min above max", "  cimd:\n    cacheMinSeconds: 900\n    cacheMaxSeconds: 300", "cacheMinSeconds"},
		{"negative min", "  cimd:\n    cacheMinSeconds: -1", "cacheMinSeconds"},
		{"host as URL", "  cimd:\n    allowedHosts: ['https://apps.example.com']", "bare hostnames"},
		{"host with port", "  cimd:\n    blockedHosts: ['apps.example.com:443']", "bare hostnames"},
		{"bad dcr pattern", "  dcr:\n    redirectUriPatterns: ['([']", "not a valid regular expression"},
		{"missing ca bundle", "  cimd:\n    extraCaBundlePath: /nonexistent/ca.pem", "cannot read"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(writeConfig(t, hydraConfig(tc.yaml)))
			if err == nil {
				t.Fatalf("want error containing %q, got none", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

// testCAPem is a throwaway CA used only to prove a valid bundle is accepted.
const testCAPem = `-----BEGIN CERTIFICATE-----
MIIC+zCCAeOgAwIBAgIUfEEs97dogwazhvozMbP8HOZG3R8wDQYJKoZIhvcNAQEL
BQAwJDEiMCAGA1UEAwwZU2hlbGxXYXRjaCBjb25maWcgdGVzdCBDQTAgFw0yNjEw
MjYyMjUwNTlaGA8yMTI2MTAwMjIyNTA1OVowJDEiMCAGA1UEAwwZU2hlbGxXYXRj
aCBjb25maWcgdGVzdCBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
ANPnGw8xB4Rj7ND/6YEsGj40STz67KN+t0zvDqi+r3VGg+OkKHSL1OVb7/ukyLfB
VE9jMF4OS4sHCp4blnly7O89TYggcAdcvFs8JloqnIxAEIq3wf30zfPm8bmRRIxY
5uRhdzKNZJiS6RD0pVD+g63bNKrd3ElsMXuKyG6MUNMxBHm5aQfSu5Z/xi0ug5B5
1Nrth2M6qwbz1y5yFCibkhG+61SfxixxfWzQONCT1j32S2W5+Bu4ODyROMeF3+fW
ifvY7eNCsaz0U5LwsMGmFppnYLFK5z/W3iOrhhWNk9QHsoxyCFrj7lLSObzBljEc
sxoBNT9BV01esoH0Ot6I0hkCAwEAAaMjMCEwDwYDVR0TAQH/BAUwAwEB/zAOBgNV
HQ8BAf8EBAMCAgQwDQYJKoZIhvcNAQELBQADggEBALIp+yzWEpLhsI+EgQ6Dpq1q
FT8urauAucibIBmksBPPgSk94n0PN6SgD5MuSv01FbYdUNTpBsKSqHxGqk+UhDuD
050e0IOM0TlNlkJOml9x91mJQZOPDYnbKhSdhDWrO5iWfgtt9JhHhmE43cAo1W12
vMQVLBeqcFYF0+EBfaz1mMBSo9igy85w1puFDvNeoV0xiDLoU7J/iu9W7iwOzZ/Y
+I7LrRijmkdyOyu0rks3dN4z2saw+wFDGl6jXT2w1UnJ0r48AS4LMAhpSnbMbPlI
r5ivhFClgaczf/CHVzjUbEkcFEG4qMlQCSYr8yONVixqvur6cTm7Z3KMd/KcX5s=
-----END CERTIFICATE-----
`
