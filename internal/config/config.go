// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Package config ports src/config/schema.ts + loader.ts: YAML config with
// hand-rolled validation (the spec's decision over struct-tag validators —
// docs/go-backend-architecture.md §2). Defaults, refinements, error wording,
// and post-load derivations (absolute keyDirectory, SPA redirect URI) mirror
// the zod schema; config semantics are a frozen invariant of the rewrite.
package config

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/goccy/go-yaml"
)

// EndpointAddress is the parsed [user@]host[:port] form
// (src/utils/endpoint-address.ts).
type EndpointAddress struct {
	Username string
	Host     string
	Port     int
}

// SeedEndpoint mirrors SeedEndpointSchema: label + address (parsed at load
// time, like zod's transform) + agentForward (default true) + description.
type SeedEndpoint struct {
	Label        string  `yaml:"label"`
	Address      string  `yaml:"address"`
	AgentForward *bool   `yaml:"agentForward"`
	Description  *string `yaml:"description"`

	// Parsed is filled by Load from Address.
	Parsed EndpointAddress `yaml:"-"`
}

type SeedAdminPasskey struct {
	CredentialID string   `yaml:"credentialId"`
	PublicKeyHex string   `yaml:"publicKeyHex"`
	Counter      int      `yaml:"counter"`
	Transports   []string `yaml:"transports"`
	Label        string   `yaml:"label"`
}

type RateLimitRule struct {
	Max           int `yaml:"max"`
	WindowMinutes int `yaml:"windowMinutes"`
}

type RateLimit struct {
	SelfRegister    RateLimitRule `yaml:"selfRegister"`
	PasskeyRegister RateLimitRule `yaml:"passkeyRegister"`
	LoginOptions    RateLimitRule `yaml:"loginOptions"`
	LoginVerify     RateLimitRule `yaml:"loginVerify"`
}

type Security struct {
	RpID                    string    `yaml:"rpId"`
	AllowedNetworks         []string  `yaml:"allowedNetworks"`
	SelfRegistrationEnabled bool      `yaml:"selfRegistrationEnabled"`
	RateLimit               RateLimit `yaml:"rateLimit"`
	TrustedWebauthnOrigins  []string  `yaml:"trustedWebauthnOrigins"`
}

type Server struct {
	Port        int    `yaml:"port"`
	ExternalURL string `yaml:"externalUrl"`
	// TrustProxy is bool | int | string | []string, passed through to the
	// HTTP layer (Fastify semantics documented in schema.ts).
	TrustProxy any `yaml:"trustProxy"`
}

type Notifications struct {
	Mcp struct {
		DebounceMs int `yaml:"debounceMs"`
	} `yaml:"mcp"`
}

type AgentSocket struct {
	ProxyEnabled bool `yaml:"proxyEnabled"`
}

type HydraSpa struct {
	ClientID    string `yaml:"clientId"`
	RedirectURI string `yaml:"redirectUri"`
}

type HydraDcr struct {
	AllowedScopes       []string `yaml:"allowedScopes"`
	RedirectURIPatterns []string `yaml:"redirectUriPatterns"`
}

type Hydra struct {
	PublicURL               string   `yaml:"publicUrl"`
	AdminURL                string   `yaml:"adminUrl"`
	Spa                     HydraSpa `yaml:"spa"`
	IntrospectionCacheTtlMs *int     `yaml:"introspectionCacheTtlMs"`
	Dcr                     HydraDcr `yaml:"dcr"`
}

type Vapid struct {
	Subject    string `yaml:"subject"`
	PublicKey  string `yaml:"publicKey"`
	PrivateKey string `yaml:"privateKey"`
}

type Config struct {
	KeyDirectory       string             `yaml:"keyDirectory"`
	SeedAdminEndpoints []SeedEndpoint     `yaml:"seedAdminEndpoints"`
	SeedAdminPasskeys  []SeedAdminPasskey `yaml:"seedAdminPasskeys"`
	DemoEndpoints      []SeedEndpoint     `yaml:"demoEndpoints"`
	Server             Server             `yaml:"server"`
	Security           Security           `yaml:"security"`
	Notifications      Notifications      `yaml:"notifications"`
	AgentSocket        AgentSocket        `yaml:"agentSocket"`
	Hydra              Hydra              `yaml:"hydra"`
	Vapid              *Vapid             `yaml:"vapid"`
}

// Defaults mirroring schema.ts field defaults.
var (
	defaultAllowedNetworks = []string{"127.0.0.1/32", "::1/128"}
	defaultRateLimit       = RateLimit{
		SelfRegister:    RateLimitRule{Max: 5, WindowMinutes: 15},
		PasskeyRegister: RateLimitRule{Max: 10, WindowMinutes: 15},
		LoginOptions:    RateLimitRule{Max: 20, WindowMinutes: 15},
		LoginVerify:     RateLimitRule{Max: 10, WindowMinutes: 15},
	}
	defaultDcrAllowedScopes       = []string{"mcp", "agent"}
	defaultDcrRedirectURIPatterns = []string{
		`^http://(127\.0\.0\.1|localhost)(:\d+)?(/.*)?$`,
		`^http://\[::1\](:\d+)?(/.*)?$`,
	}
)

const defaultIntrospectionCacheTtlMs = 60_000

// Load reads, parses, defaults, validates, and derives — the equivalent of
// loadConfig in src/config/loader.ts. Resolution order for the path:
// explicit arg > SHELLWATCH_CONFIG env > ./config.yaml.
func Load(configPath string) (*Config, error) {
	if configPath == "" {
		configPath = os.Getenv("SHELLWATCH_CONFIG")
	}
	if configPath == "" {
		configPath = "config.yaml"
	}
	resolved, err := filepath.Abs(configPath)
	if err != nil {
		return nil, err
	}

	raw, err := os.ReadFile(resolved)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file at %s: %w", resolved, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse YAML config at %s: %w", resolved, err)
	}

	cfg.applyDefaults()
	if errs := cfg.validate(); len(errs) > 0 {
		return nil, fmt.Errorf("invalid config at %s:\n  - %s", resolved, strings.Join(errs, "\n  - "))
	}

	// Post-load derivations (loader.ts):
	cfg.KeyDirectory = filepath.Join(filepath.Dir(resolved), cfg.KeyDirectory)
	if abs, err := filepath.Abs(cfg.KeyDirectory); err == nil {
		cfg.KeyDirectory = abs
	}
	if cfg.Hydra.Spa.RedirectURI == "" {
		cfg.Hydra.Spa.RedirectURI = strings.TrimRight(cfg.Server.ExternalURL, "/") + "/auth/callback"
	}
	for i := range cfg.SeedAdminEndpoints {
		if err := cfg.SeedAdminEndpoints[i].parseAddress(); err != nil {
			return nil, fmt.Errorf("invalid config at %s:\n  - seedAdminEndpoints[%d]: %s", resolved, i, err)
		}
	}
	for i := range cfg.DemoEndpoints {
		if err := cfg.DemoEndpoints[i].parseAddress(); err != nil {
			return nil, fmt.Errorf("invalid config at %s:\n  - demoEndpoints[%d]: %s", resolved, i, err)
		}
	}
	return &cfg, nil
}

func (c *Config) applyDefaults() {
	if c.KeyDirectory == "" {
		c.KeyDirectory = "./keys"
	}
	if c.Server.Port == 0 {
		c.Server.Port = 3000
	}
	if c.Server.TrustProxy == nil {
		c.Server.TrustProxy = false
	}
	if c.Security.AllowedNetworks == nil {
		c.Security.AllowedNetworks = append([]string(nil), defaultAllowedNetworks...)
	}
	rl := &c.Security.RateLimit
	fillRule(&rl.SelfRegister, defaultRateLimit.SelfRegister)
	fillRule(&rl.PasskeyRegister, defaultRateLimit.PasskeyRegister)
	fillRule(&rl.LoginOptions, defaultRateLimit.LoginOptions)
	fillRule(&rl.LoginVerify, defaultRateLimit.LoginVerify)
	if c.Notifications.Mcp.DebounceMs == 0 {
		c.Notifications.Mcp.DebounceMs = 100
	}
	if c.Hydra.Spa.ClientID == "" {
		c.Hydra.Spa.ClientID = "shellwatch-web"
	}
	if c.Hydra.IntrospectionCacheTtlMs == nil {
		v := defaultIntrospectionCacheTtlMs
		c.Hydra.IntrospectionCacheTtlMs = &v
	}
	if c.Hydra.Dcr.AllowedScopes == nil {
		c.Hydra.Dcr.AllowedScopes = append([]string(nil), defaultDcrAllowedScopes...)
	}
	if c.Hydra.Dcr.RedirectURIPatterns == nil {
		c.Hydra.Dcr.RedirectURIPatterns = append([]string(nil), defaultDcrRedirectURIPatterns...)
	}
	for i := range c.SeedAdminPasskeys {
		if c.SeedAdminPasskeys[i].Label == "" {
			c.SeedAdminPasskeys[i].Label = "Admin Passkey"
		}
		if c.SeedAdminPasskeys[i].Transports == nil {
			c.SeedAdminPasskeys[i].Transports = []string{}
		}
	}
}

func fillRule(r *RateLimitRule, d RateLimitRule) {
	if r.Max == 0 {
		r.Max = d.Max
	}
	if r.WindowMinutes == 0 {
		r.WindowMinutes = d.WindowMinutes
	}
}

func (c *Config) validate() []string {
	var errs []string
	add := func(format string, args ...any) { errs = append(errs, fmt.Sprintf(format, args...)) }

	if c.Server.Port < 1 || c.Server.Port > 65535 {
		add("server.port: must be between 1 and 65535")
	}
	if !isURL(c.Server.ExternalURL) {
		add("server.externalUrl: must be a valid URL (e.g., 'http://localhost:3000')")
	}
	switch tp := c.Server.TrustProxy.(type) {
	case bool, string, uint64:
	case int:
		if tp < 0 {
			add("server.trustProxy: hop count must be >= 0")
		}
	case []any:
		for _, e := range tp {
			if _, ok := e.(string); !ok {
				add("server.trustProxy: array entries must be strings")
				break
			}
		}
	default:
		add("server.trustProxy: must be a boolean, number, string, or array of strings")
	}

	if c.Security.RpID == "" {
		add("security.rpId is required (e.g., 'localhost' or 'shellwatch.example.com')")
	}
	if len(c.Security.TrustedWebauthnOrigins) == 0 {
		add("security.trustedWebauthnOrigins requires at least one origin (e.g., 'https://shellwatch.example.com')")
	}
	for _, o := range c.Security.TrustedWebauthnOrigins {
		if !strings.HasPrefix(o, "http://") && !strings.HasPrefix(o, "https://") {
			add("security.trustedWebauthnOrigins: each entry must start with http:// or https:// (got %q)", o)
		}
	}
	for name, r := range map[string]RateLimitRule{
		"selfRegister": c.Security.RateLimit.SelfRegister, "passkeyRegister": c.Security.RateLimit.PasskeyRegister,
		"loginOptions": c.Security.RateLimit.LoginOptions, "loginVerify": c.Security.RateLimit.LoginVerify,
	} {
		if r.Max < 1 || r.WindowMinutes < 1 {
			add("security.rateLimit.%s: max and windowMinutes must be >= 1", name)
		}
	}

	if d := c.Notifications.Mcp.DebounceMs; d < 10 || d > 5000 {
		add("notifications.mcp.debounceMs: must be between 10 and 5000")
	}

	if !isURL(c.Hydra.PublicURL) {
		add("hydra.publicUrl must be a valid URL (e.g. 'http://localhost:4444')")
	}
	if !isURL(c.Hydra.AdminURL) {
		add("hydra.adminUrl must be a valid URL (e.g. 'http://localhost:4445')")
	}
	if c.Hydra.Spa.RedirectURI != "" && !isURL(c.Hydra.Spa.RedirectURI) {
		add("hydra.spa.redirectUri: must be a valid URL")
	}
	if ttl := *c.Hydra.IntrospectionCacheTtlMs; ttl < 0 || ttl > 300_000 {
		add("hydra.introspectionCacheTtlMs: must be between 0 and 300000")
	}

	for i, e := range c.SeedAdminEndpoints {
		if e.Label == "" {
			add("seedAdminEndpoints[%d].label: required", i)
		}
	}
	for i, e := range c.DemoEndpoints {
		if e.Label == "" {
			add("demoEndpoints[%d].label: required", i)
		}
	}
	for _, e := range append(append([]SeedEndpoint{}, c.SeedAdminEndpoints...), c.DemoEndpoints...) {
		if e.Description != nil && len(*e.Description) > 1000 {
			add("endpoint %q: description exceeds 1000 characters", e.Label)
		}
	}
	for i, p := range c.SeedAdminPasskeys {
		if p.CredentialID == "" || p.PublicKeyHex == "" {
			add("seedAdminPasskeys[%d]: credentialId and publicKeyHex are required", i)
		}
	}

	if c.Vapid != nil {
		if c.Vapid.Subject == "" {
			add("vapid.subject is required (e.g., 'mailto:admin@example.com')")
		}
		if c.Vapid.PublicKey == "" {
			add("vapid.publicKey is required (base64url-encoded VAPID public key)")
		}
		if c.Vapid.PrivateKey == "" {
			add("vapid.privateKey is required (base64url-encoded VAPID private key)")
		}
	}
	return errs
}

func isURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.Scheme != "" && u.Host != ""
}

// AgentForwardEnabled resolves the pointer default (true) from schema.ts.
func (e *SeedEndpoint) AgentForwardEnabled() bool {
	return e.AgentForward == nil || *e.AgentForward
}

func (e *SeedEndpoint) parseAddress() error {
	parsed, err := ParseEndpointAddress(e.Address)
	if err != nil {
		return err
	}
	e.Parsed = parsed
	return nil
}
