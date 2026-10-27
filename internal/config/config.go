// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Package config ports src/config/schema.ts + loader.ts: YAML config with
// hand-rolled validation (the spec's decision over struct-tag validators —
// docs/go-backend-architecture.md §2). Defaults, refinements, error wording,
// and post-load derivations (absolute keyDirectory, SPA redirect URI) mirror
// the zod schema; config semantics are a frozen invariant of the rewrite.
package config

import (
	"crypto/x509"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/goccy/go-yaml"
	"golang.org/x/crypto/ssh"
)

// EndpointAddress is the parsed [user@]host[:port] form
// (src/utils/endpoint-address.ts).
type EndpointAddress struct {
	Username string
	Host     string
	Port     int
}

// HostKeyLine is a parsed config hostKey (#241): a full OpenSSH public-key
// line (preferred — enables host-key-algorithm pinning) or a bare
// "SHA256:..." fingerprint (Type empty, Key nil; compares on fingerprint).
type HostKeyLine struct {
	Type        string
	Key         []byte
	Fingerprint string
}

// ParseHostKey parses a hostKey config value: an OpenSSH public-key line
// ("ssh-ed25519 AAAA... [comment]") or a "SHA256:..." fingerprint.
func ParseHostKey(s string) (*HostKeyLine, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("hostKey must not be empty")
	}
	if strings.HasPrefix(s, "SHA256:") {
		return &HostKeyLine{Fingerprint: s}, nil
	}
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(s))
	if err != nil {
		return nil, fmt.Errorf("hostKey must be an OpenSSH public-key line or a SHA256: fingerprint: %v", err)
	}
	return &HostKeyLine{Type: key.Type(), Key: key.Marshal(), Fingerprint: ssh.FingerprintSHA256(key)}, nil
}

// SeedEndpoint mirrors SeedEndpointSchema: label + address (parsed at load
// time, like zod's transform) + agentForward (default true) + description +
// optional hostKey (#241, pinned at load with compare-and-set).
type SeedEndpoint struct {
	Label        string  `yaml:"label"`
	Address      string  `yaml:"address"`
	AgentForward *bool   `yaml:"agentForward"`
	Description  *string `yaml:"description"`
	HostKey      *string `yaml:"hostKey"`

	// Parsed is filled by Load from Address.
	Parsed EndpointAddress `yaml:"-"`
	// ParsedHostKey is filled by Load from HostKey (nil when absent).
	ParsedHostKey *HostKeyLine `yaml:"-"`
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
	// TrustProxy is bool | string | []string (false = never trust
	// X-Forwarded-For; true = trust every hop; CIDR string/list = trust only
	// those proxies). A numeric hop count is rejected at load time: it cannot
	// validate the immediate peer, so it is unsafe rather than merely unusual.
	TrustProxy any `yaml:"trustProxy"`
}

// Sessions is terminal-session housekeeping (#244): how long a session may sit
// without input/output before the idle janitor closes it (closeReason
// "idle-timeout"), and how often that janitor runs. Fractional values are
// allowed so test deployments can exercise the idle path quickly.
type Sessions struct {
	IdleTimeoutMinutes     float64 `yaml:"idleTimeoutMinutes"`
	CleanupIntervalSeconds float64 `yaml:"cleanupIntervalSeconds"`
}

// IdleTimeout returns idleTimeoutMinutes as a duration.
func (s Sessions) IdleTimeout() time.Duration {
	return time.Duration(s.IdleTimeoutMinutes * float64(time.Minute))
}

// CleanupInterval returns cleanupIntervalSeconds as a duration.
func (s Sessions) CleanupInterval() time.Duration {
	return time.Duration(s.CleanupIntervalSeconds * float64(time.Second))
}

type Notifications struct {
	Mcp struct {
		DebounceMs int `yaml:"debounceMs"`
	} `yaml:"mcp"`
}

// Mcp exists only to reject the removed sessionTimeoutMinutes setting with a
// migration hint (#243): the MCP surface is stateless, so there are no MCP
// sessions to expire — terminal sessions end via sessions.idleTimeoutMinutes.
type Mcp struct {
	// SessionTimeoutMinutes is REMOVED; any value is a validation error.
	SessionTimeoutMinutes *int `yaml:"sessionTimeoutMinutes"`
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

// HydraCimd configures OAuth Client ID Metadata Documents (CIMD,
// draft-ietf-oauth-client-id-metadata-document-02). CIMD reuses the DCR
// policy below for redirect-URI patterns and allowed scopes.
type HydraCimd struct {
	// Enabled defaults to true. When false, a URL client_id is passed through
	// to Hydra, which rejects it as an unknown client.
	Enabled *bool `yaml:"enabled"`
	// AllowedHosts, when non-empty, is an exact-match allowlist of client_id
	// hosts. BlockedHosts always wins.
	AllowedHosts []string `yaml:"allowedHosts"`
	BlockedHosts []string `yaml:"blockedHosts"`
	// Cache bounds for fetched documents (draft §5.2): HTTP cache headers are
	// honoured, then clamped into this range.
	CacheMinSeconds int `yaml:"cacheMinSeconds"`
	CacheMaxSeconds int `yaml:"cacheMaxSeconds"`
	// ExtraCaBundlePath adds the PEM certificates in this file to the system
	// trust store for metadata-document fetches — for a CIMD client hosted
	// behind a private CA, and for the e2e suite's throwaway CA. The system
	// roots are KEPT (see hydra.LoadExtraRoots), so publicly-hosted clients
	// keep working.
	ExtraCaBundlePath string `yaml:"extraCaBundlePath"`
	// AllowLoopbackDocuments permits fetching a document from a loopback
	// address. Draft §8.6 allows this for development and testing ONLY and
	// forbids it in production — it re-opens the SSRF hole the dial-time guard
	// closes. The e2e suite needs it to serve a document locally.
	AllowLoopbackDocuments bool `yaml:"allowLoopbackDocuments"`
}

type Hydra struct {
	PublicURL               string    `yaml:"publicUrl"`
	AdminURL                string    `yaml:"adminUrl"`
	Spa                     HydraSpa  `yaml:"spa"`
	IntrospectionCacheTtlMs *int      `yaml:"introspectionCacheTtlMs"`
	Dcr                     HydraDcr  `yaml:"dcr"`
	Cimd                    HydraCimd `yaml:"cimd"`
	// DevProxyUpstream (local dev): when set, ShellWatch itself reverse-proxies
	// Hydra's public surface (/oauth2/*, /userinfo, /.well-known/jwks.json,
	// /.well-known/openid-configuration) to this address — one origin for app
	// and OAuth, like the production reverse proxy, with no extra container.
	// Set publicUrl to the shared origin (= server.externalUrl) and point this
	// at the real Hydra listener (e.g. 'http://localhost:4444'); Hydra's own
	// urls.self.issuer/public must be the shared origin too (see
	// docker-compose.yml / docs/deployment.md). Leave unset in production.
	DevProxyUpstream string `yaml:"devProxyUpstream"`
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
	Mcp                Mcp                `yaml:"mcp"`
	AgentSocket        AgentSocket        `yaml:"agentSocket"`
	Sessions           Sessions           `yaml:"sessions"`
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

// CIMD document-cache bounds (draft §5.2 lets the AS set its own).
const (
	defaultCimdCacheMinSeconds = 300
	defaultCimdCacheMaxSeconds = 86_400
)

// Session housekeeping defaults (sessionsDefaults in the original schema):
// 30 min idle timeout, janitor every 60 s.
const (
	defaultIdleTimeoutMinutes     = 30
	defaultCleanupIntervalSeconds = 60
)

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

	// Post-load derivations (loader.ts). path.resolve semantics: an absolute
	// keyDirectory wins; a relative one resolves against the config file's dir.
	if !filepath.IsAbs(cfg.KeyDirectory) {
		cfg.KeyDirectory = filepath.Join(filepath.Dir(resolved), cfg.KeyDirectory)
	}
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
	if c.Sessions.IdleTimeoutMinutes == 0 {
		c.Sessions.IdleTimeoutMinutes = defaultIdleTimeoutMinutes
	}
	if c.Sessions.CleanupIntervalSeconds == 0 {
		c.Sessions.CleanupIntervalSeconds = defaultCleanupIntervalSeconds
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
	if c.Hydra.Cimd.Enabled == nil {
		v := true
		c.Hydra.Cimd.Enabled = &v
	}
	if c.Hydra.Cimd.CacheMinSeconds == 0 {
		c.Hydra.Cimd.CacheMinSeconds = defaultCimdCacheMinSeconds
	}
	if c.Hydra.Cimd.CacheMaxSeconds == 0 {
		c.Hydra.Cimd.CacheMaxSeconds = defaultCimdCacheMaxSeconds
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
	case bool, string:
	case int, int64, uint64, float64:
		add("server.trustProxy: a hop count is not supported (it cannot validate the immediate peer); use true, false, a CIDR/IP string, or a list of them")
	case []any:
		for _, e := range tp {
			if _, ok := e.(string); !ok {
				add("server.trustProxy: array entries must be strings")
				break
			}
		}
	default:
		add("server.trustProxy: must be a boolean, string, or array of strings")
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

	if c.Mcp.SessionTimeoutMinutes != nil {
		add("mcp.sessionTimeoutMinutes: removed — MCP is stateless (no protocol-level sessions to expire); terminal sessions end via sessions.idleTimeoutMinutes. Delete this key.")
	}

	if v := c.Sessions.IdleTimeoutMinutes; v <= 0 || v > 24*60 {
		add("sessions.idleTimeoutMinutes: must be > 0 and <= 1440")
	}
	if v := c.Sessions.CleanupIntervalSeconds; v <= 0 || v > 3600 {
		add("sessions.cleanupIntervalSeconds: must be > 0 and <= 3600")
	}

	if !isURL(c.Hydra.PublicURL) {
		add("hydra.publicUrl must be a valid URL — the shared public origin of app and OAuth, i.e. Hydra's urls.self.issuer (e.g. 'http://localhost:3000')")
	}
	if !isURL(c.Hydra.AdminURL) {
		add("hydra.adminUrl must be a valid URL (e.g. 'http://localhost:4445')")
	}
	if c.Hydra.Spa.RedirectURI != "" && !isURL(c.Hydra.Spa.RedirectURI) {
		add("hydra.spa.redirectUri: must be a valid URL")
	}
	if c.Hydra.DevProxyUpstream != "" && !isURL(c.Hydra.DevProxyUpstream) {
		add("hydra.devProxyUpstream: must be a valid URL (e.g. 'http://localhost:4444')")
	}
	if ttl := *c.Hydra.IntrospectionCacheTtlMs; ttl < 0 || ttl > 300_000 {
		add("hydra.introspectionCacheTtlMs: must be between 0 and 300000")
	}
	for _, p := range c.Hydra.Dcr.RedirectURIPatterns {
		if _, err := regexp.Compile(p); err != nil {
			add("hydra.dcr.redirectUriPatterns: %q is not a valid regular expression: %v", p, err)
		}
	}
	if min, max := c.Hydra.Cimd.CacheMinSeconds, c.Hydra.Cimd.CacheMaxSeconds; min < 1 || max < 1 || min > max {
		add("hydra.cimd.cacheMinSeconds/cacheMaxSeconds: both must be >= 1 and min must not exceed max")
	}
	if p := c.Hydra.Cimd.ExtraCaBundlePath; p != "" {
		// Checked here so a typo or an unreadable mount fails at startup rather
		// than when the first client behind that CA tries to authorize.
		switch raw, err := os.ReadFile(p); {
		case err != nil:
			add("hydra.cimd.extraCaBundlePath: cannot read %q: %v", p, err)
		case !x509.NewCertPool().AppendCertsFromPEM(raw):
			add("hydra.cimd.extraCaBundlePath: no PEM certificates found in %q", p)
		}
	}
	for _, h := range append(append([]string{}, c.Hydra.Cimd.AllowedHosts...), c.Hydra.Cimd.BlockedHosts...) {
		if strings.ContainsAny(h, "/:") || strings.TrimSpace(h) == "" {
			add("hydra.cimd.allowedHosts/blockedHosts: entries are bare hostnames, not URLs or host:port (got %q)", h)
		}
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
	if e.HostKey != nil {
		hk, err := ParseHostKey(*e.HostKey)
		if err != nil {
			return err
		}
		e.ParsedHostKey = hk
	}
	return nil
}
