// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// OAuth Client ID Metadata Documents (CIMD), draft-ietf-oauth-client-id-
// metadata-document-02: the pure layer — Client Identifier URL rules (§3) and
// metadata document validation (§4). No I/O lives here; the strict fetcher is
// in cimd_fetch.go and the Hydra provisioning in cimd_resolver.go.
//
// Hydra does not implement CIMD (ory/hydra#4061), so ShellWatch resolves the
// URL client_id itself and provisions a Hydra client whose client_id IS the
// URL — the same mediation shape as DCR (/api/hydra/register).
package hydra

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// maxClientIDLen caps the Client Identifier URL. Hydra v26.2.0 on SQLite
// accepts longer ids, but the upstream CIMD RFC (ory/hydra#4134) cites a 255
// client_id column, so we stay inside that for portability.
const maxClientIDLen = 255

// IsClientIDURL reports whether a client_id is CIMD-shaped, i.e. whether the
// front door should resolve it instead of passing it through to Hydra. It is
// deliberately a cheap prefix test and NOT a validity check: a malformed
// https:// id must produce a CIMD error, never a silent Hydra passthrough
// (draft §7.1 — generated client_ids must not start with https://, which
// Hydra's UUIDs satisfy).
func IsClientIDURL(clientID string) bool {
	return strings.HasPrefix(clientID, "https://")
}

// ValidateClientIDURL enforces the Client Identifier URL rules of draft §3.
// It returns the parsed URL so callers can reuse the host.
//
// Deviation from §3, deliberate: a query component is "SHOULD NOT" in the
// draft and we reject it outright. §8.1 lets the authorization server impose
// restrictions, and a query-bearing id makes cache keying and the simple
// string comparison of §3 needlessly fragile.
func ValidateClientIDURL(clientID string) (*url.URL, error) {
	if clientID == "" {
		return nil, fmt.Errorf("client_id is required")
	}
	if len(clientID) > maxClientIDLen {
		return nil, fmt.Errorf("client_id must be at most %d characters", maxClientIDLen)
	}
	u, err := url.Parse(clientID)
	if err != nil {
		return nil, fmt.Errorf("client_id is not a valid URL")
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("client_id must use the https scheme")
	}
	if u.User != nil {
		return nil, fmt.Errorf("client_id must not contain a userinfo component")
	}
	if u.Hostname() == "" {
		return nil, fmt.Errorf("client_id must contain a host")
	}
	// Fragment and query: url.Parse keeps them separate, but a bare "#" or "?"
	// also sets ForceQuery/Fragment, so test the raw string too.
	if u.Fragment != "" || u.RawFragment != "" || strings.Contains(clientID, "#") {
		return nil, fmt.Errorf("client_id must not contain a fragment component")
	}
	if u.RawQuery != "" || u.ForceQuery || strings.Contains(clientID, "?") {
		return nil, fmt.Errorf("client_id must not contain a query component")
	}
	if u.Path == "" || u.Path == "/" {
		// §3 requires a path component and recommends against "/".
		return nil, fmt.Errorf("client_id must contain a path component")
	}
	for _, seg := range strings.Split(u.EscapedPath(), "/") {
		if seg == "." || seg == ".." {
			return nil, fmt.Errorf("client_id must not contain dot path segments")
		}
	}
	// §3 compares with simple string comparison (RFC 3986 §6.2.1), so any
	// re-serialization difference would make the document's client_id fail to
	// match the URL we fetched. Refuse ids that are not already normal form.
	if u.String() != clientID {
		return nil, fmt.Errorf("client_id must be in normalized form")
	}
	return u, nil
}

// ClientMetadata is the subset of the RFC 7591 client-metadata registry that
// ShellWatch honours in a Client ID Metadata Document. Shared-secret fields
// are present only so we can reject documents that carry them (draft §4.1).
type ClientMetadata struct {
	ClientID                string         `json:"client_id"`
	ClientName              string         `json:"client_name"`
	RedirectURIs            []string       `json:"redirect_uris"`
	GrantTypes              []string       `json:"grant_types"`
	ResponseTypes           []string       `json:"response_types"`
	Scope                   string         `json:"scope"`
	TokenEndpointAuthMethod string         `json:"token_endpoint_auth_method"`
	JwksURI                 string         `json:"jwks_uri"`
	Jwks                    map[string]any `json:"jwks"`
	LogoURI                 string         `json:"logo_uri"`
	ClientURI               string         `json:"client_uri"`
	PolicyURI               string         `json:"policy_uri"`
	TosURI                  string         `json:"tos_uri"`
	ApplicationType         string         `json:"application_type"`
	SoftwareID              string         `json:"software_id"`
	SoftwareVersion         string         `json:"software_version"`
	SoftwareStatement       string         `json:"software_statement"`
	ClientSecret            string         `json:"client_secret"`
	ClientSecretExpiresAt   *int64         `json:"client_secret_expires_at"`
	Contacts                []string       `json:"contacts"`
}

// ClientPolicy is the registration policy CIMD shares with mediated DCR
// (hydra.dcr.redirectUriPatterns + hydra.dcr.allowedScopes), compiled once at
// mount time.
type ClientPolicy struct {
	RedirectURIPatterns []*regexp.Regexp
	AllowedScopes       map[string]bool
}

// NewClientPolicy compiles the config policy. Uncompilable patterns are
// dropped (same lenient behaviour as MountProviders) — config validation is
// the place that rejects them.
func NewClientPolicy(patterns, scopes []string, agentProxyEnabled bool) ClientPolicy {
	p := ClientPolicy{
		RedirectURIPatterns: make([]*regexp.Regexp, 0, len(patterns)),
		AllowedScopes:       map[string]bool{},
	}
	for _, src := range patterns {
		if re, err := regexp.Compile(src); err == nil {
			p.RedirectURIPatterns = append(p.RedirectURIPatterns, re)
		}
	}
	for _, s := range scopes {
		if s == "agent" && !agentProxyEnabled {
			continue
		}
		p.AllowedScopes[s] = true
	}
	return p
}

// MatchRedirectURI reports whether the authorization request's redirect_uri is
// one of the document's registered URIs.
//
// draft §4.2 demands an exact match. We apply the one established exception,
// RFC 8252 §7.3: for a registered loopback IP URI the port may vary, because a
// native client binds an ephemeral port. This is not a loosening — fosite
// applies the same exception inside Hydra, so refusing it here would reject
// requests Hydra would go on to accept. "localhost" is NOT loopback for this
// purpose: it can resolve anywhere.
func MatchRedirectURI(registered []string, requested string) bool {
	req, err := url.Parse(requested)
	if err != nil {
		return false
	}
	for _, reg := range registered {
		if reg == requested {
			return true
		}
		regURL, err := url.Parse(reg)
		if err != nil || !isLoopbackHost(regURL.Hostname()) || !isLoopbackHost(req.Hostname()) {
			continue
		}
		// Everything but the port must still match exactly.
		if regURL.Scheme == req.Scheme && regURL.Hostname() == req.Hostname() &&
			regURL.EscapedPath() == req.EscapedPath() && regURL.RawQuery == req.RawQuery {
			return true
		}
	}
	return false
}

// isLoopbackHost is the RFC 8252 §7.3 host set — literal loopback IPs only.
func isLoopbackHost(host string) bool {
	return host == "127.0.0.1" || host == "::1"
}

// Supported auth methods (draft §4.1 forbids every shared-secret method;
// §8.2 recommends private_key_jwt for clients that can hold a key).
const (
	authMethodNone          = "none"
	authMethodPrivateKeyJWT = "private_key_jwt"
)

// ValidateDocument checks a fetched document against draft §4 and the
// ShellWatch DCR policy, returning the normalized metadata to provision.
//
// clientIDURL is the URL the document was fetched from; policy carries the
// redirect-URI patterns and allowed scopes CIMD shares with DCR.
func ValidateDocument(doc ClientMetadata, clientIDURL string, policy ClientPolicy) (ClientMetadata, error) {
	// §4: the document's client_id MUST match the Client Identifier URL, by
	// simple string comparison.
	if doc.ClientID != clientIDURL {
		return doc, fmt.Errorf("document client_id does not match the client_id URL")
	}
	// §4.1: no shared secrets, ever.
	if doc.ClientSecret != "" || doc.ClientSecretExpiresAt != nil {
		return doc, fmt.Errorf("document must not contain client_secret")
	}

	switch doc.TokenEndpointAuthMethod {
	case "":
		doc.TokenEndpointAuthMethod = authMethodNone
	case authMethodNone:
	case authMethodPrivateKeyJWT:
		if doc.JwksURI == "" && len(doc.Jwks) == 0 {
			return doc, fmt.Errorf("private_key_jwt requires jwks or jwks_uri")
		}
	default:
		return doc, fmt.Errorf("token_endpoint_auth_method %q is not supported", doc.TokenEndpointAuthMethod)
	}
	// §8.6: only fetch/parse URLs with known schemes. jwks_uri is fetched by
	// Hydra, so https is non-negotiable.
	if doc.JwksURI != "" {
		if err := requireHTTPSURL(doc.JwksURI, "jwks_uri"); err != nil {
			return doc, err
		}
	}
	for field, raw := range map[string]string{
		"client_uri": doc.ClientURI,
		"logo_uri":   doc.LogoURI,
		"policy_uri": doc.PolicyURI,
		"tos_uri":    doc.TosURI,
	} {
		if raw == "" {
			continue
		}
		if err := requireHTTPSURL(raw, field); err != nil {
			return doc, err
		}
	}

	// client_name is required by the MCP authorization spec; without it the
	// consent page has nothing but a hostname to show.
	if strings.TrimSpace(doc.ClientName) == "" {
		return doc, fmt.Errorf("client_name is required")
	}

	if len(doc.RedirectURIs) == 0 {
		return doc, fmt.Errorf("redirect_uris must be a non-empty array")
	}
	for _, uri := range doc.RedirectURIs {
		if !isAbsoluteURI(uri) {
			return doc, fmt.Errorf("redirect_uri is not an absolute URI: %s", uri)
		}
		if !matchAny(policy.RedirectURIPatterns, uri) {
			return doc, fmt.Errorf("redirect_uri not allowed by policy: %s", uri)
		}
	}

	if len(doc.GrantTypes) == 0 {
		doc.GrantTypes = []string{"authorization_code", "refresh_token"}
	}
	for _, gt := range doc.GrantTypes {
		if gt != "authorization_code" && gt != "refresh_token" {
			return doc, fmt.Errorf("grant_type %q is not supported", gt)
		}
	}
	if len(doc.ResponseTypes) == 0 {
		doc.ResponseTypes = []string{"code"}
	}
	for _, rt := range doc.ResponseTypes {
		if rt != "code" {
			return doc, fmt.Errorf("response_type %q is not supported", rt)
		}
	}
	return doc, nil
}

// GrantedScope filters a requested scope through the shared DCR allowlist and
// appends offline_access, exactly as handleDCR does. An empty intersection is
// an error — the client asked for nothing we can grant.
func GrantedScope(requested string, allowed map[string]bool) ([]string, error) {
	want := []string{"mcp"}
	if s := strings.TrimSpace(requested); s != "" {
		want = strings.Fields(s)
	}
	granted := make([]string, 0, len(want))
	for _, s := range want {
		if s == "offline_access" {
			continue
		}
		if allowed[s] {
			granted = append(granted, s)
		}
	}
	if len(granted) == 0 {
		return nil, fmt.Errorf("scope must be a subset of: %s", strings.Join(keys(allowed), " "))
	}
	return append(granted, "offline_access"), nil
}

func requireHTTPSURL(raw, field string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("%s must be an absolute https URL", field)
	}
	return nil
}

func isAbsoluteURI(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme != "" && (u.Host != "" || u.Opaque != "")
}
