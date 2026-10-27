// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// CIMD retrieval (draft-ietf-oauth-client-id-metadata-document-02 §5, §8.6,
// §8.7): a deliberately hostile HTTP client — HTTPS only, no redirects, hard
// deadline, byte-capped body, and a dial-time guard that rejects special-use
// destinations AFTER DNS resolution (so a rebinding answer cannot slip past a
// hostname check) — plus the document cache of §5.2.
package hydra

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/rado0x54/shellwatch/internal/clock"
	"github.com/rado0x54/shellwatch/internal/ephemeral"
)

const (
	// cimdMaxBody is draft §8.7's recommended cap. It bounds bytes READ, not
	// the advertised file size, so a lying Content-Length cannot get around it.
	cimdMaxBody = 5 << 10
	// cimdTimeout is the whole-request deadline (connect + TLS + body).
	cimdTimeout = 5 * time.Second
	// cimdCacheCap bounds the number of cached documents, so an attacker
	// walking distinct URLs cannot grow the map without limit.
	cimdCacheCap = 512
)

// LoadExtraRoots returns the system trust store with the PEM certificates in
// path appended. It APPENDS deliberately: tls.Config.RootCAs replaces the
// system pool rather than adding to it, so handing the raw file to the fetcher
// would silently stop every publicly-hosted client from being trusted.
//
// Setting this also takes the fetcher off the platform verifier, which is the
// only way to trust a private CA on macOS — Go ignores SSL_CERT_FILE there
// (root_unix.go excludes darwin).
func LoadExtraRoots(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read CA bundle: %w", err)
	}
	pool, err := x509.SystemCertPool()
	if err != nil {
		// Refuse rather than fall back to the extra certs alone: that would
		// quietly narrow the trust store to one CA.
		return nil, fmt.Errorf("load system trust store: %w", err)
	}
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no PEM certificates found in %s", path)
	}
	return pool, nil
}

// FetcherParams configures the strict document fetcher.
type FetcherParams struct {
	// AllowLoopback permits loopback and private destinations. Draft §8.6
	// allows this exception for development and testing ONLY and forbids it in
	// production; config validation warns loudly. Tests need it to serve a
	// document from httptest.
	AllowLoopback bool
	// AllowedHosts, when non-empty, is an exact-match allowlist of client_id
	// hosts (draft §8.5 domain allowlist guidance). BlockedHosts always wins.
	AllowedHosts []string
	BlockedHosts []string
	CacheMin     time.Duration
	CacheMax     time.Duration
	Clock        clock.Clock
	// RootCAs is the trust store for document fetches; nil uses the platform
	// default. Build it with LoadExtraRoots so the system roots are kept.
	// HTTPS stays mandatory either way — this is not a verification bypass.
	RootCAs *x509.CertPool
}

// cachedDocument is a validated document plus the HTTP validators we keep so a
// refresh can be conditional.
type cachedDocument struct {
	Doc       ClientMetadata
	FetchedAt time.Time
}

// Fetcher retrieves and caches Client ID Metadata Documents.
type Fetcher struct {
	http    *http.Client
	params  FetcherParams
	cache   *ephemeral.Store[string, cachedDocument]
	clk     clock.Clock
	blocked map[string]bool
	allowed map[string]bool
}

// NewFetcher builds the hostile client. The returned Fetcher is safe for
// concurrent use.
func NewFetcher(p FetcherParams) *Fetcher {
	clk := p.Clock
	if clk == nil {
		clk = clock.Real{}
	}
	if p.CacheMin <= 0 {
		p.CacheMin = 5 * time.Minute
	}
	if p.CacheMax <= 0 {
		p.CacheMax = 24 * time.Hour
	}
	f := &Fetcher{
		params:  p,
		clk:     clk,
		blocked: lowerSet(p.BlockedHosts),
		allowed: lowerSet(p.AllowedHosts),
		// The store's own TTL is the ceiling; each entry gets its own TTL from
		// the response's cache headers via PutTTL.
		cache: ephemeral.New[string, cachedDocument](p.CacheMax, cimdCacheCap, clk),
	}
	dialer := &net.Dialer{
		Timeout: cimdTimeout,
		// Control runs with the RESOLVED address, for every address the dialer
		// tries — this is the SSRF choke point (draft §8.6).
		Control: func(network, address string, _ syscall.RawConn) error {
			return f.checkDialAddress(network, address)
		},
	}
	f.http = &http.Client{
		Timeout: cimdTimeout,
		// draft §5: MUST NOT automatically follow redirects.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return fmt.Errorf("redirects are not followed")
		},
		Transport: &http.Transport{
			DialContext:       dialer.DialContext,
			ForceAttemptHTTP2: true,
			// No proxy: a proxy would defeat the dial-time IP guard.
			Proxy:                 nil,
			TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: p.RootCAs},
			TLSHandshakeTimeout:   cimdTimeout,
			ResponseHeaderTimeout: cimdTimeout,
			DisableKeepAlives:     true,
		},
	}
	return f
}

// Fetch returns the document for clientIDURL, from cache when live. The bool
// reports whether the result came from cache (the front door uses it for the
// "first seen" consent hint and to skip a Hydra write).
//
// A validated document is cached; errors and invalid documents never are
// (draft §5.2).
func (f *Fetcher) Fetch(ctx context.Context, clientIDURL string, policy ClientPolicy) (ClientMetadata, bool, error) {
	if hit, ok := f.cache.Get(clientIDURL); ok {
		return hit.Doc, true, nil
	}
	doc, ttl, err := f.fetchUncached(ctx, clientIDURL, policy)
	if err != nil {
		return ClientMetadata{}, false, err
	}
	f.cache.PutTTL(clientIDURL, cachedDocument{Doc: doc, FetchedAt: f.clk.Now()}, ttl)
	return doc, false, nil
}

// Invalidate drops a cached document (used when provisioning fails, so the
// next attempt re-reads rather than trusting a document we could not apply).
func (f *Fetcher) Invalidate(clientIDURL string) { f.cache.Delete(clientIDURL) }

func (f *Fetcher) fetchUncached(ctx context.Context, clientIDURL string, policy ClientPolicy) (ClientMetadata, time.Duration, error) {
	u, err := ValidateClientIDURL(clientIDURL)
	if err != nil {
		return ClientMetadata{}, 0, err
	}
	host := strings.ToLower(u.Hostname())
	if f.blocked[host] {
		return ClientMetadata{}, 0, fmt.Errorf("client_id host is blocked")
	}
	if len(f.allowed) > 0 && !f.allowed[host] {
		return ClientMetadata{}, 0, fmt.Errorf("client_id host is not allowed")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, clientIDURL, nil)
	if err != nil {
		return ClientMetadata{}, 0, fmt.Errorf("client metadata unavailable")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "ShellWatch-CIMD/1")

	res, err := f.http.Do(req)
	if err != nil {
		return ClientMetadata{}, 0, fmt.Errorf("client metadata unavailable")
	}
	defer res.Body.Close()
	// draft §5: anything but 200 is an error; a 3xx reaches here because
	// CheckRedirect refuses, which also lands as an error from Do.
	if res.StatusCode != http.StatusOK {
		return ClientMetadata{}, 0, fmt.Errorf("client metadata returned HTTP %d", res.StatusCode)
	}
	if !isJSONContentType(res.Header.Get("Content-Type")) {
		return ClientMetadata{}, 0, fmt.Errorf("client metadata is not JSON")
	}

	// Read one byte past the cap so an oversize body is detected rather than
	// silently truncated into a parse error.
	body, err := io.ReadAll(io.LimitReader(res.Body, cimdMaxBody+1))
	if err != nil {
		return ClientMetadata{}, 0, fmt.Errorf("client metadata unavailable")
	}
	if len(body) > cimdMaxBody {
		return ClientMetadata{}, 0, fmt.Errorf("client metadata exceeds %d bytes", cimdMaxBody)
	}

	var doc ClientMetadata
	dec := json.NewDecoder(strings.NewReader(string(body)))
	if err := dec.Decode(&doc); err != nil {
		return ClientMetadata{}, 0, fmt.Errorf("client metadata is not valid JSON")
	}
	doc, err = ValidateDocument(doc, clientIDURL, policy)
	if err != nil {
		return ClientMetadata{}, 0, err
	}
	return doc, f.cacheTTL(res.Header), nil
}

// cacheTTL honours RFC 9111 cache headers, clamped into [CacheMin, CacheMax]
// (draft §5.2 lets the AS set its own bounds). no-store/no-cache collapse to
// the minimum rather than to zero: a document that forbids caching would
// otherwise make every authorization request re-fetch.
func (f *Fetcher) cacheTTL(h http.Header) time.Duration {
	ttl := f.params.CacheMin
	cc := strings.ToLower(h.Get("Cache-Control"))
	switch {
	case strings.Contains(cc, "no-store"), strings.Contains(cc, "no-cache"):
		return f.params.CacheMin
	case strings.Contains(cc, "max-age="):
		if secs, ok := parseMaxAge(cc); ok {
			ttl = time.Duration(secs) * time.Second
		}
	default:
		if exp := h.Get("Expires"); exp != "" {
			if t, err := http.ParseTime(exp); err == nil {
				ttl = t.Sub(f.clk.Now())
			}
		}
	}
	if ttl < f.params.CacheMin {
		return f.params.CacheMin
	}
	if ttl > f.params.CacheMax {
		return f.params.CacheMax
	}
	return ttl
}

func parseMaxAge(cc string) (int, bool) {
	for _, part := range strings.Split(cc, ",") {
		part = strings.TrimSpace(part)
		if !strings.HasPrefix(part, "max-age=") {
			continue
		}
		secs, err := strconv.Atoi(strings.TrimPrefix(part, "max-age="))
		if err != nil || secs < 0 {
			return 0, false
		}
		return secs, true
	}
	return 0, false
}

// checkDialAddress is the post-DNS SSRF guard (draft §8.6).
func (f *Fetcher) checkDialAddress(network, address string) error {
	if !strings.HasPrefix(network, "tcp") {
		return fmt.Errorf("refusing non-TCP network %q", network)
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("refusing unparseable address %q", address)
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("refusing non-literal address %q", host)
	}
	if isSpecialUse(addr) && !(f.params.AllowLoopback && addr.Unmap().IsLoopback()) {
		return fmt.Errorf("refusing special-use address %s", addr)
	}
	return nil
}

// specialUsePrefixes covers the RFC 6890 ranges that netip's predicates miss.
var specialUsePrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),          // "this network"
	netip.MustParsePrefix("100.64.0.0/10"),      // CGNAT
	netip.MustParsePrefix("192.0.0.0/24"),       // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),       // TEST-NET-1
	netip.MustParsePrefix("192.88.99.0/24"),     // 6to4 relay anycast
	netip.MustParsePrefix("198.18.0.0/15"),      // benchmarking
	netip.MustParsePrefix("198.51.100.0/24"),    // TEST-NET-2
	netip.MustParsePrefix("203.0.113.0/24"),     // TEST-NET-3
	netip.MustParsePrefix("240.0.0.0/4"),        // reserved
	netip.MustParsePrefix("255.255.255.255/32"), // broadcast
	netip.MustParsePrefix("::/128"),             // unspecified
	netip.MustParsePrefix("64:ff9b::/96"),       // NAT64
	netip.MustParsePrefix("100::/64"),           // discard-only
	netip.MustParsePrefix("2001::/23"),          // IETF protocol assignments
	netip.MustParsePrefix("2001:db8::/32"),      // documentation
	netip.MustParsePrefix("2002::/16"),          // 6to4
}

// isSpecialUse reports whether addr is anything but a routable public address.
func isSpecialUse(addr netip.Addr) bool {
	// An IPv4-mapped IPv6 address (::ffff:127.0.0.1) must be judged as its
	// IPv4 self, or the v4 predicates below never fire.
	addr = addr.Unmap()
	if !addr.IsValid() {
		return true
	}
	if addr.IsLoopback() || addr.IsUnspecified() || addr.IsPrivate() ||
		addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() ||
		addr.IsMulticast() || addr.IsInterfaceLocalMulticast() {
		return true
	}
	for _, p := range specialUsePrefixes {
		if p.Addr().Is4() == addr.Is4() && p.Contains(addr) {
			return true
		}
	}
	return false
}

// isJSONContentType accepts application/json and the application/…+json
// structured suffix the draft permits (§4).
func isJSONContentType(ct string) bool {
	mediaType := strings.ToLower(strings.TrimSpace(strings.Split(ct, ";")[0]))
	return mediaType == "application/json" ||
		(strings.HasPrefix(mediaType, "application/") && strings.HasSuffix(mediaType, "+json"))
}

func lowerSet(in []string) map[string]bool {
	out := map[string]bool{}
	for _, s := range in {
		if s = strings.ToLower(strings.TrimSpace(s)); s != "" {
			out[s] = true
		}
	}
	return out
}
