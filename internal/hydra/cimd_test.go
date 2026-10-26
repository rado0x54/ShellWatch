// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// CIMD conformance tests against draft-ietf-oauth-client-id-metadata-
// document-02: Client Identifier URL rules (§3), document validation (§4),
// retrieval (§5), the SSRF guard (§8.6) and the body cap (§8.7).
package hydra

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rado0x54/shellwatch/internal/clock"
)

const testClientID = "https://apps.example.com/.well-known/client.json"

func testPolicy() ClientPolicy {
	return ClientPolicy{
		RedirectURIPatterns: []*regexp.Regexp{
			regexp.MustCompile(`^http://127\.0\.0\.1(:\d+)?/`),
			regexp.MustCompile(`^http://\[::1\](:\d+)?/`),
			regexp.MustCompile(`^https://apps\.example\.com/`),
		},
		AllowedScopes: map[string]bool{"mcp": true, "agent": true},
	}
}

// validDoc is the minimum document every validation case starts from.
func validDoc() ClientMetadata {
	return ClientMetadata{
		ClientID:     testClientID,
		ClientName:   "Example App",
		RedirectURIs: []string{"http://127.0.0.1/callback"},
	}
}

func TestValidateClientIDURL(t *testing.T) {
	// Exactly maxClientIDLen, so the boundary case is a real boundary.
	prefix := "https://apps.example.com/"
	long := prefix + strings.Repeat("a", maxClientIDLen-len(prefix))
	tests := []struct {
		name    string
		in      string
		wantErr string // substring; "" means accept
	}{
		{"canonical", testClientID, ""},
		{"with port", "https://apps.example.com:8443/client.json", ""},
		{"deep path", "https://apps.example.com/a/b/c", ""},
		{"empty", "", "required"},
		{"http scheme", "http://apps.example.com/client.json", "https scheme"},
		{"no scheme", "apps.example.com/client.json", "https scheme"},
		{"userinfo", "https://user@apps.example.com/client.json", "userinfo"},
		{"userinfo with password", "https://u:p@apps.example.com/c.json", "userinfo"},
		{"no host", "https:///client.json", "host"},
		{"fragment", "https://apps.example.com/c.json#frag", "fragment"},
		{"bare fragment", "https://apps.example.com/c.json#", "fragment"},
		{"query", "https://apps.example.com/c.json?x=1", "query"},
		{"bare query", "https://apps.example.com/c.json?", "query"},
		{"no path", "https://apps.example.com", "path component"},
		{"root path only", "https://apps.example.com/", "path component"},
		{"single dot segment", "https://apps.example.com/./c.json", "dot path segments"},
		{"double dot segment", "https://apps.example.com/a/../c.json", "dot path segments"},
		{"too long", long + "a", "at most 255"},
		{"at the length limit", long, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ValidateClientIDURL(tc.in)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("want accept, got error: %v", err)
			case tc.wantErr != "" && err == nil:
				t.Fatalf("want error %q, got accept", tc.wantErr)
			case tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr):
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

// §3: simple string comparison, so the default port is NOT normalized away.
func TestClientIDURLsAreComparedAsStrings(t *testing.T) {
	withPort := "https://apps.example.com:443/client.json"
	if _, err := ValidateClientIDURL(withPort); err != nil {
		t.Fatalf("explicit :443 must be a valid id: %v", err)
	}
	doc := validDoc()
	doc.ClientID = "https://apps.example.com/client.json"
	if _, err := ValidateDocument(doc, withPort, testPolicy()); err == nil {
		t.Fatal("a document whose client_id differs only by the default port must be rejected")
	}
}

func TestIsClientIDURL(t *testing.T) {
	// A malformed https id must still route to CIMD so it produces a CIMD
	// error, never a silent Hydra passthrough (§7.1).
	for _, id := range []string{testClientID, "https://apps.example.com", "https://"} {
		if !IsClientIDURL(id) {
			t.Errorf("IsClientIDURL(%q) = false, want true", id)
		}
	}
	for _, id := range []string{"shellwatch-web", "07f85190-7ac1-42d8-8a79-49ce076a8721", "http://x/y", ""} {
		if IsClientIDURL(id) {
			t.Errorf("IsClientIDURL(%q) = true, want false", id)
		}
	}
}

func TestValidateDocument(t *testing.T) {
	expires := int64(0)
	tests := []struct {
		name    string
		mutate  func(*ClientMetadata)
		wantErr string
	}{
		{"minimal valid", func(*ClientMetadata) {}, ""},
		{"client_id mismatch", func(d *ClientMetadata) {
			d.ClientID = "https://apps.example.com/other.json"
		}, "does not match"},
		{"client_id missing", func(d *ClientMetadata) { d.ClientID = "" }, "does not match"},
		{"client_secret present", func(d *ClientMetadata) { d.ClientSecret = "s3cret" }, "client_secret"},
		{"client_secret_expires_at present", func(d *ClientMetadata) {
			d.ClientSecretExpiresAt = &expires
		}, "client_secret"},
		{"client_secret_basic", func(d *ClientMetadata) {
			d.TokenEndpointAuthMethod = "client_secret_basic"
		}, "not supported"},
		{"client_secret_post", func(d *ClientMetadata) {
			d.TokenEndpointAuthMethod = "client_secret_post"
		}, "not supported"},
		{"client_secret_jwt", func(d *ClientMetadata) {
			d.TokenEndpointAuthMethod = "client_secret_jwt"
		}, "not supported"},
		{"none is explicit", func(d *ClientMetadata) { d.TokenEndpointAuthMethod = "none" }, ""},
		{"private_key_jwt without keys", func(d *ClientMetadata) {
			d.TokenEndpointAuthMethod = "private_key_jwt"
		}, "requires jwks"},
		{"private_key_jwt with jwks_uri", func(d *ClientMetadata) {
			d.TokenEndpointAuthMethod = "private_key_jwt"
			d.JwksURI = "https://apps.example.com/jwks.json"
		}, ""},
		{"private_key_jwt with inline jwks", func(d *ClientMetadata) {
			d.TokenEndpointAuthMethod = "private_key_jwt"
			d.Jwks = map[string]any{"keys": []any{}}
		}, ""},
		{"jwks_uri must be https", func(d *ClientMetadata) {
			d.TokenEndpointAuthMethod = "private_key_jwt"
			d.JwksURI = "http://apps.example.com/jwks.json"
		}, "jwks_uri"},
		{"client_uri javascript scheme", func(d *ClientMetadata) {
			d.ClientURI = "javascript:alert(1)"
		}, "client_uri"},
		{"logo_uri javascript scheme", func(d *ClientMetadata) {
			d.LogoURI = "javascript:alert(1)"
		}, "logo_uri"},
		{"client_name missing", func(d *ClientMetadata) { d.ClientName = "" }, "client_name"},
		{"client_name blank", func(d *ClientMetadata) { d.ClientName = "   " }, "client_name"},
		{"redirect_uris missing", func(d *ClientMetadata) { d.RedirectURIs = nil }, "redirect_uris"},
		{"redirect_uris empty", func(d *ClientMetadata) { d.RedirectURIs = []string{} }, "redirect_uris"},
		{"redirect_uri relative", func(d *ClientMetadata) {
			d.RedirectURIs = []string{"/callback"}
		}, "absolute"},
		{"redirect_uri against policy", func(d *ClientMetadata) {
			d.RedirectURIs = []string{"https://evil.example.net/callback"}
		}, "not allowed by policy"},
		{"grant_type unsupported", func(d *ClientMetadata) {
			d.GrantTypes = []string{"client_credentials"}
		}, "grant_type"},
		{"grant_type implicit", func(d *ClientMetadata) {
			d.GrantTypes = []string{"implicit"}
		}, "grant_type"},
		{"response_type unsupported", func(d *ClientMetadata) {
			d.ResponseTypes = []string{"token"}
		}, "response_type"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc := validDoc()
			tc.mutate(&doc)
			got, err := ValidateDocument(doc, testClientID, testPolicy())
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("want accept, got error: %v", err)
			case tc.wantErr != "" && err == nil:
				t.Fatalf("want error %q, got accept", tc.wantErr)
			case tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr):
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			case tc.wantErr != "":
				return
			}
			// Defaults applied on the accept path.
			if got.TokenEndpointAuthMethod == "" {
				t.Error("token_endpoint_auth_method must default to none")
			}
			if len(got.GrantTypes) == 0 || len(got.ResponseTypes) == 0 {
				t.Error("grant_types/response_types must be defaulted")
			}
		})
	}
}

func TestValidateDocumentDefaults(t *testing.T) {
	got, err := ValidateDocument(validDoc(), testClientID, testPolicy())
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if got.TokenEndpointAuthMethod != authMethodNone {
		t.Errorf("auth method = %q, want none", got.TokenEndpointAuthMethod)
	}
	if !sameStrings(got.GrantTypes, []string{"authorization_code", "refresh_token"}) {
		t.Errorf("grant_types = %v", got.GrantTypes)
	}
	if !sameStrings(got.ResponseTypes, []string{"code"}) {
		t.Errorf("response_types = %v", got.ResponseTypes)
	}
}

func TestGrantedScope(t *testing.T) {
	allowed := map[string]bool{"mcp": true, "agent": true}
	tests := []struct {
		name      string
		requested string
		want      []string
		wantErr   bool
	}{
		{"empty defaults to mcp", "", []string{"mcp", "offline_access"}, false},
		{"single", "mcp", []string{"mcp", "offline_access"}, false},
		{"both", "mcp agent", []string{"mcp", "agent", "offline_access"}, false},
		{"filters unknown", "mcp admin", []string{"mcp", "offline_access"}, false},
		{"offline_access is not double-appended", "mcp offline_access", []string{"mcp", "offline_access"}, false},
		{"all filtered out", "admin root", nil, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := GrantedScope(tc.requested, allowed)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want error, got %v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if strings.Join(got, " ") != strings.Join(tc.want, " ") {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

// RFC 8252 §7.3: a registered loopback URI matches any port, and only for a
// literal loopback IP. This mirrors what fosite does inside Hydra.
func TestMatchRedirectURI(t *testing.T) {
	registered := []string{
		"http://127.0.0.1/callback",
		"http://[::1]/callback",
		"https://apps.example.com/cb",
	}
	tests := []struct {
		name      string
		requested string
		want      bool
	}{
		{"exact loopback", "http://127.0.0.1/callback", true},
		{"loopback with port", "http://127.0.0.1:54321/callback", true},
		{"ipv6 loopback with port", "http://[::1]:54321/callback", true},
		{"exact https", "https://apps.example.com/cb", true},
		{"localhost is not loopback", "http://localhost:54321/callback", false},
		{"different path", "http://127.0.0.1:54321/other", false},
		{"different scheme", "https://127.0.0.1:54321/callback", false},
		{"https host with another port", "https://apps.example.com:8443/cb", false},
		{"unregistered host", "http://10.0.0.1:54321/callback", false},
		{"added query", "http://127.0.0.1:54321/callback?x=1", false},
		{"empty", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := MatchRedirectURI(registered, tc.requested); got != tc.want {
				t.Fatalf("MatchRedirectURI(%q) = %v, want %v", tc.requested, got, tc.want)
			}
		})
	}
}

// §8.6: the dial-time guard is the SSRF choke point, and it sees the RESOLVED
// address — so a rebinding DNS answer is caught here, not at hostname parse.
func TestSSRFGuardRejectsSpecialUseAddresses(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "127.1.2.3", "::1", // loopback
		"10.0.0.1", "172.16.0.1", "192.168.1.1", "fd00::1", // private / ULA
		"169.254.169.254", "fe80::1", // link-local (cloud metadata)
		"0.0.0.0", "::", // unspecified
		"100.64.0.1",       // CGNAT
		"192.0.2.1",        // TEST-NET-1
		"198.18.0.1",       // benchmarking
		"198.51.100.1",     // TEST-NET-2
		"203.0.113.1",      // TEST-NET-3
		"224.0.0.1",        // multicast
		"255.255.255.255",  // broadcast
		"240.0.0.1",        // reserved
		"2001:db8::1",      // documentation
		"::ffff:127.0.0.1", // IPv4-mapped loopback must be unwrapped
		"::ffff:169.254.169.254",
	}
	for _, s := range blocked {
		if !isSpecialUse(netip.MustParseAddr(s)) {
			t.Errorf("isSpecialUse(%s) = false, want true", s)
		}
	}
	for _, s := range []string{"93.184.216.34", "8.8.8.8", "2606:2800:220:1::1"} {
		if isSpecialUse(netip.MustParseAddr(s)) {
			t.Errorf("isSpecialUse(%s) = true, want false (public)", s)
		}
	}

	f := NewFetcher(FetcherParams{})
	if err := f.checkDialAddress("tcp", "169.254.169.254:443"); err == nil {
		t.Error("cloud metadata address must be refused at dial time")
	}
	if err := f.checkDialAddress("tcp", "93.184.216.34:443"); err != nil {
		t.Errorf("public address must be allowed: %v", err)
	}
	if err := f.checkDialAddress("unix", "/var/run/x.sock:0"); err == nil {
		t.Error("non-TCP network must be refused")
	}

	// The loopback exception is opt-in and dev-only (§8.6).
	dev := NewFetcher(FetcherParams{AllowLoopback: true})
	if err := dev.checkDialAddress("tcp", "127.0.0.1:443"); err != nil {
		t.Errorf("AllowLoopback must permit loopback: %v", err)
	}
	if err := dev.checkDialAddress("tcp", "10.0.0.1:443"); err == nil {
		t.Error("AllowLoopback must NOT permit other private ranges")
	}
}

func TestFetchRefusesSpecialUseHostsWithoutAnyRequest(t *testing.T) {
	f := NewFetcher(FetcherParams{})
	for _, id := range []string{
		"https://169.254.169.254/latest/meta-data/client.json",
		"https://10.0.0.1/client.json",
		"https://[::1]/client.json",
	} {
		if _, _, err := f.Fetch(context.Background(), id, testPolicy()); err == nil {
			t.Errorf("Fetch(%q) must fail", id)
		}
	}
}

// docServer serves a CIMD document over TLS on loopback and hands back a
// fetcher that trusts it (the dev-only loopback exception plus the test CA).
func docServer(t *testing.T, handler http.HandlerFunc, p FetcherParams) (*httptest.Server, *Fetcher, string) {
	t.Helper()
	srv := httptest.NewTLSServer(handler)
	t.Cleanup(srv.Close)

	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	p.AllowLoopback = true
	p.RootCAs = pool
	return srv, NewFetcher(p), srv.URL + "/client.json"
}

// writeDoc serves doc as application/json with the given headers.
func writeDoc(doc any, headers map[string]string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		for k, v := range headers {
			w.Header().Set(k, v)
		}
		if w.Header().Get("Content-Type") == "" {
			w.Header().Set("Content-Type", "application/json")
		}
		_ = json.NewEncoder(w).Encode(doc)
	}
}

func TestFetchHappyPath(t *testing.T) {
	var hits int
	var clientID string
	_, f, url := docServer(t, func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"client_id":     clientID,
			"client_name":   "Example App",
			"redirect_uris": []string{"http://127.0.0.1/callback"},
		})
	}, FetcherParams{})
	clientID = url

	doc, cached, err := f.Fetch(context.Background(), url, testPolicy())
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if cached {
		t.Error("first fetch must not report a cache hit")
	}
	if doc.ClientName != "Example App" {
		t.Errorf("client_name = %q", doc.ClientName)
	}

	// §5.2: a validated document is cached, so the second call does no I/O.
	_, cached, err = f.Fetch(context.Background(), url, testPolicy())
	if err != nil || !cached {
		t.Fatalf("second fetch: cached=%v err=%v", cached, err)
	}
	if hits != 1 {
		t.Errorf("server hits = %d, want 1", hits)
	}
}

func TestFetchRetrievalRules(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
		wantErr string
	}{
		{"non-200 is an error", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}, "HTTP 404"},
		{"201 is an error too", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{}`))
		}, "HTTP 201"},
		{"redirects are not followed", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://apps.example.com/elsewhere.json", http.StatusFound)
		}, "unavailable"},
		{"non-JSON content type", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`{"client_id":"x"}`))
		}, "not JSON"},
		{"malformed JSON", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"client_id":`))
		}, "not valid JSON"},
		{"oversize body", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"padding":"` + strings.Repeat("x", cimdMaxBody+100) + `"}`))
		}, "exceeds"},
		{"oversize chunked body, no declared length", func(w http.ResponseWriter, _ *http.Request) {
			// §8.7 caps bytes READ, so an undeclared (chunked) length must not
			// get a large body past the limit.
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			for i := 0; i < 10; i++ {
				_, _ = w.Write([]byte(strings.Repeat("x", 1024)))
				w.(http.Flusher).Flush()
			}
		}, "exceeds"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, f, url := docServer(t, tc.handler, FetcherParams{})
			_, _, err := f.Fetch(context.Background(), url, testPolicy())
			if err == nil {
				t.Fatalf("want error %q, got accept", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestFetchAcceptsStructuredJSONSuffix(t *testing.T) {
	var clientID string
	_, f, url := docServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/client-metadata+json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"client_id":     clientID,
			"client_name":   "Example App",
			"redirect_uris": []string{"http://127.0.0.1/callback"},
		})
	}, FetcherParams{})
	clientID = url
	if _, _, err := f.Fetch(context.Background(), url, testPolicy()); err != nil {
		t.Fatalf("application/…+json must be accepted: %v", err)
	}
}

// §5.2: errors and invalid documents MUST NOT be cached.
func TestFetchNeverCachesFailures(t *testing.T) {
	cases := []struct {
		name    string
		handler func(hits *int, clientID *string) http.HandlerFunc
	}{
		{"error response", func(hits *int, _ *string) http.HandlerFunc {
			return func(w http.ResponseWriter, _ *http.Request) {
				*hits++
				w.Header().Set("Cache-Control", "max-age=86400")
				w.WriteHeader(http.StatusInternalServerError)
			}
		}},
		{"invalid document", func(hits *int, clientID *string) http.HandlerFunc {
			return func(w http.ResponseWriter, _ *http.Request) {
				*hits++
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Cache-Control", "max-age=86400")
				// client_id mismatch -> invalid.
				_ = json.NewEncoder(w).Encode(map[string]any{
					"client_id":     "https://apps.example.com/other.json",
					"client_name":   "Example App",
					"redirect_uris": []string{"http://127.0.0.1/callback"},
				})
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var hits int
			var clientID string
			_, f, url := docServer(t, tc.handler(&hits, &clientID), FetcherParams{})
			clientID = url
			for i := 0; i < 3; i++ {
				if _, _, err := f.Fetch(context.Background(), url, testPolicy()); err == nil {
					t.Fatal("want error")
				}
			}
			if hits != 3 {
				t.Fatalf("server hits = %d, want 3 (nothing may be cached)", hits)
			}
		})
	}
}

// §5.2: respect cache headers, but clamp into our own bounds.
func TestCacheTTLClamping(t *testing.T) {
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	f := NewFetcher(FetcherParams{
		CacheMin: 5 * time.Minute,
		CacheMax: 24 * time.Hour,
		Clock:    clock.NewFake(now),
	})
	tests := []struct {
		name   string
		header http.Header
		want   time.Duration
	}{
		{"no headers -> min", http.Header{}, 5 * time.Minute},
		{"max-age below min -> min", http.Header{"Cache-Control": {"max-age=10"}}, 5 * time.Minute},
		{"max-age in range", http.Header{"Cache-Control": {"max-age=3600"}}, time.Hour},
		{"max-age above max -> max", http.Header{"Cache-Control": {"max-age=999999"}}, 24 * time.Hour},
		{"no-store -> min", http.Header{"Cache-Control": {"no-store"}}, 5 * time.Minute},
		{"no-cache -> min", http.Header{"Cache-Control": {"no-cache"}}, 5 * time.Minute},
		{"public, max-age mixed", http.Header{"Cache-Control": {"public, max-age=7200"}}, 2 * time.Hour},
		{"negative max-age -> min", http.Header{"Cache-Control": {"max-age=-5"}}, 5 * time.Minute},
		{"garbage max-age -> min", http.Header{"Cache-Control": {"max-age=abc"}}, 5 * time.Minute},
		{"expires in range", http.Header{"Expires": {now.Add(time.Hour).Format(http.TimeFormat)}}, time.Hour},
		{"expires in the past -> min", http.Header{"Expires": {now.Add(-time.Hour).Format(http.TimeFormat)}}, 5 * time.Minute},
		{"cache-control wins over expires", http.Header{
			"Cache-Control": {"max-age=3600"},
			"Expires":       {now.Add(100 * time.Hour).Format(http.TimeFormat)},
		}, time.Hour},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := f.cacheTTL(tc.header); got != tc.want {
				t.Fatalf("cacheTTL = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCacheExpiryRefetches(t *testing.T) {
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	fake := clock.NewFake(now)
	var hits int
	var clientID string
	_, f, url := docServer(t, func(w http.ResponseWriter, _ *http.Request) {
		hits++
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "max-age=600")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"client_id":     clientID,
			"client_name":   "Example App",
			"redirect_uris": []string{"http://127.0.0.1/callback"},
		})
	}, FetcherParams{CacheMin: time.Minute, CacheMax: time.Hour, Clock: fake})
	clientID = url

	if _, _, err := f.Fetch(context.Background(), url, testPolicy()); err != nil {
		t.Fatalf("fetch: %v", err)
	}
	fake.Advance(9 * time.Minute)
	if _, cached, _ := f.Fetch(context.Background(), url, testPolicy()); !cached {
		t.Error("document must still be cached at 9m of a 10m TTL")
	}
	fake.Advance(2 * time.Minute)
	if _, cached, _ := f.Fetch(context.Background(), url, testPolicy()); cached {
		t.Error("document must be re-fetched after its TTL")
	}
	if hits != 2 {
		t.Errorf("server hits = %d, want 2", hits)
	}
}

func TestFetchHostAllowAndBlockLists(t *testing.T) {
	// Both lists are matched on the client_id host; blocked always wins.
	f := NewFetcher(FetcherParams{BlockedHosts: []string{"Blocked.Example.com"}})
	if _, _, err := f.Fetch(context.Background(), "https://blocked.example.com/c.json", testPolicy()); err == nil ||
		!strings.Contains(err.Error(), "blocked") {
		t.Errorf("blocked host: got %v", err)
	}
	f = NewFetcher(FetcherParams{AllowedHosts: []string{"apps.example.com"}})
	if _, _, err := f.Fetch(context.Background(), "https://other.example.com/c.json", testPolicy()); err == nil ||
		!strings.Contains(err.Error(), "not allowed") {
		t.Errorf("non-allowlisted host: got %v", err)
	}
	f = NewFetcher(FetcherParams{
		AllowedHosts: []string{"apps.example.com"},
		BlockedHosts: []string{"apps.example.com"},
	})
	if _, _, err := f.Fetch(context.Background(), testClientID, testPolicy()); err == nil ||
		!strings.Contains(err.Error(), "blocked") {
		t.Errorf("blocked must win over allowed: got %v", err)
	}
}

// --- resolver ---------------------------------------------------------------

// fakeAdmin is the admin surface the CIMD resolver uses. internal/hydratest
// imports this package, so the in-package tests need their own.
type fakeAdmin struct {
	mu      sync.Mutex
	clients map[string]OAuth2Client
	creates int
	updates int
	// createErr, when set, is returned by the next CreateClient.
	createErr error
}

func newFakeAdmin() *fakeAdmin {
	return &fakeAdmin{clients: map[string]OAuth2Client{}}
}

func (f *fakeAdmin) CreateClient(_ context.Context, c OAuth2Client) (OAuth2Client, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.createErr != nil {
		err := f.createErr
		f.createErr = nil
		return OAuth2Client{}, err
	}
	if _, exists := f.clients[c.ClientID]; exists {
		return OAuth2Client{}, &APIError{Status: http.StatusConflict, Msg: "client exists"}
	}
	f.creates++
	f.clients[c.ClientID] = c
	return c, nil
}

func (f *fakeAdmin) GetClient(_ context.Context, id string) (*OAuth2Client, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.clients[id]
	if !ok {
		return nil, nil
	}
	return &c, nil
}

func (f *fakeAdmin) UpdateClient(_ context.Context, id string, c OAuth2Client) (OAuth2Client, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.updates++
	f.clients[id] = c
	return c, nil
}

func (f *fakeAdmin) stored(id string) OAuth2Client {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.clients[id]
}

func (f *fakeAdmin) counts() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.creates, f.updates
}

// Unused by CIMD; present to satisfy Admin.
func (f *fakeAdmin) Introspect(context.Context, string) (Introspection, error) {
	return Introspection{}, fmt.Errorf("not implemented")
}
func (f *fakeAdmin) AcceptLoginRequest(context.Context, string, AcceptLogin) (Redirect, error) {
	return Redirect{}, nil
}
func (f *fakeAdmin) GetLoginRequest(context.Context, string) (LoginRequest, error) {
	return LoginRequest{}, nil
}
func (f *fakeAdmin) GetConsentRequest(context.Context, string) (ConsentRequest, error) {
	return ConsentRequest{}, nil
}
func (f *fakeAdmin) AcceptConsentRequest(context.Context, string, AcceptConsent) (Redirect, error) {
	return Redirect{}, nil
}
func (f *fakeAdmin) ListConsentSessions(context.Context, string) ([]ConsentSession, error) {
	return nil, nil
}
func (f *fakeAdmin) RevokeConsentSessions(context.Context, string, string) error { return nil }
func (f *fakeAdmin) RevokeLoginSessions(context.Context, string) error           { return nil }
func (f *fakeAdmin) GetLogoutRequest(context.Context, string) (LogoutRequest, error) {
	return LogoutRequest{}, nil
}
func (f *fakeAdmin) AcceptLogoutRequest(context.Context, string) (Redirect, error) {
	return Redirect{}, nil
}
func (f *fakeAdmin) RejectLogoutRequest(context.Context, string) error { return nil }

var _ Admin = (*fakeAdmin)(nil)

// resolverFixture serves a mutable document and returns the resolver over it.
func resolverFixture(t *testing.T, doc *map[string]any) (*CIMDResolver, *fakeAdmin, string, *int) {
	t.Helper()
	var hits int
	admin := newFakeAdmin()
	_, f, url := docServer(t, func(w http.ResponseWriter, _ *http.Request) {
		hits++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(*doc)
	}, FetcherParams{CacheMin: 5 * time.Minute, CacheMax: time.Hour})
	(*doc)["client_id"] = url
	return NewCIMDResolver(CIMDResolverParams{
		Admin: admin, Fetcher: f, Policy: testPolicy(),
	}), admin, url, &hits
}

func TestResolveProvisionsHydraClientWithTheURLAsID(t *testing.T) {
	doc := map[string]any{
		"client_name":   "Example App",
		"redirect_uris": []string{"http://127.0.0.1/callback"},
		"client_uri":    "https://apps.example.com/",
		"logo_uri":      "https://apps.example.com/logo.png",
	}
	r, admin, url, _ := resolverFixture(t, &doc)

	res, err := r.Resolve(context.Background(), url, "http://127.0.0.1:54321/callback", "mcp")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !res.FirstSeen {
		t.Error("a newly provisioned client must report FirstSeen")
	}
	got := admin.stored(url)
	if got.ClientID != url {
		t.Errorf("client_id = %q, want the URL %q", got.ClientID, url)
	}
	if got.ClientName != "Example App" {
		t.Errorf("client_name = %q", got.ClientName)
	}
	if got.Scope != "mcp offline_access" {
		t.Errorf("scope = %q, want \"mcp offline_access\"", got.Scope)
	}
	if got.TokenEndpointAuthMethod != "none" {
		t.Errorf("auth method = %q", got.TokenEndpointAuthMethod)
	}
	// §9.3: the logo is never carried into Hydra, so no consent page can
	// render a remote image.
	if got.Metadata == nil {
		t.Fatal("metadata must mark the CIMD origin")
	}
	if !isCIMDClient(&got) {
		t.Errorf("metadata = %v, want origin cimd", got.Metadata)
	}
	raw, _ := json.Marshal(got)
	if strings.Contains(string(raw), "logo.png") {
		t.Error("logo_uri must not reach Hydra")
	}
}

func TestResolveRejectsUnregisteredRedirectURI(t *testing.T) {
	doc := map[string]any{
		"client_name":   "Example App",
		"redirect_uris": []string{"http://127.0.0.1/callback"},
	}
	r, admin, url, _ := resolverFixture(t, &doc)

	_, err := r.Resolve(context.Background(), url, "http://127.0.0.1:54321/evil", "mcp")
	if err == nil {
		t.Fatal("want error for an unregistered redirect_uri")
	}
	if creates, _ := admin.counts(); creates != 0 {
		t.Errorf("nothing may be written to Hydra on rejection (creates=%d)", creates)
	}
}

func TestResolveIsIdempotentAndCacheHitsSkipHydra(t *testing.T) {
	doc := map[string]any{
		"client_name":   "Example App",
		"redirect_uris": []string{"http://127.0.0.1/callback"},
	}
	r, admin, url, hits := resolverFixture(t, &doc)

	for i := 0; i < 3; i++ {
		if _, err := r.Resolve(context.Background(), url, "http://127.0.0.1:1/callback", "mcp"); err != nil {
			t.Fatalf("resolve %d: %v", i, err)
		}
	}
	creates, updates := admin.counts()
	if creates != 1 || updates != 0 {
		t.Errorf("creates=%d updates=%d, want 1/0", creates, updates)
	}
	if *hits != 1 {
		t.Errorf("document fetches = %d, want 1 (cached)", *hits)
	}
}

func TestResolveConcurrentFirstSeenProvisionsOnce(t *testing.T) {
	doc := map[string]any{
		"client_name":   "Example App",
		"redirect_uris": []string{"http://127.0.0.1/callback"},
	}
	r, admin, url, hits := resolverFixture(t, &doc)

	const n = 12
	var wg sync.WaitGroup
	firstSeen := make([]bool, n)
	errs := make([]error, n)
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			res, err := r.Resolve(context.Background(), url, "http://127.0.0.1:1/callback", "mcp")
			firstSeen[i], errs[i] = res.FirstSeen, err
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: %v", i, err)
		}
	}
	creates, _ := admin.counts()
	if creates != 1 {
		t.Errorf("creates = %d, want exactly 1", creates)
	}
	if *hits != 1 {
		t.Errorf("document fetches = %d, want 1", *hits)
	}
	seen := 0
	for _, f := range firstSeen {
		if f {
			seen++
		}
	}
	if seen != 1 {
		t.Errorf("FirstSeen reported %d times, want 1", seen)
	}
}

func TestResolveRefreshesAChangedDocument(t *testing.T) {
	doc := map[string]any{
		"client_name":   "Example App",
		"redirect_uris": []string{"http://127.0.0.1/callback"},
	}
	r, admin, url, _ := resolverFixture(t, &doc)

	if _, err := r.Resolve(context.Background(), url, "", "mcp"); err != nil {
		t.Fatalf("first resolve: %v", err)
	}
	// Change the document and expire the cache entry.
	doc["client_name"] = "Example App v2"
	doc["redirect_uris"] = []string{"http://127.0.0.1/callback", "http://[::1]/callback"}
	r.fetcher.Invalidate(url)

	res, err := r.Resolve(context.Background(), url, "", "mcp")
	if err != nil {
		t.Fatalf("second resolve: %v", err)
	}
	if res.MaterialChange {
		t.Error("a name/redirect change is not material")
	}
	_, updates := admin.counts()
	if updates != 1 {
		t.Errorf("updates = %d, want 1", updates)
	}
	if got := admin.stored(url); got.ClientName != "Example App v2" || len(got.RedirectURIs) != 2 {
		t.Errorf("stored client not refreshed: %+v", got)
	}
}

// §9.2: a changed authentication shape or key set invalidates what the user
// approved, so the resolver flags it for the consent step.
func TestResolveFlagsMaterialChanges(t *testing.T) {
	tests := []struct {
		name  string
		first map[string]any
		then  func(map[string]any)
	}{
		{"private_key_jwt -> none",
			map[string]any{
				"client_name":                "Example App",
				"redirect_uris":              []string{"http://127.0.0.1/callback"},
				"token_endpoint_auth_method": "private_key_jwt",
				"jwks_uri":                   "https://apps.example.com/jwks.json",
			},
			func(d map[string]any) {
				d["token_endpoint_auth_method"] = "none"
				delete(d, "jwks_uri")
			}},
		{"jwks_uri changed",
			map[string]any{
				"client_name":                "Example App",
				"redirect_uris":              []string{"http://127.0.0.1/callback"},
				"token_endpoint_auth_method": "private_key_jwt",
				"jwks_uri":                   "https://apps.example.com/jwks.json",
			},
			func(d map[string]any) { d["jwks_uri"] = "https://apps.example.com/jwks2.json" }},
		{"inline jwks changed",
			map[string]any{
				"client_name":                "Example App",
				"redirect_uris":              []string{"http://127.0.0.1/callback"},
				"token_endpoint_auth_method": "private_key_jwt",
				"jwks":                       map[string]any{"keys": []any{map[string]any{"kid": "a"}}},
			},
			func(d map[string]any) {
				d["jwks"] = map[string]any{"keys": []any{map[string]any{"kid": "b"}}}
			}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc := tc.first
			r, _, url, _ := resolverFixture(t, &doc)
			if _, err := r.Resolve(context.Background(), url, "", "mcp"); err != nil {
				t.Fatalf("first resolve: %v", err)
			}
			tc.then(doc)
			r.fetcher.Invalidate(url)
			res, err := r.Resolve(context.Background(), url, "", "mcp")
			if err != nil {
				t.Fatalf("second resolve: %v", err)
			}
			if !res.MaterialChange {
				t.Error("want MaterialChange")
			}
		})
	}
}

// A client ShellWatch did not create from CIMD keeps its registration, even if
// its id happens to be a URL.
func TestResolveNeverOverwritesForeignClient(t *testing.T) {
	doc := map[string]any{
		"client_name":   "Impostor",
		"redirect_uris": []string{"http://127.0.0.1/callback"},
	}
	r, admin, url, _ := resolverFixture(t, &doc)

	admin.mu.Lock()
	admin.clients[url] = OAuth2Client{
		ClientID:     url,
		ClientName:   "Operator's own client",
		RedirectURIs: []string{"https://apps.example.com/cb"},
		Scope:        "mcp offline_access",
	}
	admin.mu.Unlock()

	res, err := r.Resolve(context.Background(), url, "", "mcp")
	if err != nil {
		t.Fatalf("resolve must still succeed: %v", err)
	}
	if res.FirstSeen {
		t.Error("an existing client is not first-seen")
	}
	if _, updates := admin.counts(); updates != 0 {
		t.Errorf("updates = %d, want 0 — a foreign client must be untouched", updates)
	}
	if got := admin.stored(url); got.ClientName != "Operator's own client" {
		t.Errorf("foreign client was overwritten: %+v", got)
	}
}

// A provisioning failure must not leave a cached document, or the next attempt
// would serve a client Hydra does not have.
func TestResolveInvalidatesCacheWhenProvisioningFails(t *testing.T) {
	doc := map[string]any{
		"client_name":   "Example App",
		"redirect_uris": []string{"http://127.0.0.1/callback"},
	}
	r, admin, url, hits := resolverFixture(t, &doc)

	admin.mu.Lock()
	admin.createErr = &APIError{Status: http.StatusInternalServerError, Msg: "boom"}
	admin.mu.Unlock()

	if _, err := r.Resolve(context.Background(), url, "", "mcp"); err == nil {
		t.Fatal("want error when Hydra rejects the create")
	}
	if _, err := r.Resolve(context.Background(), url, "", "mcp"); err != nil {
		t.Fatalf("retry must succeed: %v", err)
	}
	if *hits != 2 {
		t.Errorf("document fetches = %d, want 2 (the failed attempt must not be cached)", *hits)
	}
}

func TestResolveRejectsInvalidClientIDURL(t *testing.T) {
	r := NewCIMDResolver(CIMDResolverParams{
		Admin: newFakeAdmin(), Fetcher: NewFetcher(FetcherParams{}), Policy: testPolicy(),
	})
	for _, id := range []string{"https://apps.example.com", "https://apps.example.com/c.json?x=1", "not-a-url"} {
		if _, err := r.Resolve(context.Background(), id, "", "mcp"); err == nil {
			t.Errorf("Resolve(%q) must fail", id)
		}
	}
}
