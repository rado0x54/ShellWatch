// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// GET /api/hydra/authorize over the full handler stack: a non-URL client_id is
// handed to Hydra untouched, a URL client_id is resolved as a Client ID
// Metadata Document and provisioned into Hydra first, and every failure routes
// to the safe destination.
package httpserver

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/rado0x54/shellwatch/internal/audit"
	"github.com/rado0x54/shellwatch/internal/auth"
	"github.com/rado0x54/shellwatch/internal/buildinfo"
	"github.com/rado0x54/shellwatch/internal/config"
	"github.com/rado0x54/shellwatch/internal/hydra"
	"github.com/rado0x54/shellwatch/internal/hydratest"
	"github.com/rado0x54/shellwatch/internal/store"
)

// cimdDocHost serves a mutable metadata document over TLS on loopback and
// returns its URL. The caller's config must trust it (see frontDoorServer).
func cimdDocHost(t *testing.T, doc map[string]any, hits *int) (*httptest.Server, string) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if hits != nil {
			*hits++
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	}))
	t.Cleanup(srv.Close)
	return srv, srv.URL + "/client.json"
}

// frontDoorServer boots the handler stack with CIMD enabled, trusting docSrv's
// certificate so a document can be served from loopback in-process.
func frontDoorServer(t *testing.T, admin hydra.Admin, docSrv *httptest.Server, tweak func(*config.Config)) *httptest.Server {
	t.Helper()
	ts, _ := frontDoorServerWithLog(t, admin, docSrv, tweak)
	return ts
}

// frontDoorServerWithLog also returns the registration log the server writes
// to, so the DCR/CIMD -> audit wiring can be asserted end to end.
func frontDoorServerWithLog(t *testing.T, admin hydra.Admin, docSrv *httptest.Server, tweak func(*config.Config)) (*httptest.Server, *audit.OAuthClients) {
	t.Helper()
	cfg := &config.Config{}
	cfg.Server.ExternalURL = externalURL
	cfg.Hydra.PublicURL = "http://hydra.test:4444"
	cfg.Hydra.Dcr.AllowedScopes = []string{"mcp", "agent"}
	cfg.Hydra.Dcr.RedirectURIPatterns = []string{
		`^http://(127\.0\.0\.1|localhost)(:\d+)?(/.*)?$`,
		`^http://\[::1\](:\d+)?(/.*)?$`,
	}
	cfg.Hydra.Cimd.CacheMinSeconds = 300
	cfg.Hydra.Cimd.CacheMaxSeconds = 86400
	// draft §8.6's dev/test-only exception, which is the whole reason a
	// document can be served from httptest here.
	cfg.Hydra.Cimd.AllowLoopbackDocuments = true
	if tweak != nil {
		tweak(cfg)
	}

	// The document host is an httptest TLS server, so the fetcher has to trust
	// its throwaway CA. HTTPS itself still applies.
	var fetcher *hydra.Fetcher
	if docSrv != nil {
		pool := x509.NewCertPool()
		pool.AddCert(docSrv.Certificate())
		fetcher = hydra.NewFetcher(hydra.FetcherParams{
			AllowLoopback: cfg.Hydra.Cimd.AllowLoopbackDocuments,
			RootCAs:       pool,
			CacheMin:      time.Duration(cfg.Hydra.Cimd.CacheMinSeconds) * time.Second,
			CacheMax:      time.Duration(cfg.Hydra.Cimd.CacheMaxSeconds) * time.Second,
		})
	}

	db, err := store.Open("sqlite::memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := store.Migrate(db); err != nil {
		t.Fatal(err)
	}
	log := audit.NewOAuthClients(db, nil)

	handler := New(Params{
		Config:      cfg,
		Resolve:     auth.Resolver(func(context.Context, string) *auth.Principal { return nil }),
		StaticFS:    os.DirFS(t.TempDir()),
		BuildInfo:   buildinfo.Info{},
		HydraAdmin:  admin,
		CimdFetcher: fetcher,
		ClientLog:   log,
	})
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	return ts, log
}

// authorizeNoFollow issues the authorization request without following the
// hand-off, so the Location can be asserted.
func authorizeNoFollow(t *testing.T, ts *httptest.Server, query string) *http.Response {
	t.Helper()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	res, err := client.Get(ts.URL + "/api/hydra/authorize?" + query)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { res.Body.Close() })
	return res
}

// A non-URL client_id must reach Hydra with the query string byte-for-byte —
// the SPA and every DCR client depend on it.
func TestFrontDoorPassesThroughNonURLClientIDs(t *testing.T) {
	ts := frontDoorServer(t, hydratest.New(), nil, nil)

	// Deliberately awkward: duplicate keys, reserved characters, an empty
	// value and unusual ordering must all survive untouched.
	raw := "client_id=shellwatch-web&response_type=code&scope=ui+offline_access&" +
		"redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fauth%2Fcallback&state=a%2Bb%26c%3Dd&" +
		"code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&" +
		"prompt=&audience=x&audience=y"
	res := authorizeNoFollow(t, ts, raw)

	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", res.StatusCode)
	}
	loc := res.Header.Get("Location")
	want := "http://hydra.test:4444/oauth2/auth?" + raw
	if loc != want {
		t.Fatalf("Location =\n  %s\nwant\n  %s", loc, want)
	}
	if cc := res.Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
}

func TestFrontDoorPassesThroughMissingClientID(t *testing.T) {
	ts := frontDoorServer(t, hydratest.New(), nil, nil)
	res := authorizeNoFollow(t, ts, "response_type=code")
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303 (Hydra owns the missing-client_id error)", res.StatusCode)
	}
	if loc := res.Header.Get("Location"); loc != "http://hydra.test:4444/oauth2/auth?response_type=code" {
		t.Fatalf("Location = %s", loc)
	}
}

// With CIMD disabled a URL client_id is passed through, so it fails at Hydra
// as an unknown client rather than being resolved here.
func TestFrontDoorPassesThroughURLClientIDWhenCimdDisabled(t *testing.T) {
	off := false
	ts := frontDoorServer(t, hydratest.New(), nil, func(c *config.Config) {
		c.Hydra.Cimd.Enabled = &off
	})
	res := authorizeNoFollow(t, ts, "client_id=https%3A%2F%2Fapps.example.com%2Fclient.json")
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", res.StatusCode)
	}
	if loc := res.Header.Get("Location"); !strings.HasPrefix(loc, "http://hydra.test:4444/oauth2/auth?") {
		t.Fatalf("Location = %s, want a Hydra passthrough", loc)
	}

	// Discovery must agree: no CIMD flag, and Hydra's own endpoint.
	res2, err := http.Get(ts.URL + "/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatal(err)
	}
	defer res2.Body.Close()
	var meta map[string]any
	if err := json.NewDecoder(res2.Body).Decode(&meta); err != nil {
		t.Fatal(err)
	}
	if _, present := meta["client_id_metadata_document_supported"]; present {
		t.Error("the CIMD flag must be absent when CIMD is disabled")
	}
	if got := meta["authorization_endpoint"]; got != "http://hydra.test:4444/oauth2/auth" {
		t.Errorf("authorization_endpoint = %v, want Hydra's", got)
	}
}

func TestDiscoveryAdvertisesTheFrontDoorWhenCimdEnabled(t *testing.T) {
	ts := frontDoorServer(t, hydratest.New(), nil, nil)
	res, err := http.Get(ts.URL + "/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var meta map[string]any
	if err := json.NewDecoder(res.Body).Decode(&meta); err != nil {
		t.Fatal(err)
	}
	if meta["client_id_metadata_document_supported"] != true {
		t.Error("client_id_metadata_document_supported must be true")
	}
	if got := meta["authorization_endpoint"]; got != externalURL+"/api/hydra/authorize" {
		t.Errorf("authorization_endpoint = %v, want the front door", got)
	}
	// The token endpoint stays Hydra's: CIMD changes authorization only.
	if got := meta["token_endpoint"]; got != "http://hydra.test:4444/oauth2/token" {
		t.Errorf("token_endpoint = %v, want Hydra's", got)
	}
}

// The happy path: a URL client_id becomes a Hydra client with that exact id,
// and the browser is handed on to Hydra unchanged.
func TestFrontDoorResolvesCimdAndProvisionsHydraClient(t *testing.T) {
	admin := hydratest.New()
	doc := map[string]any{
		"client_name":   "Example MCP Client",
		"redirect_uris": []string{"http://127.0.0.1/callback"},
	}
	var hits int
	docSrv, clientID := cimdDocHost(t, doc, &hits)
	doc["client_id"] = clientID
	ts := frontDoorServer(t, admin, docSrv, nil)

	query := url.Values{
		"client_id":             {clientID},
		"response_type":         {"code"},
		"redirect_uri":          {"http://127.0.0.1:54321/callback"},
		"scope":                 {"mcp"},
		"state":                 {"xyz"},
		"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
		"code_challenge_method": {"S256"},
	}.Encode()
	res := authorizeNoFollow(t, ts, query)

	if res.StatusCode != http.StatusSeeOther {
		body := make([]byte, 400)
		n, _ := res.Body.Read(body)
		t.Fatalf("status = %d, want 303; body: %s", res.StatusCode, body[:n])
	}
	if loc := res.Header.Get("Location"); loc != "http://hydra.test:4444/oauth2/auth?"+query {
		t.Fatalf("Location = %s", loc)
	}

	client, ok := admin.Clients()[clientID]
	if !ok {
		t.Fatalf("no Hydra client provisioned for %q; have %v", clientID, keysOf(admin.Clients()))
	}
	if client.ClientID != clientID {
		t.Errorf("client_id = %q, want the URL", client.ClientID)
	}
	if client.ClientName != "Example MCP Client" {
		t.Errorf("client_name = %q", client.ClientName)
	}
	if client.Scope != "mcp offline_access" {
		t.Errorf("scope = %q", client.Scope)
	}
	if client.TokenEndpointAuthMethod != "none" {
		t.Errorf("token_endpoint_auth_method = %q", client.TokenEndpointAuthMethod)
	}
	sw, _ := client.Metadata["shellwatch"].(map[string]any)
	if sw == nil || sw["origin"] != "cimd" {
		t.Errorf("metadata = %v, want origin cimd", client.Metadata)
	}

	// A second authorization is served from the document cache.
	authorizeNoFollow(t, ts, query)
	if hits != 1 {
		t.Errorf("document fetches = %d, want 1 (cached)", hits)
	}
}

// Failures before the redirect_uri is validated must render, never redirect:
// the requested redirect_uri is attacker-chosen at that point.
func TestFrontDoorRendersErrorsItCannotSafelyRedirect(t *testing.T) {
	admin := hydratest.New()
	doc := map[string]any{
		"client_name":   "Example MCP Client",
		"redirect_uris": []string{"http://127.0.0.1/callback"},
	}
	docSrv, clientID := cimdDocHost(t, doc, nil)
	doc["client_id"] = clientID
	ts := frontDoorServer(t, admin, docSrv, nil)

	tests := []struct {
		name  string
		query url.Values
	}{
		{"client_id URL with no path", url.Values{
			"client_id": {"https://apps.example.com"}, "redirect_uri": {"http://127.0.0.1:1/callback"},
		}},
		{"client_id URL with a query", url.Values{
			"client_id": {"https://apps.example.com/c.json?x=1"}, "redirect_uri": {"http://127.0.0.1:1/callback"},
		}},
		{"document unreachable", url.Values{
			"client_id": {"https://127.0.0.1:1/client.json"}, "redirect_uri": {"http://127.0.0.1:1/callback"},
		}},
		{"redirect_uri not in the document", url.Values{
			"client_id": {clientID}, "redirect_uri": {"http://127.0.0.1:1/evil"},
		}},
		{"redirect_uri host not in the document", url.Values{
			"client_id": {clientID}, "redirect_uri": {"http://localhost:1/callback"},
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.query.Set("state", "xyz")
			res := authorizeNoFollow(t, ts, tc.query.Encode())
			if res.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (rendered, not redirected); Location=%q",
					res.StatusCode, res.Header.Get("Location"))
			}
			if loc := res.Header.Get("Location"); loc != "" {
				t.Fatalf("must not redirect, got Location=%q", loc)
			}
			if ct := res.Header.Get("Content-Type"); !strings.Contains(ct, "text/html") {
				t.Errorf("Content-Type = %q, want HTML", ct)
			}
		})
	}
}

// An SSRF target must be refused without anything reaching Hydra.
func TestFrontDoorRefusesSSRFDocuments(t *testing.T) {
	admin := hydratest.New()
	ts := frontDoorServer(t, admin, nil, func(c *config.Config) {
		// No loopback exception here: this is the production posture.
		c.Hydra.Cimd.AllowLoopbackDocuments = false
	})
	for _, id := range []string{
		"https://169.254.169.254/latest/meta-data/client.json",
		"https://10.0.0.1/client.json",
		"https://127.0.0.1/client.json",
	} {
		res := authorizeNoFollow(t, ts, url.Values{"client_id": {id}}.Encode())
		if res.StatusCode != http.StatusBadRequest {
			t.Errorf("client_id %q: status = %d, want 400", id, res.StatusCode)
		}
	}
	if n := len(admin.Clients()); n != 0 {
		t.Errorf("Hydra clients = %d, want 0 — nothing may be written for a refused document", n)
	}
}

// Once the redirect_uri IS validated, a later failure is reported to the
// client the OAuth way (RFC 6749 §4.1.2.1), with state preserved.
func TestFrontDoorRedirectsErrorsOnceRedirectURIIsValidated(t *testing.T) {
	admin := hydratest.New()
	doc := map[string]any{
		"client_name":   "Example MCP Client",
		"redirect_uris": []string{"http://127.0.0.1/callback"},
	}
	docSrv, clientID := cimdDocHost(t, doc, nil)
	doc["client_id"] = clientID
	ts := frontDoorServer(t, admin, docSrv, nil)

	res := authorizeNoFollow(t, ts, url.Values{
		"client_id":    {clientID},
		"redirect_uri": {"http://127.0.0.1:54321/callback"},
		"scope":        {"root admin"}, // nothing the policy allows
		"state":        {"xyz"},
	}.Encode())

	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303 to the validated redirect_uri", res.StatusCode)
	}
	loc, err := url.Parse(res.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if loc.Host != "127.0.0.1:54321" || loc.Path != "/callback" {
		t.Fatalf("Location = %s, want the client's own redirect_uri", loc)
	}
	if got := loc.Query().Get("error"); got != "invalid_scope" {
		t.Errorf("error = %q, want invalid_scope", got)
	}
	if got := loc.Query().Get("state"); got != "xyz" {
		t.Errorf("state = %q, want it preserved", got)
	}
	if loc.Query().Get("error_description") == "" {
		t.Error("error_description must be present")
	}
	if n := len(admin.Clients()); n != 0 {
		t.Errorf("Hydra clients = %d, want 0 — the scope was rejected before provisioning", n)
	}
}

func keysOf[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// --- registration log wiring (#242) ----------------------------------------

func logRows(t *testing.T, log *audit.OAuthClients, f audit.OAuthClientFilter) []audit.OAuthClientRegistration {
	t.Helper()
	page, err := log.List(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	return page.Rows
}

func TestCimdRegistrationAndRejectionAreLogged(t *testing.T) {
	admin := hydratest.New()
	doc := map[string]any{
		"client_name":   "Example MCP Client",
		"redirect_uris": []string{"http://127.0.0.1/callback"},
	}
	docSrv, clientID := cimdDocHost(t, doc, nil)
	doc["client_id"] = clientID
	ts, log := frontDoorServerWithLog(t, admin, docSrv, nil)

	query := url.Values{
		"client_id": {clientID}, "response_type": {"code"},
		"redirect_uri": {"http://127.0.0.1:54321/callback"}, "scope": {"mcp"}, "state": {"xyz"},
	}.Encode()
	if res := authorizeNoFollow(t, ts, query); res.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", res.StatusCode)
	}

	rows := logRows(t, log, audit.OAuthClientFilter{Origin: audit.OriginCIMD})
	if len(rows) != 1 {
		t.Fatalf("log rows = %d, want 1", len(rows))
	}
	r := rows[0]
	if r.ClientID != clientID {
		t.Errorf("clientId = %q, want the document URL", r.ClientID)
	}
	if r.Event != audit.EventRegistered {
		t.Errorf("event = %q, want registered", r.Event)
	}
	if r.MetadataHost == nil || *r.MetadataHost != "127.0.0.1" {
		t.Errorf("metadataHost = %v, want the client_id hostname", r.MetadataHost)
	}
	if r.AuthMethod == nil || *r.AuthMethod != "none" {
		t.Errorf("authMethod = %v", r.AuthMethod)
	}

	// Repeating the authorization is a cache hit: no new row, because nothing
	// about the client changed.
	authorizeNoFollow(t, ts, query)
	if rows := logRows(t, log, audit.OAuthClientFilter{Origin: audit.OriginCIMD}); len(rows) != 1 {
		t.Errorf("log rows after a cache hit = %d, want 1", len(rows))
	}

	// A refused document is logged with its reason and creates no client.
	authorizeNoFollow(t, ts, url.Values{
		"client_id": {"https://169.254.169.254/latest/meta-data/client.json"},
	}.Encode())
	rejected := logRows(t, log, audit.OAuthClientFilter{Event: audit.EventRejected})
	if len(rejected) != 1 {
		t.Fatalf("rejected rows = %d, want 1", len(rejected))
	}
	if rejected[0].Reason == nil || *rejected[0].Reason == "" {
		t.Error("a rejection must record its reason")
	}
	if rejected[0].MetadataHost == nil || *rejected[0].MetadataHost != "169.254.169.254" {
		t.Errorf("metadataHost = %v", rejected[0].MetadataHost)
	}
	if n := len(admin.Clients()); n != 1 {
		t.Errorf("Hydra clients = %d, want 1 (the rejected one must not exist)", n)
	}
}
