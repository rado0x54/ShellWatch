// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
package hydra

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/rado0x54/shellwatch/internal/config"
)

// defaultPolicy is the CIMD policy of a stock deployment: the document must
// resolve against it with no operator configuration at all.
func defaultPolicy(t *testing.T) ClientPolicy {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(`server:
  externalUrl: https://app.shellwatch.ai
security:
  rpId: app.shellwatch.ai
  trustedWebauthnOrigins: [https://app.shellwatch.ai]
hydra:
  publicUrl: https://app.shellwatch.ai
  adminUrl: http://hydra:4445
`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return NewClientPolicy(cfg.Hydra.Dcr.RedirectURIPatterns, cfg.Hydra.Dcr.AllowedScopes, true)
}

func embeddedAgentDoc(t *testing.T) ClientMetadata {
	t.Helper()
	var doc ClientMetadata
	dec := json.NewDecoder(strings.NewReader(string(agentClientMetadata)))
	dec.DisallowUnknownFields() // a typo'd field would otherwise be silently ignored
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("embedded agent document: %v", err)
	}
	return doc
}

// The published document must pass the server's own validation, so a broken
// edit fails CI instead of every agent login in production.
func TestAgentClientMetadataValidates(t *testing.T) {
	if _, err := ValidateClientIDURL(AgentClientID); err != nil {
		t.Fatalf("AgentClientID: %v", err)
	}
	if !strings.HasSuffix(AgentClientID, AgentClientMetadataPath) {
		t.Fatalf("AgentClientID %q is not served at %q", AgentClientID, AgentClientMetadataPath)
	}
	policy := defaultPolicy(t)
	doc, err := ValidateDocument(embeddedAgentDoc(t), AgentClientID, policy)
	if err != nil {
		t.Fatalf("ValidateDocument: %v", err)
	}
	scope, err := GrantedScope(doc.Scope, policy.AllowedScopes)
	if err != nil {
		t.Fatalf("GrantedScope: %v", err)
	}
	if strings.Join(scope, " ") != "agent offline_access" {
		t.Errorf("granted scope = %v, want [agent offline_access]", scope)
	}
}

// Every redirect URI is a loopback IP literal, never `localhost` (#281): only
// IP literals get the RFC 8252 §7.3 any-port exception, so a `localhost` entry
// would never match the agent's ephemeral port.
func TestAgentClientMetadataRedirectsAreLoopbackIPLiterals(t *testing.T) {
	doc := embeddedAgentDoc(t)
	for _, raw := range doc.RedirectURIs {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("%s: %v", raw, err)
		}
		if u.Scheme != "http" || !isLoopbackHost(u.Hostname()) || u.Port() != "" {
			t.Errorf("%s: want a port-less http loopback IP literal", raw)
		}
	}
	for _, tc := range []struct {
		requested string
		want      bool
	}{
		{"http://127.0.0.1:54321/callback", true},
		{"http://[::1]:54321/callback", true},
		{"http://localhost:54321/callback", false},
		{"http://127.0.0.1:54321/other", false},
	} {
		if got := MatchRedirectURI(doc.RedirectURIs, tc.requested); got != tc.want {
			t.Errorf("MatchRedirectURI(%s) = %v, want %v", tc.requested, got, tc.want)
		}
	}
}

// The document is a contract with the agent (separate module, so no import):
// its client_id, callback host + path and scope must match what login.go sends.
func TestAgentClientMetadataMatchesAgentClient(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "agent-client", "internal", "oauth", "login.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`"` + AgentClientID + `"`,
		`"127.0.0.1:0"`,
		`"http://127.0.0.1:%d/callback"`,
	} {
		if !strings.Contains(string(src), want) {
			t.Errorf("agent-client/internal/oauth/login.go no longer contains %s", want)
		}
	}
	if strings.Contains(string(src), "localhost") {
		t.Error("agent-client/internal/oauth/login.go mentions localhost; its redirect must be a loopback IP literal (#281)")
	}
}

func TestAgentClientMetadataServed(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		r := chi.NewRouter()
		MountDiscovery(r, DiscoveryParams{
			ExternalURL:       func() string { return "https://app.shellwatch.ai" },
			HydraPublicURL:    "https://app.shellwatch.ai",
			AgentProxyEnabled: enabled,
		})
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, AgentClientMetadataPath, nil))
		if !enabled {
			if rec.Code != http.StatusNotFound {
				t.Errorf("agent proxy disabled: status %d, want 404", rec.Code)
			}
			continue
		}
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d", rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); !isJSONContentType(ct) {
			t.Errorf("Content-Type %q is not JSON; the CIMD fetcher would refuse it", ct)
		}
		if cc := rec.Header().Get("Cache-Control"); cc != agentClientMetadataMaxAge {
			t.Errorf("Cache-Control = %q", cc)
		}
		if rec.Body.String() != string(agentClientMetadata) {
			t.Error("served body differs from the embedded document")
		}
	}
}
