// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Consent for a URL client_id (#242): the hostname leads, no remote logo is
// ever rendered, and the silent `skip` path is refused so a human re-approves
// every authorization — because a metadata document can change under them.
package hydra

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/rado0x54/shellwatch/internal/clock"
)

const cimdConsentClientID = "https://apps.example.com/.well-known/client.json"

// consentAdmin is the admin surface the consent page uses, with a scripted
// consent request and a record of what was accepted.
type consentAdmin struct {
	*fakeAdmin
	consent  ConsentRequest
	accepted []AcceptConsent
}

func (c *consentAdmin) GetConsentRequest(context.Context, string) (ConsentRequest, error) {
	return c.consent, nil
}

func (c *consentAdmin) AcceptConsentRequest(_ context.Context, _ string, body AcceptConsent) (Redirect, error) {
	c.accepted = append(c.accepted, body)
	return Redirect{RedirectTo: "https://hydra.test/continue"}, nil
}

// consentServer mounts the providers at a fixed time so the "recently changed"
// window is deterministic.
func consentServer(t *testing.T, cr ConsentRequest, clients ...OAuth2Client) (*httptest.Server, *consentAdmin) {
	t.Helper()
	admin := &consentAdmin{fakeAdmin: newFakeAdmin(), consent: cr}
	for _, c := range clients {
		admin.clients[c.ClientID] = c
	}
	r := chi.NewRouter()
	MountProviders(r, ProviderParams{
		Admin:               admin,
		SPAClientID:         "shellwatch-web",
		AllowedScopes:       []string{"mcp"},
		RedirectURIPatterns: []string{`^http://127\.0\.0\.1(:\d+)?/`},
		Now:                 func() time.Time { return consentNow },
	})
	ts := httptest.NewServer(r)
	t.Cleanup(ts.Close)
	return ts, admin
}

var consentNow = time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)

func getConsent(t *testing.T, ts *httptest.Server) (int, string, string) {
	t.Helper()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	res, err := client.Get(ts.URL + "/api/hydra/consent?consent_challenge=cc")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(body), res.Header.Get("Location")
}

// cimdMetadata is what the resolver stamps on a client it provisioned.
func cimdMetadata(fetchedAt time.Time) map[string]any {
	return map[string]any{"shellwatch": map[string]any{
		"origin":     OriginCIMD,
		"fetched_at": fetchedAt.UTC().Format(clock.ISOMillis),
	}}
}

func TestConsentShowsHostnameFirstForURLClientID(t *testing.T) {
	ts, _ := consentServer(t, ConsentRequest{
		Challenge: "cc", Subject: "acc-1",
		Client: OAuth2Client{
			ClientID: cimdConsentClientID, ClientName: "Example App",
			ClientURI: "https://example.com/",
			Metadata:  cimdMetadata(consentNow.Add(-24 * time.Hour)),
		},
		RequestedScope: []string{"mcp", "offline_access"},
	})

	status, body, _ := getConsent(t, ts)
	if status != 200 {
		t.Fatalf("status = %d, want 200", status)
	}
	// The hostname is present and comes BEFORE the self-assigned name.
	hostIdx := strings.Index(body, "apps.example.com")
	nameIdx := strings.Index(body, "Example App")
	if hostIdx < 0 {
		t.Fatal("the client_id hostname must be shown")
	}
	if nameIdx < 0 || hostIdx > nameIdx {
		t.Errorf("hostname must precede client_name (host=%d name=%d)", hostIdx, nameIdx)
	}
	if !strings.Contains(body, `class="cimd-host"`) {
		t.Error("the hostname must be rendered in the monospace identity block")
	}
	// The name is presented as a claim, not as established identity.
	if !strings.Contains(body, "calls itself") {
		t.Error("client_name must be framed as a self-assigned claim")
	}
	// client_uri's host differs from the client_id host, which is worth seeing.
	if !strings.Contains(body, "example.com") {
		t.Error("client_uri host must be shown when it differs")
	}
	// §9.3: no remote image, ever. The page's only <img> is ShellWatch's own
	// local logo; see TestConsentCannotRenderARemoteLogo for why a client's
	// logo_uri cannot reach here at all.
	for _, tag := range strings.Split(body, "<img")[1:] {
		attrs := tag[:strings.Index(tag, ">")]
		if !strings.Contains(attrs, `src="/logo.svg"`) {
			t.Errorf("unexpected image on the consent page: <img%s>", attrs)
		}
	}
	// Not recent: the hint must be absent.
	if strings.Contains(body, "less than an hour ago") {
		t.Error("the recently-changed hint must not show for an old client")
	}
	for _, scope := range []string{"mcp", "offline_access"} {
		if !strings.Contains(body, scope) {
			t.Errorf("scope %q must be listed", scope)
		}
	}
}

func TestConsentFlagsRecentlyChangedClient(t *testing.T) {
	tests := []struct {
		name      string
		fetchedAt time.Time
		want      bool
	}{
		{"just now", consentNow.Add(-time.Minute), true},
		{"59 minutes ago", consentNow.Add(-59 * time.Minute), true},
		{"just over an hour", consentNow.Add(-61 * time.Minute), false},
		{"yesterday", consentNow.Add(-24 * time.Hour), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ts, _ := consentServer(t, ConsentRequest{
				Challenge: "cc", Subject: "acc-1",
				Client: OAuth2Client{
					ClientID: cimdConsentClientID, ClientName: "Example App",
					Metadata: cimdMetadata(tc.fetchedAt),
				},
				RequestedScope: []string{"mcp"},
			})
			_, body, _ := getConsent(t, ts)
			got := strings.Contains(body, "less than an hour ago")
			if got != tc.want {
				t.Fatalf("recent hint = %v, want %v", got, tc.want)
			}
		})
	}
}

// Hydra's consent request may not echo the client's metadata; the page must
// fall back to reading the client so the hint does not silently vanish.
func TestConsentReadsMetadataFromHydraWhenAbsent(t *testing.T) {
	ts, _ := consentServer(t,
		ConsentRequest{
			Challenge: "cc", Subject: "acc-1",
			// No Metadata, no ClientURI on the consent request itself.
			Client:         OAuth2Client{ClientID: cimdConsentClientID, ClientName: "Example App"},
			RequestedScope: []string{"mcp"},
		},
		OAuth2Client{
			ClientID: cimdConsentClientID, ClientName: "Example App",
			ClientURI: "https://home.example.org/",
			Metadata:  cimdMetadata(consentNow.Add(-5 * time.Minute)),
		})

	_, body, _ := getConsent(t, ts)
	if !strings.Contains(body, "less than an hour ago") {
		t.Error("the recent hint must survive a consent request that omits metadata")
	}
	if !strings.Contains(body, "home.example.org") {
		t.Error("client_uri host must be picked up from the stored client")
	}
}

// The silent skip is what CIMD refuses: a remembered consent must still show
// the page, because the document behind the client_id can have changed.
func TestConsentNeverSkipsForURLClientID(t *testing.T) {
	ts, admin := consentServer(t, ConsentRequest{
		Challenge: "cc", Subject: "acc-1", Skip: true,
		Client: OAuth2Client{
			ClientID: cimdConsentClientID, ClientName: "Example App",
			Metadata: cimdMetadata(consentNow.Add(-24 * time.Hour)),
		},
		RequestedScope: []string{"mcp"},
	})

	status, body, loc := getConsent(t, ts)
	if status != 200 {
		t.Fatalf("status = %d (Location %q), want 200 — a CIMD client must not auto-accept",
			status, loc)
	}
	if len(admin.accepted) != 0 {
		t.Errorf("consent was accepted without asking: %+v", admin.accepted)
	}
	if !strings.Contains(body, "apps.example.com") {
		t.Error("the rendered page must identify the client")
	}
}

// Refusing skip must NOT mean refusing remember: the remembered consent
// session is what lists the client under Authorized clients and makes it
// revocable.
func TestConsentStillRemembersURLClientGrants(t *testing.T) {
	ts, admin := consentServer(t, ConsentRequest{
		Challenge: "cc", Subject: "acc-1",
		Client:         OAuth2Client{ClientID: cimdConsentClientID, ClientName: "Example App"},
		RequestedScope: []string{"mcp"},
		// A fresh passkey login in this same flow allows the approve shortcut.
		Context: map[string]any{"freshLogin": true},
	})

	res, err := ts.Client().Post(ts.URL+"/api/hydra/consent/approve", "application/json",
		strings.NewReader(`{"consent_challenge":"cc"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("approve status = %d", res.StatusCode)
	}
	if len(admin.accepted) != 1 {
		t.Fatalf("accepted %d times, want 1", len(admin.accepted))
	}
	if !admin.accepted[0].Remember {
		t.Error("the grant must still be remembered, or the client never appears " +
			"under Authorized clients and cannot be revoked")
	}
}

// A non-URL client_id keeps every existing behaviour, skip included.
func TestConsentSkipStillWorksForNonURLClients(t *testing.T) {
	ts, admin := consentServer(t, ConsentRequest{
		Challenge: "cc", Subject: "acc-1", Skip: true,
		Client:         OAuth2Client{ClientID: "07f85190-7ac1-42d8-8a79-49ce076a8721", ClientName: "MCP Inspector"},
		RequestedScope: []string{"mcp"},
	})

	status, _, loc := getConsent(t, ts)
	if status != http.StatusFound {
		t.Fatalf("status = %d, want 302 (remembered DCR consent still skips)", status)
	}
	if loc != "https://hydra.test/continue" {
		t.Errorf("Location = %q", loc)
	}
	if len(admin.accepted) != 1 {
		t.Fatalf("accepted %d times, want 1", len(admin.accepted))
	}
}

// A DCR client without a name still falls back to its opaque id; a CIMD client
// does not, because the page already shows its hostname.
func TestConsentNameFallback(t *testing.T) {
	ts, _ := consentServer(t, ConsentRequest{
		Challenge: "cc", Subject: "acc-1",
		Client:         OAuth2Client{ClientID: "07f85190-7ac1-42d8-8a79-49ce076a8721"},
		RequestedScope: []string{"mcp"},
	})
	_, body, _ := getConsent(t, ts)
	if !strings.Contains(body, "07f85190") {
		t.Error("an unnamed DCR client must fall back to its client_id")
	}

	ts2, _ := consentServer(t, ConsentRequest{
		Challenge: "cc", Subject: "acc-1",
		Client:         OAuth2Client{ClientID: cimdConsentClientID},
		RequestedScope: []string{"mcp"},
	})
	_, body2, _ := getConsent(t, ts2)
	if strings.Contains(body2, "calls itself") {
		t.Error("an unnamed CIMD client must not render an empty claim line")
	}
	if !strings.Contains(body2, "apps.example.com") {
		t.Error("the hostname must still identify the client")
	}
}

// A client's logo_uri can never reach the consent page, because ShellWatch
// does not carry it into Hydra: OAuth2Client has no such field, so there is
// nothing for the renderer to read even by accident (draft §9.3 asks for
// prefetching, caching and moderation, none of which ShellWatch does).
func TestConsentCannotRenderARemoteLogo(t *testing.T) {
	raw, err := os.ReadFile("types.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "logo_uri") {
		t.Error("OAuth2Client must not carry logo_uri: the consent page would then " +
			"be one field reference away from rendering a client-controlled image")
	}
	// And the validated document's logo is dropped on the way to Hydra.
	doc := validDoc()
	doc.LogoURI = "https://evil.example.net/logo.png"
	doc, err = ValidateDocument(doc, testClientID, testPolicy())
	if err != nil {
		t.Fatal(err)
	}
	r := NewCIMDResolver(CIMDResolverParams{Admin: newFakeAdmin(), Policy: testPolicy()})
	desired := r.desiredClient(testClientID, doc, []string{"mcp", "offline_access"})
	blob, _ := json.Marshal(desired)
	if strings.Contains(string(blob), "logo") {
		t.Errorf("logo_uri leaked into the Hydra client: %s", blob)
	}
}

// The identity block escapes what the client supplies: client_name comes
// straight from a document an attacker controls.
func TestConsentEscapesClientSuppliedName(t *testing.T) {
	ts, _ := consentServer(t, ConsentRequest{
		Challenge: "cc", Subject: "acc-1",
		Client: OAuth2Client{
			ClientID:   cimdConsentClientID,
			ClientName: `<script>alert(1)</script>`,
		},
		RequestedScope: []string{"mcp"},
	})
	_, body, _ := getConsent(t, ts)
	if strings.Contains(body, "<script>alert(1)</script>") {
		t.Fatal("client_name must be HTML-escaped")
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Error("the escaped name should still be visible to the user")
	}
}
