// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Registration events emitted by mediated DCR (#242). The CIMD side is
// covered by the front-door tests; the audit mapping that consumes these
// events lives in internal/httpserver.
package hydra

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

// dcrServer mounts the providers with a capturing event sink. WebAuthn is nil:
// only /api/hydra/register is exercised, and it never touches it.
func dcrServer(t *testing.T, admin Admin) (*httptest.Server, *[]ClientEvent) {
	t.Helper()
	var events []ClientEvent
	r := chi.NewRouter()
	MountProviders(r, ProviderParams{
		Admin:               admin,
		SPAClientID:         "shellwatch-web",
		AllowedScopes:       []string{"mcp", "agent"},
		RedirectURIPatterns: []string{`^http://127\.0\.0\.1(:\d+)?/`},
		AgentProxyEnabled:   true,
		OnEvent: func(_ *http.Request, ev ClientEvent) {
			events = append(events, ev)
		},
	})
	ts := httptest.NewServer(r)
	t.Cleanup(ts.Close)
	return ts, &events
}

func postRegister(t *testing.T, ts *httptest.Server, body string) *http.Response {
	t.Helper()
	res, err := ts.Client().Post(ts.URL+"/api/hydra/register", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { res.Body.Close() })
	return res
}

// A successful DCR registration emits one registered event, and the Hydra
// client is stamped with its origin so an admin reading Hydra's client list
// can tell DCR from CIMD.
func TestDCREmitsRegisteredEventAndStampsOrigin(t *testing.T) {
	admin := newFakeAdmin()
	ts, events := dcrServer(t, admin)

	res := postRegister(t, ts, `{"redirect_uris":["http://127.0.0.1:6274/cb"],"client_name":"MCP Inspector","scope":"mcp"}`)
	if res.StatusCode != 201 {
		t.Fatalf("status = %d, want 201", res.StatusCode)
	}
	if len(*events) != 1 {
		t.Fatalf("events = %d, want 1", len(*events))
	}
	ev := (*events)[0]
	if ev.Origin != ClientOriginDCR || ev.Event != ClientEventRegistered {
		t.Errorf("origin/event = %q/%q, want dcr/registered", ev.Origin, ev.Event)
	}
	if ev.ClientName != "MCP Inspector" {
		t.Errorf("clientName = %q", ev.ClientName)
	}
	if ev.MetadataHost != "" {
		t.Errorf("metadataHost = %q, want empty for DCR (no metadata document)", ev.MetadataHost)
	}
	if ev.AuthMethod != "none" {
		t.Errorf("authMethod = %q", ev.AuthMethod)
	}
	if ev.Scope != "mcp offline_access" {
		t.Errorf("scope = %q", ev.Scope)
	}
	if ev.ClientID == "" {
		t.Error("the event must carry the minted client_id — it is the link to Hydra")
	}

	stored := admin.stored(ev.ClientID)
	sw, _ := stored.Metadata["shellwatch"].(map[string]any)
	if sw == nil || sw["origin"] != ClientOriginDCR {
		t.Errorf("Hydra metadata = %v, want origin dcr", stored.Metadata)
	}
}

// A policy refusal is answered inline and emits nothing: it has no client_id,
// and the 400 already tells the caller everything. Only a failed Hydra write
// produces a rejected event, because that one is the server's problem.
func TestDCRPolicyRefusalEmitsNothing(t *testing.T) {
	admin := newFakeAdmin()
	ts, events := dcrServer(t, admin)

	for _, body := range []string{
		`{"redirect_uris":["https://evil.example.net/cb"]}`,        // policy
		`{"redirect_uris":[]}`,                                     // missing
		`{"redirect_uris":["http://127.0.0.1/cb"],"scope":"root"}`, // scope
	} {
		res := postRegister(t, ts, body)
		if res.StatusCode != 400 {
			t.Errorf("body %s: status = %d, want 400", body, res.StatusCode)
		}
	}
	if len(*events) != 0 {
		t.Errorf("events = %d, want 0 for policy refusals: %+v", len(*events), *events)
	}
	if creates, _ := admin.counts(); creates != 0 {
		t.Errorf("Hydra creates = %d, want 0", creates)
	}
}

// A Hydra write failure is the server's fault, so it is recorded.
func TestDCRHydraFailureEmitsRejectedEvent(t *testing.T) {
	admin := newFakeAdmin()
	admin.createErr = &APIError{Status: http.StatusInternalServerError, Msg: "boom"}
	ts, events := dcrServer(t, admin)

	res := postRegister(t, ts, `{"redirect_uris":["http://127.0.0.1/cb"],"client_name":"Doomed"}`)
	if res.StatusCode != 502 {
		t.Fatalf("status = %d, want 502", res.StatusCode)
	}
	if len(*events) != 1 {
		t.Fatalf("events = %d, want 1", len(*events))
	}
	ev := (*events)[0]
	if ev.Event != ClientEventRejected || ev.Origin != ClientOriginDCR {
		t.Errorf("origin/event = %q/%q, want dcr/rejected", ev.Origin, ev.Event)
	}
	if ev.ClientID != "" {
		t.Errorf("clientId = %q, want empty — no client was created", ev.ClientID)
	}
	if ev.Reason == "" {
		t.Error("a rejection must carry a reason")
	}
}

// A nil sink must be safe: the server runs with the log disabled.
func TestDCRWithNoSinkDoesNotPanic(t *testing.T) {
	r := chi.NewRouter()
	MountProviders(r, ProviderParams{
		Admin:               newFakeAdmin(),
		AllowedScopes:       []string{"mcp"},
		RedirectURIPatterns: []string{`^http://127\.0\.0\.1(:\d+)?/`},
	})
	ts := httptest.NewServer(r)
	t.Cleanup(ts.Close)
	if res := postRegister(t, ts, `{"redirect_uris":["http://127.0.0.1/cb"]}`); res.StatusCode != 201 {
		t.Fatalf("status = %d, want 201", res.StatusCode)
	}
}
