// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Two proofs for the parity harness (#210 Phase 1):
//
//  1. Idempotency over every committed fixture: the Go normalization maps
//     each already-normalized golden to itself. If the Go rule set drifted
//     from golden.ts (a placeholder re-matched, a key missed), this breaks.
//
//  2. Live replay against the NODE server (the spec's "prove the harness
//     against Node first"): with SHELLWATCH_GOLDEN_BASE_URL set to a running
//     Node backend, the stateless fixtures (health, discovery, 401s) are
//     replayed over HTTP, normalized by THIS implementation, and diffed
//     against the same files the Node tests assert. Skipped when unset.
package golden

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

const goldensDir = "../../src/test/integration/__goldens__"

func TestNormalizationIdempotentOverAllFixtures(t *testing.T) {
	entries, err := os.ReadDir(goldensDir)
	if err != nil {
		t.Fatalf("goldens dir: %v", err)
	}
	count := 0
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		count++
		raw, err := os.ReadFile(filepath.Join(goldensDir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		var doc any
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("%s: %v", e.Name(), err)
		}
		normalized := Normalize(doc, Options{})
		if !reflect.DeepEqual(normalized, doc) {
			a, _ := json.MarshalIndent(doc, "", "  ")
			b, _ := json.MarshalIndent(normalized, "", "  ")
			t.Errorf("%s: normalization not idempotent\n--- fixture ---\n%s\n--- re-normalized ---\n%s", e.Name(), a, b)
		}
	}
	if count < 20 {
		t.Fatalf("expected the full fixture set, found only %d files", count)
	}
	t.Logf("idempotent over %d fixtures", count)
}

func TestNormalizeRules(t *testing.T) {
	in := map[string]any{
		"createdAt":  "2026-07-02T10:00:00.000Z",
		"challenge":  "abc123",
		"nextCursor": "opaque-cursor",
		"id":         "3f2504e0-4f89-11d3-9a0c-0305e82c3301",
		"sessionId":  "sess_0123456789ab",
		"when":       "2026-07-02T10:00:00Z",
		"fp":         "SHA256:AAAus9WYNPsAA+x9K2Kl91gJBmTZQ8HzXbLDL0FtnLI=",
		"url":        "http://127.0.0.1:39001/api/x",
		"port":       float64(39002),
		"keep":       "plain",
		"n":          float64(42),
	}
	out := Normalize(in, Options{
		BaseURLs: []string{"http://127.0.0.1:39001"},
		Ports:    []float64{39002},
	}).(map[string]any)
	want := map[string]any{
		"createdAt": "<TS>", "challenge": "<REDACTED>", "nextCursor": "<CURSOR>",
		"id": "<UUID>", "sessionId": "sess_<ID>", "when": "<TS>",
		"fp": "<FINGERPRINT>", "url": "<BASE_URL>/api/x", "port": "<PORT>",
		"keep": "plain", "n": float64(42),
	}
	if !reflect.DeepEqual(out, want) {
		t.Fatalf("got %#v", out)
	}
}

// Stateless fixtures replayable against a live server with no seeded state
// and no auth. The 401s ARE the unauthenticated responses.
var replayable = []string{
	"health",
	"err-401-api",
	"err-401-mcp",
	"discovery-protected-resource",
	"discovery-protected-resource-mcp",
	"discovery-authorization-server",
}

func TestReplayStatelessGoldensAgainstLiveServer(t *testing.T) {
	base := os.Getenv("SHELLWATCH_GOLDEN_BASE_URL")
	if base == "" {
		t.Skip("SHELLWATCH_GOLDEN_BASE_URL not set — start the Node backend and point this at it (e.g. http://127.0.0.1:3000)")
	}
	base = strings.TrimRight(base, "/")
	// Discovery bodies embed server.externalUrl, not the request origin; fold
	// both (they coincide in a default dev setup).
	baseURLs := []string{base}
	if ext := os.Getenv("SHELLWATCH_EXTERNAL_URL"); ext != "" {
		baseURLs = append(baseURLs, strings.TrimRight(ext, "/"))
	}

	client := &http.Client{Timeout: 10 * time.Second}
	for _, name := range replayable {
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(goldensDir, name+".json"))
			if err != nil {
				t.Fatal(err)
			}
			var fixture struct {
				Request struct {
					Path string `json:"path"`
				} `json:"request"`
				Status          float64 `json:"status"`
				WwwAuthenticate any     `json:"wwwAuthenticate"`
				Body            any     `json:"body"`
			}
			if err := json.Unmarshal(raw, &fixture); err != nil {
				t.Fatal(err)
			}

			resp, err := client.Get(base + fixture.Request.Path)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			var body any
			if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
				t.Fatalf("body decode: %v", err)
			}

			var www any
			if h := resp.Header.Get("Www-Authenticate"); h != "" {
				www = h
			}
			envelope := map[string]any{
				"request":         map[string]any{"path": fixture.Request.Path},
				"status":          float64(resp.StatusCode),
				"wwwAuthenticate": www,
				"body":            body,
			}
			normalized := Normalize(envelope, Options{BaseURLs: baseURLs})

			var expected any
			if err := json.Unmarshal(raw, &expected); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(normalized, expected) {
				a, _ := json.MarshalIndent(expected, "", "  ")
				b, _ := json.MarshalIndent(normalized, "", "  ")
				t.Errorf("parity mismatch\n--- golden ---\n%s\n--- live (normalized) ---\n%s", a, b)
			}
		})
	}
}
