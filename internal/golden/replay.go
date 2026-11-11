// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Replay helper shared by the harness-vs-Node proof (golden_test.go) and the
// Go server's own parity tests: perform the fixture's GET, capture the
// {request, status, wwwAuthenticate, body} envelope, normalize, and return
// both sides for comparison.
package golden

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// ReplayGET replays a stateless fixture against base and returns
// (normalized live envelope, expected fixture document).
func ReplayGET(client *http.Client, base string, fixtureRaw []byte, baseURLs []string) (normalized, expected any, err error) {
	var fixture struct {
		Request struct {
			Path string `json:"path"`
		} `json:"request"`
	}
	if err := json.Unmarshal(fixtureRaw, &fixture); err != nil {
		return nil, nil, err
	}

	resp, err := client.Get(strings.TrimRight(base, "/") + fixture.Request.Path)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	var body any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, nil, fmt.Errorf("body decode: %w", err)
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
	if err := json.Unmarshal(fixtureRaw, &expected); err != nil {
		return nil, nil, err
	}
	return Normalize(envelope, Options{BaseURLs: baseURLs}), expected, nil
}
