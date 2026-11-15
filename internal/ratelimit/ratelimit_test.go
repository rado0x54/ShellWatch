// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
package ratelimit

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRuleMatchesHeadAsGet(t *testing.T) {
	get := Rule{Method: http.MethodGet, Path: "/api/hydra/authorize"}
	post := Rule{Method: http.MethodPost, Path: "/api/hydra/register"}
	for _, tc := range []struct {
		rule   Rule
		method string
		path   string
		want   bool
	}{
		{get, http.MethodGet, "/api/hydra/authorize", true},
		{get, http.MethodHead, "/api/hydra/authorize", true},
		{get, http.MethodPost, "/api/hydra/authorize", false},
		{post, http.MethodPost, "/api/hydra/register", true},
		// HEAD is never mapped onto a POST route, so it must not match one.
		{post, http.MethodHead, "/api/hydra/register", false},
	} {
		req := httptest.NewRequest(tc.method, tc.path, nil)
		if got := tc.rule.matches(req); got != tc.want {
			t.Errorf("%s rule vs %s %s: %v, want %v", tc.rule.Method, tc.method, tc.path, got, tc.want)
		}
	}
}
