// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
package auth

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLogRejected(t *testing.T) {
	cases := []struct {
		name    string
		p       RejectedRequest
		want    []string
		notWant []string
	}{
		{
			name:    "no principal",
			p:       RejectedRequest{Level: slog.LevelInfo, Scope: McpScope, Reason: "inactive or unknown token"},
			want:    []string{"level=INFO", `msg="auth: request rejected"`, "path=/mcp", "scope=mcp", `reason="inactive or unknown token"`},
			notWant: []string{"account="},
		},
		{
			name: "resolved principal lacking scope",
			p: RejectedRequest{Level: slog.LevelWarn, Scope: McpScope, Reason: "token lacks scope",
				Principal: &Principal{AccountID: "acc-1", ClientID: "client-1"}},
			want: []string{"level=WARN", "account=acc-1", "client=client-1"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var buf bytes.Buffer
			prev := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
			t.Cleanup(func() { slog.SetDefault(prev) })

			c.p.Request = httptest.NewRequest(http.MethodPost, "/mcp", nil)
			logRejected(c.p)

			logged := buf.String()
			for _, w := range c.want {
				if !strings.Contains(logged, w) {
					t.Errorf("log missing %q:\n%s", w, logged)
				}
			}
			for _, w := range c.notWant {
				if strings.Contains(logged, w) {
					t.Errorf("log unexpectedly contains %q:\n%s", w, logged)
				}
			}
		})
	}
}
