// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
package mcp

import (
	"strings"
	"testing"
)

func TestEndpointPatchFromWire(t *testing.T) {
	p, msg := endpointPatchFromWire(map[string]any{
		"label": "L", "host": "h", "username": "u", "port": float64(2222),
		"userVerification": "preferred", "agentForward": false, "description": "d",
	})
	if msg != "" {
		t.Fatalf("valid patch rejected: %s", msg)
	}
	if *p.Label != "L" || *p.Host != "h" || *p.Username != "u" || *p.Port != 2222 {
		t.Fatalf("basic fields wrong: %+v", p)
	}
	if *p.UserVerification != "preferred" || *p.AgentForward != false {
		t.Fatalf("uv/forward wrong: %+v", p)
	}
	if !p.DescriptionSet || p.Description == nil || *p.Description != "d" {
		t.Fatalf("description wrong: %+v", p)
	}

	// Absent fields stay nil; a JSON null description means "clear".
	p, msg = endpointPatchFromWire(map[string]any{"description": nil})
	if msg != "" || !p.DescriptionSet || p.Description != nil {
		t.Fatalf("null description: msg=%q patch=%+v", msg, p)
	}
	if p.Label != nil || p.UserVerification != nil || p.AgentForward != nil {
		t.Fatalf("absent fields must be nil: %+v", p)
	}

	for _, tc := range []struct {
		name string
		data map[string]any
		want string
	}{
		{"uv unknown value", map[string]any{"userVerification": "none"},
			"data.userVerification must be one of: required, preferred, discouraged"},
		{"uv wrong type", map[string]any{"userVerification": true},
			"data.userVerification must be one of: required, preferred, discouraged"},
		{"agentForward string", map[string]any{"agentForward": "yes"},
			"data.agentForward must be a boolean"},
		{"port string", map[string]any{"port": "22"},
			"data.port must be a number"},
		{"label number", map[string]any{"label": float64(5)},
			"data.label must be a string"},
		{"description too long", map[string]any{"description": strings.Repeat("x", 1001)},
			"data.description must be a string up to 1000 characters (pass null to clear)"},
		{"description wrong type", map[string]any{"description": float64(1)},
			"data.description must be a string up to 1000 characters (pass null to clear)"},
	} {
		if _, msg := endpointPatchFromWire(tc.data); msg != tc.want {
			t.Errorf("%s: got %q want %q", tc.name, msg, tc.want)
		}
	}
}
