// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Package golden is the Go side of the cross-language parity oracle
// (#210/#225): a port of src/test/helpers/golden.ts's normalization. Both
// implementations must fold volatile values to the same placeholders so they
// can diff against the same committed fixtures
// (src/test/integration/__goldens__/*.json). Keep the rule set in lockstep
// with golden.ts — it is the contract, not an implementation detail.
package golden

import (
	"regexp"
	"strings"
)

var tsKeys = map[string]bool{
	"createdAt": true, "updatedAt": true, "lastActivityAt": true,
	"lastUsedAt": true, "builtAt": true, "authorizedAt": true,
	"closedAt": true, "resolvedAt": true, "expiresAt": true,
}

var redactKeys = map[string]bool{
	"challenge": true, "challengeId": true, "token": true, "stepUpToken": true,
}

var (
	sessionIDRe   = regexp.MustCompile(`^sess_[0-9a-f]{12}$`)
	uuidRe        = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	isoRe         = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?$`)
	fingerprintRe = regexp.MustCompile(`^SHA256:[A-Za-z0-9+/=]+$`)
)

// Options mirror NormalizeOptions in golden.ts.
type Options struct {
	// BaseURLs are live server origins folded to "<BASE_URL>" in strings.
	BaseURLs []string
	// Ports are per-run ephemeral ports folded to "<PORT>" in a `port` field.
	Ports []float64
}

func normalizeString(s string, baseURLs []string) any {
	out := s
	for _, b := range baseURLs {
		if b != "" {
			out = strings.ReplaceAll(out, b, "<BASE_URL>")
		}
	}
	if out != s {
		return out // was a URL-bearing string; don't also pattern-swap it
	}
	switch {
	case sessionIDRe.MatchString(out):
		return "sess_<ID>"
	case uuidRe.MatchString(out):
		return "<UUID>"
	case isoRe.MatchString(out):
		return "<TS>"
	case fingerprintRe.MatchString(out):
		return "<FINGERPRINT>"
	}
	return out
}

// Normalize deep-normalizes a decoded JSON value (map[string]any / []any /
// string / float64 / bool / nil) into its stable golden form — the exact
// walk of normalizeGolden in golden.ts.
func Normalize(value any, opts Options) any {
	return walk(value, "", opts)
}

func walk(v any, key string, opts Options) any {
	if key != "" && tsKeys[key] && v != nil {
		return "<TS>"
	}
	if key != "" && redactKeys[key] {
		if _, ok := v.(string); ok {
			return "<REDACTED>"
		}
	}
	if key == "nextCursor" {
		if s, ok := v.(string); ok && len(s) > 0 {
			return "<CURSOR>"
		}
	}
	// Scoped to `port` on purpose (see golden.ts): key-agnostic folding would
	// mask any numeric field that happened to equal an ephemeral port.
	if key == "port" {
		if n, ok := v.(float64); ok {
			for _, p := range opts.Ports {
				if p == n {
					return "<PORT>"
				}
			}
		}
	}
	switch t := v.(type) {
	case string:
		return normalizeString(t, opts.BaseURLs)
	case []any:
		out := make([]any, len(t))
		for i, item := range t {
			out[i] = walk(item, "", opts)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			out[k] = walk(val, k, opts)
		}
		return out
	default:
		return v
	}
}
