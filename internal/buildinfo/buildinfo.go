// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Package buildinfo ports src/server/buildInfo.ts: build identity served by
// GET /api/version and injected into /config.js. Reads the CI-generated
// buildInfo.generated.json from the working directory, with GIT_TAG from the
// environment (set at retag time), falling back to dev/local values.
package buildinfo

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// Info is the /api/version response body. Field order and JSON names are
// part of the frozen wire contract (BuildInfo in docs/api/openapi.yaml).
type Info struct {
	Sha     string  `json:"sha"`
	Ref     string  `json:"ref"`
	Tag     *string `json:"tag"`
	BuiltAt *string `json:"builtAt"`
	Display string  `json:"display"`
}

type persisted struct {
	Sha     string  `json:"sha"`
	Ref     string  `json:"ref"`
	BuiltAt *string `json:"builtAt"`
}

// DeriveDisplay mirrors deriveDisplay in buildInfo.ts: tag if set, else
// "<ref>@<shortSha>".
func DeriveDisplay(sha, ref string, tag *string) string {
	if tag != nil && *tag != "" {
		return *tag
	}
	short := sha
	if len(short) > 7 {
		short = short[:7]
	}
	return ref + "@" + short
}

// Load reads buildInfo.generated.json from cwd (like the Node backend);
// missing or malformed files fall back to sha "dev" / ref "local".
func Load(cwd string) Info {
	sha, ref := "dev", "local"
	var builtAt *string

	if raw, err := os.ReadFile(filepath.Join(cwd, "buildInfo.generated.json")); err == nil {
		var p persisted
		if json.Unmarshal(raw, &p) == nil {
			// `||`-style fallback, not nil-coalescing: empty strings count as
			// missing too (same guard as buildInfo.ts).
			if p.Sha != "" {
				sha = p.Sha
			}
			if p.Ref != "" {
				ref = p.Ref
			}
			builtAt = p.BuiltAt
		}
	}

	var tag *string
	if t := os.Getenv("GIT_TAG"); t != "" {
		tag = &t
	}
	return Info{Sha: sha, Ref: ref, Tag: tag, BuiltAt: builtAt, Display: DeriveDisplay(sha, ref, tag)}
}
