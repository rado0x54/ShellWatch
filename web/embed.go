// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Package web embeds the SvelteKit client build so the release binary is
// fully self-contained (docs/go-backend-architecture.md §2/§5.11).
//
// dist/ holds a committed placeholder; a release build copies the SvelteKit
// output (client/build/*) into dist/ before `go build`. At runtime the
// -static-dir flag overrides the embedded copy for development.
package web

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

// Dist returns the embedded client build rooted at its content directory.
func Dist() (fs.FS, error) {
	return fs.Sub(dist, "dist")
}
