// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Package web embeds the SvelteKit client build so the binary is fully
// self-contained (docs/go-backend-architecture.md §2/§5.11).
//
// `pnpm build:client` writes the SvelteKit output straight into dist/
// (client/svelte.config.js); only dist/.gitkeep is tracked. A binary built
// before the client exists serves no UI (404 for /) but every API still works.
// At runtime the -static-dir flag overrides the embedded copy for development.
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
