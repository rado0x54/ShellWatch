//go:build !windows

package config

import (
	"fmt"
	"os"
	"path/filepath"
)

func defaultSocketPath() string {
	if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
		return filepath.Join(dir, "shellwatch-agent.sock")
	}
	// Use UID suffix to avoid predictable paths in shared /tmp (symlink attack vector)
	return filepath.Join(os.TempDir(), fmt.Sprintf("shellwatch-agent-%d.sock", os.Getuid()))
}
