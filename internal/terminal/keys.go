// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Named key -> escape sequence mapping (port of terminal/keys.ts).
package terminal

import (
	"fmt"
	"strings"
)

var keyMap = map[string]string{
	"ctrl+c": "\x03", "ctrl+d": "\x04", "ctrl+z": "\x1a", "ctrl+l": "\x0c",
	"ctrl+a": "\x01", "ctrl+e": "\x05", "ctrl+u": "\x15", "ctrl+k": "\x0b",
	"ctrl+w": "\x17", "tab": "\t", "enter": "\r", "escape": "\x1b",
	"up": "\x1b[A", "down": "\x1b[B", "right": "\x1b[C", "left": "\x1b[D",
	"home": "\x1b[H", "end": "\x1b[F", "backspace": "\x7f", "delete": "\x1b[3~",
}

// ResolveKey maps a named key or "text:<raw>" to bytes (resolveKey()).
func ResolveKey(key string) (string, error) {
	if mapped, ok := keyMap[strings.ToLower(key)]; ok {
		return mapped, nil
	}
	if strings.HasPrefix(key, "text:") {
		raw := key[len("text:"):]
		raw = strings.NewReplacer(`\n`, "\n", `\r`, "\r", `\t`, "\t").Replace(raw)
		return raw, nil
	}
	return "", fmt.Errorf("unknown key: %s", key)
}

// ResolveKeys concatenates resolved keys.
func ResolveKeys(keys []string) (string, error) {
	var b strings.Builder
	for _, k := range keys {
		r, err := ResolveKey(k)
		if err != nil {
			return "", err
		}
		b.WriteString(r)
	}
	return b.String(), nil
}
