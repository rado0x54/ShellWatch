// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Package ids is the shared random-identifier leaf: one v4 UUID generator
// instead of a copy per composition point (main, webauthn, mcp).
package ids

import (
	"crypto/rand"
	"encoding/hex"
)

// NewUUID generates a random v4 UUID (matches Node's randomUUID() output
// shape; the goldens normalize these to <UUID>).
func NewUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}
