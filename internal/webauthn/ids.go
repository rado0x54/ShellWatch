// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
package webauthn

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
)

// newUUID generates a random v4 UUID (matches Node's randomUUID() output
// shape; the goldens normalize these to <UUID>).
func newUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// randomB64URL returns n random bytes, base64url-no-pad (challenge / step-up
// token encoding, matching @simplewebauthn + randomBytes().toString("base64url")).
func randomB64URL(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
