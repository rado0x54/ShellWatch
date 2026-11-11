// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
package webauthn

import (
	"crypto/rand"
	"encoding/base64"

	"github.com/rado0x54/shellwatch/internal/ids"
)

// newUUID generates a random v4 UUID (shared generator; the goldens
// normalize these to <UUID>).
func newUUID() string { return ids.NewUUID() }

// randomB64URL returns n random bytes, base64url-no-pad (challenge / step-up
// token encoding, matching @simplewebauthn + randomBytes().toString("base64url")).
func randomB64URL(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
