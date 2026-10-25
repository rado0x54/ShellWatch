// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// AAGUID -> authenticator name (port of src/webauthn/aaguid-lookup.ts). The
// embedded aaguid-names.json (FIDO MDS-derived, mirrored from the Node package)
// maps a credential's AAGUID to a product name ("YubiKey 5 Series", "iCloud
// Keychain", …). Unknown or the all-zero (anonymous) AAGUID falls back to the
// generic "Passkey" label.
package webauthn

import (
	_ "embed"
	"encoding/hex"
	"encoding/json"
)

//go:embed aaguid-names.json
var aaguidNamesJSON []byte

var aaguidNames = func() map[string]string {
	m := map[string]string{}
	_ = json.Unmarshal(aaguidNamesJSON, &m)
	return m
}()

// lookupAAGUID returns the product name for a credential's 16-byte AAGUID, or
// "Passkey" when it's unknown or all-zero (anonymous authenticators).
func lookupAAGUID(aaguid []byte) string {
	if len(aaguid) != 16 || allZero(aaguid) {
		return "Passkey"
	}
	if name, ok := aaguidNames[formatUUID(aaguid)]; ok {
		return name
	}
	return "Passkey"
}

func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

// formatUUID renders 16 bytes as the canonical 8-4-4-4-12 lowercase UUID string.
func formatUUID(b []byte) string {
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}
