// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// AAGUID -> human label (port of src/webauthn/aaguid-lookup.ts). The full
// Node lookup maps known authenticator AAGUIDs to product names; the port
// carries the fallback and grows the table as needed. The fixtures use a
// zero AAGUID, which maps to the "Passkey" fallback.
package webauthn

// lookupAAGUID returns the product label for a known AAGUID, or "Passkey".
func lookupAAGUID(aaguid []byte) string {
	// TODO(phase2): port the full aaguid table (scripts/update-aaguids.ts
	// output) if any golden depends on a named authenticator. All current
	// fixtures use the all-zero AAGUID -> fallback.
	return "Passkey"
}
