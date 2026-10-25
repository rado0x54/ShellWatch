// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
package webauthn

import "testing"

func TestLookupAAGUID(t *testing.T) {
	// All-zero (anonymous) -> fallback.
	if got := lookupAAGUID(make([]byte, 16)); got != "Passkey" {
		t.Errorf("zero AAGUID: got %q, want Passkey", got)
	}
	// Wrong length -> fallback.
	if got := lookupAAGUID([]byte{1, 2, 3}); got != "Passkey" {
		t.Errorf("short AAGUID: got %q", got)
	}
	// A known AAGUID from the table resolves to its product name.
	// 9eb7eabc-9db5-49a1-b6c3-555a802093f4 -> "YubiKey 5 Series with NFC KVZR57"
	known := []byte{0x9e, 0xb7, 0xea, 0xbc, 0x9d, 0xb5, 0x49, 0xa1, 0xb6, 0xc3, 0x55, 0x5a, 0x80, 0x20, 0x93, 0xf4}
	if got := lookupAAGUID(known); got != "YubiKey 5 Series with NFC KVZR57" {
		t.Errorf("known AAGUID: got %q", got)
	}
	// Unknown 16-byte AAGUID -> fallback.
	unknown := []byte{0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	if got := lookupAAGUID(unknown); got != "Passkey" {
		t.Errorf("unknown AAGUID: got %q", got)
	}
	if len(aaguidNames) < 100 {
		t.Fatalf("aaguid table looks empty/truncated: %d entries", len(aaguidNames))
	}
}
