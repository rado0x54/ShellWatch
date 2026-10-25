// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Package apierr owns every HTTP error envelope ShellWatch emits. The wire
// contract (docs/api/, pinned by the err-* goldens) has three shapes:
//
//   - {error}                    — the standard envelope (REST, WebAuthn,
//     bearer gate, Hydra provider pages, IP allowlist)
//   - {error, code}              — the step-up gate's machine-readable 401
//     (contract item F, the only coded error today)
//   - {error, error_description} — mediated DCR, RFC 7591 wording
//
// Handlers must not hand-roll error bodies: rendering through one package is
// what makes the planned post-cutover envelope convergence (item F — fold
// {error} into {error, code}) a change here instead of a hunt through
// handlers. Success payloads stay with the per-surface writeJSON helpers.
package apierr

import (
	"encoding/json"
	"net/http"
)

func write(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// Write renders the standard {error} envelope. Status is caller-chosen — the
// Hydra provider pages ship {error} bodies with 200 (pinned; the SPA
// branches on the field, not the status).
func Write(w http.ResponseWriter, status int, msg string) {
	write(w, status, map[string]string{"error": msg})
}

// WriteCode renders the step-up {error, code} envelope.
func WriteCode(w http.ResponseWriter, status int, msg, code string) {
	write(w, status, map[string]string{"error": msg, "code": code})
}

// WriteOAuth renders the {error, error_description} envelope (mediated DCR).
func WriteOAuth(w http.ResponseWriter, status int, code, desc string) {
	write(w, status, map[string]string{"error": code, "error_description": desc})
}
