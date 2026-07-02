// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// SSH file-key listing (/api/keys) REST (port of ssh-keys.ts). Admin-only;
// passkeys are listed via /api/webauthn/credentials. Pinned by keys-list golden.
package rest

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/rado0x54/shellwatch/internal/store"
)

// Keys wires GET /api/keys.
type Keys struct {
	Store    *store.SSHKeys
	Accounts *store.Accounts
	// Available reports whether a key's material is currently on disk (the
	// key-directory watcher); nil => assume available.
	Available func(fingerprint string) bool
}

func (k *Keys) Mount(r chi.Router) { r.Get("/api/keys", k.list) }

func (k *Keys) list(w http.ResponseWriter, r *http.Request) {
	out := []map[string]any{}
	// File keys are admin-only (passkeys go through the credentials route).
	if k.Accounts.IsAdmin(r.Context(), accountID(r)) {
		keys, err := k.Store.ListFull(r.Context())
		if err != nil {
			writeErr(w, 500, "internal error")
			return
		}
		for _, key := range keys {
			if key.Type != "file" {
				continue
			}
			available := key.Enabled && (k.Available == nil || k.Available(key.Fingerprint))
			algorithm := "unknown"
			if fields := strings.Fields(key.PublicKey); len(fields) > 0 {
				algorithm = fields[0]
			}
			var authorizedKeys any
			if key.PublicKey != "" {
				authorizedKeys = key.PublicKey
			}
			out = append(out, map[string]any{
				"id": key.ID, "label": key.Label, "type": key.Type, "algorithm": algorithm,
				"fingerprint": key.Fingerprint,
				"revoked":     !key.Enabled, "available": available,
				"authorizedKeysEntry": authorizedKeys,
				"createdAt":           key.CreatedAt, "lastUsedAt": key.LastUsedAt,
			})
		}
	}
	writeJSON(w, 200, map[string]any{"keys": out})
}
