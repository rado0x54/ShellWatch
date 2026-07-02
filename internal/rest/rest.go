// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
package rest

import (
	"encoding/json"
	"net"
	"net/http"

	"github.com/rado0x54/shellwatch/internal/auth"
)

// isoMillis matches Node's new Date().toISOString().
const isoMillis = "2006-01-02T15:04:05.000Z"

// clientIP is the request peer (Node request.ip; trust-proxy handling lands
// with the middleware stack).
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// accountID returns the authenticated account (the gate guarantees one on
// /api/* routes; "" is never seen by these handlers).
func accountID(r *http.Request) string {
	if p, ok := auth.PrincipalFrom(r.Context()); ok {
		return p.AccountID
	}
	return ""
}

// readRawBody decodes the request body into a presence-preserving map, so
// handlers can tell an absent field from an explicit null (the tri-state the
// Node partial-update handlers rely on).
func readRawBody(r *http.Request) map[string]json.RawMessage {
	m := map[string]json.RawMessage{}
	_ = json.NewDecoder(r.Body).Decode(&m)
	return m
}

func stringField(m map[string]json.RawMessage, key string) string {
	if raw, ok := m[key]; ok {
		return jsonString(raw)
	}
	return ""
}

func jsonString(raw json.RawMessage) string {
	var s string
	_ = json.Unmarshal(raw, &s)
	return s
}

func isJSONBool(raw json.RawMessage) bool {
	s := string(raw)
	return s == "true" || s == "false"
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
