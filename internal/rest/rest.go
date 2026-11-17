// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
package rest

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/go-chi/chi/v5"

	"github.com/rado0x54/shellwatch/internal/apierr"
	"github.com/rado0x54/shellwatch/internal/auth"
	"github.com/rado0x54/shellwatch/internal/clock"
)

// isoMillis matches Node's new Date().toISOString().
const isoMillis = clock.ISOMillis

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

// pathParam is a chi URL parameter, percent-decoded. chi matches on the
// escaped path, so an id the client sent through encodeURIComponent (a demo
// id's ":" as %3A, a CIMD client id's URL) is still escaped in URLParam.
// net/http answers a malformed escape with its own 400 before routing, so
// the error is defence in depth only.
func pathParam(r *http.Request, key string) (string, error) {
	return url.PathUnescape(chi.URLParam(r, key))
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	apierr.Write(w, status, msg)
}

// writeInternal answers 500 "internal error" and logs the cause, which the
// response body deliberately hides.
func writeInternal(w http.ResponseWriter, r *http.Request, err error) {
	attrs := []any{"method", r.Method, "route", routePattern(r), "err", err}
	if p, ok := auth.PrincipalFrom(r.Context()); ok {
		attrs = append(attrs, "account", p.AccountID)
	}
	slog.Error("rest: internal error", attrs...)
	apierr.Write(w, http.StatusInternalServerError, "internal error")
}

// routePattern is the chi route ("/api/endpoints/{id}"), never the raw path.
func routePattern(r *http.Request) string {
	if rc := chi.RouteContext(r.Context()); rc != nil && rc.RoutePattern() != "" {
		return rc.RoutePattern()
	}
	return "unknown"
}
