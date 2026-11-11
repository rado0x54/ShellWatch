// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// CORS middleware (port of @fastify/cors registered with {origin: true}):
// reflect any Origin, answer preflight OPTIONS with 204 before the bearer
// gate — hosted MCP clients and cross-origin browser callers depend on the
// preflight not 401ing.
package httpserver

import "net/http"

const corsAllowMethods = "GET,HEAD,PUT,PATCH,POST,DELETE"

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "" {
			next.ServeHTTP(w, r)
			return
		}
		h := w.Header()
		h.Add("Vary", "Origin")
		h.Set("Access-Control-Allow-Origin", origin)

		if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
			// Preflight: reflect requested headers, allow the default method
			// set, and stop here (fastify-cors preflightContinue: false).
			h.Set("Access-Control-Allow-Methods", corsAllowMethods)
			if reqHeaders := r.Header.Get("Access-Control-Request-Headers"); reqHeaders != "" {
				h.Set("Access-Control-Allow-Headers", reqHeaders)
				h.Add("Vary", "Access-Control-Request-Headers")
			}
			h.Set("Content-Length", "0")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
