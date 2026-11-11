// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Allowlist of recognized Web Push services (port of
// src/server/routes/push-endpoint-validator.ts). Anything outside this list
// is rejected at submit-time so an attacker cannot turn /api/push/subscribe
// into an SSRF primitive (the stored URL is later POSTed to by the sender).
//
// Mirrors https://github.com/pushpad/known-push-services/blob/master/whitelist
package push

import (
	"net/url"
	"strings"
)

var exactHosts = map[string]bool{
	"android.googleapis.com":            true, // Chrome (legacy GCM)
	"fcm.googleapis.com":                true, // Chrome / Edge (Chromium) / FCM Web Push
	"updates.push.services.mozilla.com": true, // Firefox autopush (production)
	"updates-autopush.stage.mozaws.net": true, // Firefox autopush (stage)
	"updates-autopush.dev.mozaws.net":   true, // Firefox autopush (dev)
}

var suffixHosts = []string{
	".push.apple.com",     // Safari (e.g. web.push.apple.com)
	".notify.windows.com", // Edge (legacy) / WNS
}

// IsAllowedEndpoint reports whether endpoint is a recognized push service URL.
func IsAllowedEndpoint(endpoint string) bool {
	u, err := url.Parse(endpoint)
	if err != nil {
		return false
	}
	if u.Scheme != "https" {
		return false
	}
	if u.User != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	if exactHosts[host] {
		return true
	}
	for _, suffix := range suffixHosts {
		if strings.HasSuffix(host, suffix) {
			return true
		}
	}
	return false
}
