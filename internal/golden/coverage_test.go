// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Golden coverage guard (#234): every operationId in docs/api/openapi.yaml is
// either pinned by at least one golden fixture or explicitly excluded with a
// stated reason. The original failure mode (#225) was treating "N goldens
// green" as "contract complete" while the oracle covered ~20 of 54
// operations; this test makes such a gap impossible to hide. When an
// operation is added, removed or renamed in the spec, this test fails until
// the manifest below is updated — exclusions are visible and reviewed, never
// silent.
package golden

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/goccy/go-yaml"
)

const specPath = "../../docs/api/openapi.yaml"

type coverage struct {
	goldens  []string
	excluded string
}

func goldened(names ...string) coverage { return coverage{goldens: names} }
func excluded(reason string) coverage   { return coverage{excluded: reason} }

const optionsPassthrough = "WebAuthn ceremony /options body is a non-deterministic library passthrough " +
	"(random challenge); only the ShellWatch-constructed finish body is goldened."

// goldenCoverage maps every spec operationId to its fixture(s) under
// testdata/goldens/ (file name without .json) or to an exclusion reason.
var goldenCoverage = map[string]coverage{
	// --- Meta + discovery ---
	"getHealth":                              goldened("health"),
	"getVersion":                             goldened("meta-version"),
	"getConfigScript":                        goldened("meta-config-js"),
	"getAuthorizationServerMetadata":         goldened("discovery-authorization-server"),
	"getProtectedResourceMetadata":           goldened("discovery-protected-resource"),
	"getProtectedResourceMetadataMcp":        goldened("discovery-protected-resource-mcp"),
	"getProtectedResourceMetadataAgentProxy": goldened("discovery-protected-resource-agent"),

	// --- Endpoints ---
	"listEndpoints":         goldened("endpoints-list"),
	"createEndpoint":        goldened("endpoints-create"),
	"updateEndpoint":        goldened("endpoint-update"),
	"deleteEndpoint":        goldened("endpoint-delete"),
	"pinEndpointHostKey":    goldened("endpoint-hostkey-pin"),
	"deleteEndpointHostKey": goldened("endpoint-hostkey-delete"),

	// --- Sessions ---
	"createSession":  goldened("session-create"),
	"listSessions":   goldened("session-list"),
	"getSessionTail": goldened("session-tail"),
	"closeSession":   goldened("session-close"),

	// --- Audit ---
	"listAuditSessions": goldened("audit-sessions-page1", "audit-sessions-page2"),
	"listAuditSignings": goldened("audit-signings-page1"),
	"getAuditSigning":   goldened("audit-signings-by-id"),

	// --- Notification log (#252) ---
	"listNotifications": goldened("notifications-list"),

	// --- Current account + admin ---
	"getCurrentAccount":    goldened("account-me"),
	"updateCurrentAccount": goldened("account-update"),
	"listAccounts":         goldened("account-list"),
	"deleteAccount":        goldened("account-delete"),
	"exportSeedConfig":     goldened("account-export-seed"),
	"listSshKeys":          goldened("keys-list"),

	// --- Passkey credentials + invites ---
	"getPasskeyStatus":                goldened("passkey-status"),
	"listPasskeys":                    goldened("credentials-list"),
	"confirmPasskey":                  goldened("credential-confirm"),
	"updatePasskeyLabel":              goldened("credential-label"),
	"revokePasskey":                   goldened("credential-revoke"),
	"createPasskeyInvite":             goldened("webauthn-invite-mint"),
	"getPasskeyInvite":                goldened("invite-get"),
	"getPasskeyInviteByToken":         goldened("invite-by-token"),
	"finishPasskeyRegistration":       goldened("webauthn-register"),
	"finishInvitePasskeyRegistration": goldened("webauthn-invite-redeem"),

	// --- Account registration + login + step-up ---
	"finishAccountRegistration": goldened("webauthn-self-register"),
	"finishHydraLogin":          goldened("webauthn-login-verify"),
	"finishStepUp":              goldened("webauthn-stepup-verify"),

	// --- WebAuthn /options passthroughs — deliberately excluded ---
	"startAccountRegistration":       excluded(optionsPassthrough),
	"startPasskeyRegistration":       excluded(optionsPassthrough),
	"startStepUp":                    excluded(optionsPassthrough),
	"startHydraLogin":                excluded(optionsPassthrough),
	"startInvitePasskeyRegistration": excluded(optionsPassthrough),

	// --- Authorized clients + DCR + consent ---
	"listAuthorizedClients":      goldened("auth-sessions-list"),
	"revokeAuthorizedClient":     goldened("auth-session-revoke"),
	"revokeAllAuthorizedClients": goldened("auth-session-revoke-all"),
	"registerOauthClient":        goldened("dcr-register"),
	"approveHydraConsent":        goldened("consent-approve"),
	"startHydraConsent":          excluded(optionsPassthrough),
	"finishHydraConsent": excluded("The { redirectTo } success envelope is already characterized by " +
		"webauthn-login-verify (identical accept-consent → redirect construction); the success path " +
		"additionally requires a full DB-enrolled WebAuthn assertion ceremony. Dedicated capture deferred."),

	// --- Pending actions + push ---
	"getAction":              goldened("action-get"),
	"resolveAction":          goldened("action-resolve"),
	"denyAction":             goldened("action-deny", "action-deny-expired"),
	"createPushSubscription": goldened("push-subscribe"),
	"deletePushSubscription": goldened("push-unsubscribe"),
}

func specOperationIDs(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(specPath)
	if err != nil {
		t.Fatalf("read spec: %v", err)
	}
	var doc struct {
		Paths map[string]map[string]struct {
			OperationID string `yaml:"operationId"`
		} `yaml:"paths"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse spec: %v", err)
	}
	methods := map[string]bool{"get": true, "post": true, "put": true, "patch": true, "delete": true}
	var ids []string
	for _, item := range doc.Paths {
		for method, op := range item {
			if methods[method] && op.OperationID != "" {
				ids = append(ids, op.OperationID)
			}
		}
	}
	sort.Strings(ids)
	return ids
}

func TestGoldenCoverage(t *testing.T) {
	specOps := specOperationIDs(t)
	if len(specOps) == 0 {
		t.Fatal("no operationIds found in the spec")
	}

	t.Run("every spec operationId is goldened or explicitly excluded", func(t *testing.T) {
		for _, op := range specOps {
			if _, ok := goldenCoverage[op]; !ok {
				t.Errorf("%s: neither goldened nor excluded — add a fixture under testdata/goldens and map it here, or document why it is excluded", op)
			}
		}
	})

	t.Run("the manifest has no stale entries", func(t *testing.T) {
		specSet := map[string]bool{}
		for _, op := range specOps {
			specSet[op] = true
		}
		for op := range goldenCoverage {
			if !specSet[op] {
				t.Errorf("%s: in the manifest but not in openapi.yaml (renamed or removed operation?)", op)
			}
		}
	})

	t.Run("every mapped fixture exists and every exclusion states a reason", func(t *testing.T) {
		for op, c := range goldenCoverage {
			if len(c.goldens) == 0 && c.excluded == "" {
				t.Errorf("%s: empty manifest entry", op)
			}
			for _, name := range c.goldens {
				if _, err := os.Stat(filepath.Join(goldensDir, name+".json")); err != nil {
					t.Errorf("%s → %s.json: %v", op, name, err)
				}
			}
		}
	})
}
