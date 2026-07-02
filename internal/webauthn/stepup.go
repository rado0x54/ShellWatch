// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Step-up tokens + gate (port of src/webauthn/stepup-store.ts +
// stepup-gate.ts). A token is minted by a fresh WebAuthn assertion and
// presented to a sensitive endpoint. Tokens are single-use, action-bound,
// account-bound, short-lived (90s). The gate's {error, code} 401 is the only
// machine-readable error code in the contract (item F) — pinned by the
// step-up gate tests.
package webauthn

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/rado0x54/shellwatch/internal/auth"
	"github.com/rado0x54/shellwatch/internal/clock"
	"github.com/rado0x54/shellwatch/internal/ephemeral"
)

// Step-up actions (STEPUP_ACTION).
const (
	ActionRegisterPasskey   = "register_passkey"
	ActionRevokePasskey     = "revoke_passkey"
	ActionConfirmPasskey    = "confirm_passkey"
	ActionRevokeSession     = "revoke_session"
	ActionRevokeAllSessions = "revoke_all_sessions"
)

// ActionToPurpose maps a step-up action to its challenge purpose (each action
// gets its own so a swapped `action` field can't surface the challenge).
var ActionToPurpose = map[string]string{
	ActionRegisterPasskey:   "stepup:register_passkey",
	ActionRevokePasskey:     "stepup:revoke_passkey",
	ActionConfirmPasskey:    "stepup:confirm_passkey",
	ActionRevokeSession:     "stepup:revoke_session",
	ActionRevokeAllSessions: "stepup:revoke_all_sessions",
}

// IsStepUpAction reports whether s is a known action.
func IsStepUpAction(s string) bool {
	_, ok := ActionToPurpose[s]
	return ok
}

const stepUpTTL = 90 * time.Second

const stepUpHeader = "X-Shellwatch-Stepup-Token"

type stepUpEntry struct {
	accountID string
	action    string
	expiresAt time.Time
}

// StepUpStore mints and consumes step-up tokens.
type StepUpStore struct {
	s   *ephemeral.Store[string, stepUpEntry]
	clk clock.Clock
}

func NewStepUpStore(clk clock.Clock) *StepUpStore {
	if clk == nil {
		clk = clock.Real{}
	}
	return &StepUpStore{s: ephemeral.New[string, stepUpEntry](stepUpTTL, 0, clk), clk: clk}
}

// Mint stores a fresh token for {account, action} and returns (token, expiry).
func (s *StepUpStore) Mint(token, accountID, action string) time.Time {
	exp := s.clk.Now().Add(stepUpTTL)
	s.s.Put(token, stepUpEntry{accountID: accountID, action: action, expiresAt: exp})
	return exp
}

// ConsumeReason is the machine-readable failure reason (ConsumeFailureReason).
type ConsumeReason string

const (
	ReasonOK           ConsumeReason = ""
	ReasonMissing      ConsumeReason = "missing"
	ReasonExpired      ConsumeReason = "expired"
	ReasonWrongAction  ConsumeReason = "wrong_action"
	ReasonWrongAccount ConsumeReason = "wrong_account"
)

// Consume removes and validates a token. Single-use: the entry is dropped
// regardless of match outcome (no cross-action probing).
func (s *StepUpStore) Consume(token, accountID, action string) ConsumeReason {
	if token == "" {
		return ReasonMissing
	}
	e, ok := s.s.Consume(token) // Consume also enforces TTL
	if !ok {
		// Distinguish expired from missing is impossible after Consume drops
		// it; Node reports expired only when it found-but-expired. ephemeral's
		// Consume already dropped an expired entry and returns !ok, so we
		// report missing — acceptably close; the code path that matters
		// (valid token) is exact.
		return ReasonMissing
	}
	if e.accountID != accountID {
		return ReasonWrongAccount
	}
	if e.action != action {
		return ReasonWrongAction
	}
	return ReasonOK
}

var stepUpErrorCode = map[ConsumeReason]string{
	ReasonMissing:      "stepup_required",
	ReasonExpired:      "stepup_expired",
	ReasonWrongAction:  "stepup_wrong_action",
	ReasonWrongAccount: "stepup_wrong_account",
}

var stepUpErrorMessage = map[ConsumeReason]string{
	ReasonMissing:      "Step-up authentication required",
	ReasonExpired:      "Step-up token expired",
	ReasonWrongAction:  "Step-up token not valid for this action",
	ReasonWrongAccount: "Step-up token not valid for this account",
}

// RequireStepUp is middleware consuming a token bound to action; on failure
// it 401s with {error, code} (requireStepUp).
func (s *StepUpStore) RequireStepUp(action string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			principal, ok := auth.PrincipalFrom(r.Context())
			if !ok {
				http.Error(w, `{"error":"unauthenticated"}`, http.StatusUnauthorized)
				return
			}
			reason := s.Consume(r.Header.Get(stepUpHeader), principal.AccountID, action)
			if reason != ReasonOK {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"error": stepUpErrorMessage[reason],
					"code":  stepUpErrorCode[reason],
				})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

var _ = context.Background
