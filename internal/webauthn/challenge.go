// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Purpose-tagged challenge store (port of src/webauthn/challenge-store.ts) on
// the generic ephemeral.Store. The purpose binds a minted challenge to the
// flow it was minted for so a captured assertion can't be replayed against a
// sibling endpoint (same-type cross-flow defence on top of @simplewebauthn's
// clientDataJSON.type binding).
package webauthn

import (
	"time"

	"github.com/rado0x54/shellwatch/internal/clock"
	"github.com/rado0x54/shellwatch/internal/ephemeral"
)

// Challenge purposes (CHALLENGE_PURPOSE). Step-up purposes embed the action.
const (
	PurposeLogin             = "auth:login"
	PurposeSelfRegister      = "auth:register"
	PurposeRegisterInAccount = "register:in_account"
	PurposeRegisterInvite    = "register:invite"
)

const (
	challengeTTL = 5 * time.Minute
	challengeCap = 10_000
)

type challengeEntry struct {
	challenge string
	purpose   string
}

// ChallengeStore mints and consumes purpose-bound challenges.
type ChallengeStore struct {
	s *ephemeral.Store[string, challengeEntry]
}

func NewChallengeStore(clk clock.Clock) *ChallengeStore {
	return &ChallengeStore{s: ephemeral.New[string, challengeEntry](challengeTTL, challengeCap, clk)}
}

// Store binds a challenge to a purpose and returns its id.
func (c *ChallengeStore) Store(challengeID, challenge, purpose string) {
	c.s.Put(challengeID, challengeEntry{challenge: challenge, purpose: purpose})
}

// Consume returns the challenge string, or "" if expired, missing, or stored
// under a different purpose. The entry is removed even on purpose mismatch
// (single-use; no cross-purpose probing).
func (c *ChallengeStore) Consume(challengeID, expectedPurpose string) string {
	e, ok := c.s.Consume(challengeID)
	if !ok || e.purpose != expectedPurpose {
		return ""
	}
	return e.challenge
}
