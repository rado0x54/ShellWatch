// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Passkey-invite slot (port of src/webauthn/invite-store.ts): one slot per
// account, 5-minute TTL, single-use. Creating a new invite supersedes the
// old one; the atomic consume-if-token-matches closes the redeem/supersede
// race. An injected instance (not a module-level singleton) — the W4 fix.
package webauthn

import (
	"sync"
	"time"

	"github.com/rado0x54/shellwatch/internal/clock"
)

const inviteTTL = 5 * time.Minute

// InviteSlot is an active invite.
type InviteSlot struct {
	AccountID string
	Token     string
	ExpiresAt time.Time
	CreatedAt time.Time
}

// InviteStore holds one slot per account with token lookup.
type InviteStore struct {
	mu        sync.Mutex
	byAccount map[string]InviteSlot
	clk       clock.Clock
}

func NewInviteStore(clk clock.Clock) *InviteStore {
	if clk == nil {
		clk = clock.Real{}
	}
	return &InviteStore{byAccount: map[string]InviteSlot{}, clk: clk}
}

// Create mints (or supersedes) the account's invite. token is injected.
func (s *InviteStore) Create(accountID, token string) InviteSlot {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.clk.Now()
	slot := InviteSlot{AccountID: accountID, Token: token, CreatedAt: now, ExpiresAt: now.Add(inviteTTL)}
	s.byAccount[accountID] = slot
	return slot
}

// FindForAccount returns the account's live slot, if any.
func (s *InviteStore) FindForAccount(accountID string) (InviteSlot, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	slot, ok := s.byAccount[accountID]
	if !ok || !slot.ExpiresAt.After(s.clk.Now()) {
		if ok {
			delete(s.byAccount, accountID)
		}
		return InviteSlot{}, false
	}
	return slot, true
}

// FindByToken looks up a live slot by token (O(n) over accounts).
func (s *InviteStore) FindByToken(token string) (InviteSlot, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.clk.Now()
	for acc, slot := range s.byAccount {
		if !slot.ExpiresAt.After(now) {
			delete(s.byAccount, acc)
			continue
		}
		if slot.Token == token {
			return slot, true
		}
	}
	return InviteSlot{}, false
}

// ConsumeIfTokenMatches removes the account's slot only if its current token
// matches — refuses to delete a freshly-superseded slot (consumeInviteSlotIfTokenMatches).
func (s *InviteStore) ConsumeIfTokenMatches(accountID, token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	slot, ok := s.byAccount[accountID]
	if !ok || slot.Token != token {
		return false
	}
	delete(s.byAccount, accountID)
	return true
}
