// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Package ephemeral is the one generic TTL store behind every in-memory map
// in the system (docs/go-backend-architecture.md §5.4): WebAuthn challenges,
// step-up tokens, the passkey-invite slot, the bearer-introspection cache.
// It replaces the Node backend's mix of module-level singletons and ad-hoc
// sweep timers; the single-instance deployment constraint lives here.
package ephemeral

import (
	"context"
	"sync"
	"time"

	"github.com/rado0x54/shellwatch/internal/clock"
)

type entry[V any] struct {
	value     V
	expiresAt time.Time
}

// Store is a mutex-guarded TTL map with an optional capacity (FIFO eviction
// of the oldest insertion, matching the Node stores' Map-order eviction).
type Store[K comparable, V any] struct {
	mu    sync.Mutex
	m     map[K]entry[V]
	order []K // insertion order for capacity eviction
	ttl   time.Duration
	cap   int // 0 = unbounded
	clk   clock.Clock
}

func New[K comparable, V any](ttl time.Duration, capacity int, clk clock.Clock) *Store[K, V] {
	if clk == nil {
		clk = clock.Real{}
	}
	return &Store[K, V]{m: make(map[K]entry[V]), ttl: ttl, cap: capacity, clk: clk}
}

// Put inserts or replaces k, restarting its TTL. At capacity the oldest
// insertion is evicted first.
func (s *Store[K, V]) Put(k K, v V) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.m[k]; !exists && s.cap > 0 && len(s.m) >= s.cap {
		s.evictOldestLocked()
	}
	if _, exists := s.m[k]; !exists {
		s.order = append(s.order, k)
	}
	s.m[k] = entry[V]{value: v, expiresAt: s.clk.Now().Add(s.ttl)}
}

// Get returns the live value for k, if any.
func (s *Store[K, V]) Get(k K) (V, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.m[k]
	if !ok || !e.expiresAt.After(s.clk.Now()) {
		if ok {
			s.deleteLocked(k)
		}
		var zero V
		return zero, false
	}
	return e.value, true
}

// Consume returns and removes the live value for k (single-use semantics —
// challenges, step-up tokens, invites).
func (s *Store[K, V]) Consume(k K) (V, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.m[k]
	if ok {
		s.deleteLocked(k)
	}
	if !ok || !e.expiresAt.After(s.clk.Now()) {
		var zero V
		return zero, false
	}
	return e.value, true
}

// Delete removes k if present.
func (s *Store[K, V]) Delete(k K) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deleteLocked(k)
}

// Len reports the number of entries, expired ones included until swept.
func (s *Store[K, V]) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.m)
}

// Sweep drops all expired entries.
func (s *Store[K, V]) Sweep() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.clk.Now()
	kept := s.order[:0]
	for _, k := range s.order {
		if e, ok := s.m[k]; ok && !e.expiresAt.After(now) {
			delete(s.m, k)
		} else if ok {
			kept = append(kept, k)
		}
	}
	s.order = kept
}

// Janitor sweeps every interval until ctx is cancelled. One goroutine per
// store, started by the composition root.
func (s *Store[K, V]) Janitor(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.Sweep()
		}
	}
}

func (s *Store[K, V]) evictOldestLocked() {
	for len(s.order) > 0 {
		k := s.order[0]
		s.order = s.order[1:]
		if _, ok := s.m[k]; ok {
			delete(s.m, k)
			return
		}
	}
}

func (s *Store[K, V]) deleteLocked(k K) {
	if _, ok := s.m[k]; !ok {
		return
	}
	delete(s.m, k)
	for i, ok := range s.order {
		if ok == k {
			s.order = append(s.order[:i], s.order[i+1:]...)
			break
		}
	}
}
