// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Package clock is the injectable time source every TTL store and janitor
// uses (docs/go-backend-architecture.md §5.4) — tests drive a fake clock
// instead of sleeping.
package clock

import (
	"sync"
	"time"
)

// ISOMillis matches Node's new Date().toISOString() rendering — the wire and
// database timestamp format everywhere (one definition instead of a copy per
// package).
const ISOMillis = "2006-01-02T15:04:05.000Z"

type Clock interface {
	Now() time.Time
	// After returns a channel that fires once after d, and a stop function
	// that releases the timer early — callers must invoke it on their fast
	// path so real timers don't accumulate. The fake clock fires waiters
	// from Advance, so timeout code stays testable without wall-clock waits.
	After(d time.Duration) (<-chan time.Time, func())
}

// Real is the wall clock.
type Real struct{}

func (Real) Now() time.Time { return time.Now() }

func (Real) After(d time.Duration) (<-chan time.Time, func()) {
	t := time.NewTimer(d)
	return t.C, func() { t.Stop() }
}

// Fake is a manually-advanced clock for tests.
type Fake struct {
	mu      sync.Mutex
	t       time.Time
	nextID  int
	waiters map[int]fakeWaiter
}

type fakeWaiter struct {
	deadline time.Time
	ch       chan time.Time
}

func NewFake(start time.Time) *Fake { return &Fake{t: start, waiters: map[int]fakeWaiter{}} }

func (f *Fake) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.t
}

func (f *Fake) After(d time.Duration) (<-chan time.Time, func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w := fakeWaiter{deadline: f.t.Add(d), ch: make(chan time.Time, 1)}
	if d <= 0 {
		w.ch <- f.t
		return w.ch, func() {}
	}
	id := f.nextID
	f.nextID++
	f.waiters[id] = w
	return w.ch, func() {
		f.mu.Lock()
		defer f.mu.Unlock()
		delete(f.waiters, id)
	}
}

// Advance moves the clock and fires every waiter whose deadline has passed.
func (f *Fake) Advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.t = f.t.Add(d)
	for id, w := range f.waiters {
		if !w.deadline.After(f.t) {
			w.ch <- f.t
			delete(f.waiters, id)
		}
	}
}
