// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Package clock is the injectable time source every TTL store and janitor
// uses (docs/go-backend-architecture.md §5.4) — tests drive a fake clock
// instead of sleeping.
package clock

import (
	"sync"
	"time"
)

type Clock interface {
	Now() time.Time
}

// Real is the wall clock.
type Real struct{}

func (Real) Now() time.Time { return time.Now() }

// Fake is a manually-advanced clock for tests.
type Fake struct {
	mu sync.Mutex
	t  time.Time
}

func NewFake(start time.Time) *Fake { return &Fake{t: start} }

func (f *Fake) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.t
}

func (f *Fake) Advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.t = f.t.Add(d)
}
