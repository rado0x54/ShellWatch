// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
package ephemeral

import (
	"testing"
	"time"

	"github.com/rado0x54/shellwatch/internal/clock"
)

func TestTTLAndConsume(t *testing.T) {
	clk := clock.NewFake(time.Unix(1000, 0))
	s := New[string, int](time.Minute, 0, clk)

	s.Put("a", 1)
	if v, ok := s.Get("a"); !ok || v != 1 {
		t.Fatalf("get live: %v %v", v, ok)
	}
	clk.Advance(time.Minute + time.Second)
	if _, ok := s.Get("a"); ok {
		t.Fatal("expired entry must not be returned")
	}

	s.Put("b", 2)
	if v, ok := s.Consume("b"); !ok || v != 2 {
		t.Fatalf("consume: %v %v", v, ok)
	}
	if _, ok := s.Get("b"); ok {
		t.Fatal("consume must be single-use")
	}
	clk.Advance(2 * time.Minute)
	s.Put("c", 3)
	clk.Advance(2 * time.Minute)
	if _, ok := s.Consume("c"); ok {
		t.Fatal("consume of expired entry must fail")
	}
}

func TestCapacityEvictsOldest(t *testing.T) {
	clk := clock.NewFake(time.Unix(1000, 0))
	s := New[string, int](time.Hour, 2, clk)
	s.Put("a", 1)
	s.Put("b", 2)
	s.Put("c", 3) // evicts a
	if _, ok := s.Get("a"); ok {
		t.Fatal("oldest entry must be evicted at capacity")
	}
	for k, want := range map[string]int{"b": 2, "c": 3} {
		if v, ok := s.Get(k); !ok || v != want {
			t.Fatalf("%s: %v %v", k, v, ok)
		}
	}
}

func TestSweepDropsExpiredOnly(t *testing.T) {
	clk := clock.NewFake(time.Unix(1000, 0))
	s := New[string, int](time.Minute, 0, clk)
	s.Put("old", 1)
	clk.Advance(30 * time.Second)
	s.Put("new", 2)
	clk.Advance(31 * time.Second) // old expired, new alive
	s.Sweep()
	if s.Len() != 1 {
		t.Fatalf("len after sweep: %d", s.Len())
	}
	if _, ok := s.Get("new"); !ok {
		t.Fatal("live entry lost in sweep")
	}
}
