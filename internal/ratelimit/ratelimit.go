// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Package ratelimit is a fixed-window per-IP limiter for the unauthenticated
// surfaces (port of @fastify/rate-limit as configured in Node: per-route
// counters keyed by request.ip, 429 body {statusCode, error, message} and
// x-ratelimit-* / retry-after headers). security.rateLimit feeds the windows.
package ratelimit

import (
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/rado0x54/shellwatch/internal/clock"
	"github.com/rado0x54/shellwatch/internal/realip"
)

// maxBuckets caps per-limiter memory under a source-address flood (Node's
// @fastify/rate-limit uses a 5000-entry LRU for the same reason). Evicting a
// live bucket resets that key's window — the same trade-off the LRU makes.
const maxBuckets = 5000

// Limiter is one route's fixed-window counter set (one bucket per client IP).
type Limiter struct {
	max    int
	window time.Duration
	clk    clock.Clock

	mu        sync.Mutex
	buckets   map[string]*bucket
	lastPrune time.Time
}

type bucket struct {
	count int
	start time.Time
}

// New builds a limiter; max <= 0 disables it (Allow always true).
func New(max int, window time.Duration, clk clock.Clock) *Limiter {
	if clk == nil {
		clk = clock.Real{}
	}
	return &Limiter{max: max, window: window, clk: clk, buckets: map[string]*bucket{}}
}

// Allow records a hit for key and reports whether it is within the limit,
// plus the remaining quota and time until the window resets.
func (l *Limiter) Allow(key string) (ok bool, remaining int, reset time.Duration) {
	if l.max <= 0 {
		return true, 0, 0
	}
	now := l.clk.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.buckets[key]
	if b == nil || now.Sub(b.start) >= l.window {
		if b == nil && len(l.buckets) >= maxBuckets {
			// At capacity: prune expired buckets, but at most once per second —
			// under a sustained flood every bucket is in-window and a per-insert
			// O(n) scan would find nothing while holding the lock.
			if now.Sub(l.lastPrune) >= time.Second {
				l.lastPrune = now
				for k, old := range l.buckets {
					if now.Sub(old.start) >= l.window {
						delete(l.buckets, k)
					}
				}
			}
			// Still full: evict one arbitrary entry (O(1)) so the flood is
			// memory-bounded rather than the limiter failing open or closed.
			if len(l.buckets) >= maxBuckets {
				for k := range l.buckets {
					delete(l.buckets, k)
					break
				}
			}
		}
		b = &bucket{start: now}
		l.buckets[key] = b
	}
	b.count++
	remaining = l.max - b.count
	if remaining < 0 {
		remaining = 0
	}
	return b.count <= l.max, remaining, l.window - now.Sub(b.start)
}

// Rule attaches a limiter to a method + path (Prefix matches path as a
// leading segment, for parameterized routes like /api/passkey-invite/:token).
type Rule struct {
	Method  string
	Path    string
	Prefix  bool
	Limiter *Limiter
}

func (r Rule) matches(req *http.Request) bool {
	if req.Method != r.Method {
		return false
	}
	if r.Prefix {
		return len(req.URL.Path) > len(r.Path) && req.URL.Path[:len(r.Path)] == r.Path
	}
	return req.URL.Path == r.Path
}

// Middleware enforces the first matching rule per request (rules don't
// overlap in practice; each route has its own counter, like Node).
func Middleware(rules []Rule) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			for i := range rules {
				if !rules[i].matches(req) {
					continue
				}
				l := rules[i].Limiter
				ok, remaining, reset := l.Allow(realip.FromRequest(req))
				resetSecs := int(reset.Seconds() + 0.5)
				w.Header().Set("X-RateLimit-Limit", strconv.Itoa(l.max))
				w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
				w.Header().Set("X-RateLimit-Reset", strconv.Itoa(resetSecs))
				if !ok {
					w.Header().Set("Retry-After", strconv.Itoa(resetSecs))
					w.Header().Set("Content-Type", "application/json; charset=utf-8")
					w.WriteHeader(http.StatusTooManyRequests)
					_, _ = fmt.Fprintf(w,
						`{"statusCode":429,"error":"Too Many Requests","message":"Rate limit exceeded, retry in %s"}`,
						humanDuration(reset))
					return
				}
				break
			}
			next.ServeHTTP(w, req)
		})
	}
}

// humanDuration approximates the ms-library formatting @fastify/rate-limit
// uses in its default 429 message ("15 minutes", "1 minute", "30 seconds").
func humanDuration(d time.Duration) string {
	if d >= time.Minute {
		mins := int(d.Round(time.Minute) / time.Minute)
		if mins <= 1 {
			return "1 minute"
		}
		return fmt.Sprintf("%d minutes", mins)
	}
	secs := int(d.Round(time.Second) / time.Second)
	if secs <= 1 {
		return "1 second"
	}
	return fmt.Sprintf("%d seconds", secs)
}
