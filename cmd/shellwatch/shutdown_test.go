// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
package main

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"
)

// startServer serves h on a loopback listener with request contexts derived
// from a cancellable base, as run() wires it.
func startServer(t *testing.T, h http.Handler) (*http.Server, context.CancelFunc, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	reqCtx, cancel := context.WithCancel(context.Background())
	srv := &http.Server{
		Handler:     h,
		BaseContext: func(net.Listener) context.Context { return reqCtx },
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { cancel(); _ = srv.Close() })
	return srv, cancel, "http://" + ln.Addr().String()
}

// openRequest issues a GET and returns once the handler is running.
func openRequest(t *testing.T, url string, started <-chan struct{}) {
	t.Helper()
	go func() {
		resp, err := http.Get(url)
		if err == nil {
			_ = resp.Body.Close()
		}
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("handler never started")
	}
}

func TestDrainHTTP(t *testing.T) {
	tests := []struct {
		name string
		// handler blocks until it is told to stop; release is never closed
		// for the straggler case, so only the hard close ends it.
		honoursContext bool
		grace          time.Duration
		deadline       time.Duration
		wantForced     bool
		maxElapsed     time.Duration
	}{
		{
			// The #272 case: a stream that ends with its request context.
			// The drain finishes right after the grace, far inside the deadline.
			name:           "streaming handler unwinds after grace",
			honoursContext: true,
			grace:          50 * time.Millisecond,
			deadline:       10 * time.Second,
			wantForced:     false,
			maxElapsed:     2 * time.Second,
		},
		{
			name:           "handler ignoring its context is hard-closed at the deadline",
			honoursContext: false,
			grace:          20 * time.Millisecond,
			deadline:       200 * time.Millisecond,
			wantForced:     true,
			maxElapsed:     2 * time.Second,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			started := make(chan struct{})
			release := make(chan struct{})
			defer close(release)
			h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				close(started)
				if tc.honoursContext {
					<-r.Context().Done()
					return
				}
				<-release
			})
			srv, cancel, url := startServer(t, h)
			openRequest(t, url, started)

			begin := time.Now()
			forced := drainHTTP(srv, cancel, tc.grace, tc.deadline)
			elapsed := time.Since(begin)

			if forced != tc.wantForced {
				t.Errorf("forced = %v, want %v", forced, tc.wantForced)
			}
			if elapsed > tc.maxElapsed {
				t.Errorf("drain took %v, want < %v", elapsed, tc.maxElapsed)
			}
		})
	}
}

// A request that finishes inside the grace period is not cancelled: the
// drain waits for it rather than cutting it short.
func TestDrainHTTPLetsShortRequestsFinish(t *testing.T) {
	started := make(chan struct{})
	finished := make(chan error, 1)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		time.Sleep(100 * time.Millisecond) // an in-flight write
		finished <- r.Context().Err()
	})
	srv, cancel, url := startServer(t, h)
	openRequest(t, url, started)

	if drainHTTP(srv, cancel, time.Second, 10*time.Second) {
		t.Fatal("drain was forced")
	}
	if err := <-finished; err != nil {
		t.Errorf("request context cancelled before the grace ran out: %v", err)
	}
}
