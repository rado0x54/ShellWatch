// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
package main

import (
	"context"
	"io"
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

// openRequest issues a GET and returns once the handler is running. The
// returned channel yields the client's outcome when the request ends: nil for
// a complete response, the transport error if the connection was cut.
func openRequest(t *testing.T, url string, started <-chan struct{}) <-chan error {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		resp, err := http.Get(url)
		if err == nil {
			_, err = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("handler never started")
	}
	return done
}

// clientOutcome waits briefly for the client's request to end.
func clientOutcome(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(2 * time.Second):
		t.Fatal("client request still open after the drain returned")
		return nil
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
		minElapsed     time.Duration // the drain must not give up early
		maxElapsed     time.Duration
		// wantClientErr: the client saw its connection cut (hard close)
		// rather than a complete response.
		wantClientErr bool
	}{
		{
			// The #272 case: a stream that ends with its request context.
			// The drain finishes right after the grace, far inside the deadline.
			name:           "streaming handler unwinds after grace",
			honoursContext: true,
			grace:          50 * time.Millisecond,
			deadline:       10 * time.Second,
			wantForced:     false,
			minElapsed:     50 * time.Millisecond,
			maxElapsed:     2 * time.Second,
			wantClientErr:  false,
		},
		{
			name:           "handler ignoring its context is hard-closed at the deadline",
			honoursContext: false,
			grace:          20 * time.Millisecond,
			deadline:       200 * time.Millisecond,
			wantForced:     true,
			minElapsed:     200 * time.Millisecond,
			maxElapsed:     2 * time.Second,
			wantClientErr:  true,
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
			done := openRequest(t, url, started)

			begin := time.Now()
			forced := drainHTTP(srv, cancel, tc.grace, tc.deadline)
			elapsed := time.Since(begin)

			if forced != tc.wantForced {
				t.Errorf("forced = %v, want %v", forced, tc.wantForced)
			}
			if elapsed < tc.minElapsed || elapsed > tc.maxElapsed {
				t.Errorf("drain took %v, want between %v and %v", elapsed, tc.minElapsed, tc.maxElapsed)
			}
			if err := clientOutcome(t, done); (err != nil) != tc.wantClientErr {
				t.Errorf("client error = %v, want error: %v", err, tc.wantClientErr)
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
	done := openRequest(t, url, started)

	if drainHTTP(srv, cancel, time.Second, 10*time.Second) {
		t.Fatal("drain was forced")
	}
	if err := <-finished; err != nil {
		t.Errorf("request context cancelled before the grace ran out: %v", err)
	}
	if err := clientOutcome(t, done); err != nil {
		t.Errorf("client did not get a complete response: %v", err)
	}
}
