// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
package main

import (
	"context"
	"net/http"
	"time"
)

const (
	// shutdownGrace is how long in-flight requests get to finish on their own
	// before their contexts are cancelled; enough for an upload's commit or an
	// audit write, short enough that Ctrl-C feels immediate (#272).
	shutdownGrace = time.Second
	// shutdownDeadline bounds the whole drain; whatever is still running then
	// (a handler that ignores its context) is hard-closed.
	shutdownDeadline = 10 * time.Second
)

// drainHTTP stops srv accepting and waits for its requests to finish. After
// grace it calls cancelRequests — the cancel of the context srv.BaseContext
// hands out — so streaming handlers (MCP streams, read_output long-polls)
// unwind instead of holding the drain open. If deadline passes anyway, the
// remaining connections are hard-closed and forced reports true. Either way
// the server is fully stopped on return; a forced close is not an error.
func drainHTTP(srv *http.Server, cancelRequests context.CancelFunc, grace, deadline time.Duration) (forced bool) {
	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()
	timer := time.AfterFunc(grace, cancelRequests)
	defer timer.Stop()
	// Hijacked connections (browser WebSockets, /agent-proxy) are not tracked
	// by Shutdown; cancelling their request context on the way out ends them.
	defer cancelRequests()

	if err := srv.Shutdown(ctx); err != nil {
		_ = srv.Close()
		return true
	}
	return false
}
