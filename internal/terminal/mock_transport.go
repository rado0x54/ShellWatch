// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
package terminal

import "sync"

// MockTransport is an in-memory transport for tests: writes are echoed back
// as output unless Echo is disabled, and Push/Hangup/Fail drive events.
type MockTransport struct {
	mu     sync.Mutex
	events chan Event
	closed bool
	Writes [][]byte
	Echo   bool
}

// NewMockTransport returns a ready mock. Echo defaults on.
func NewMockTransport() *MockTransport {
	return &MockTransport{events: make(chan Event, 64), Echo: true}
}

func (t *MockTransport) Write(data []byte) error {
	t.mu.Lock()
	t.Writes = append(t.Writes, append([]byte(nil), data...))
	echo := t.Echo && !t.closed
	t.mu.Unlock()
	if echo {
		t.events <- Event{Data: data}
	}
	return nil
}

func (t *MockTransport) Resize(cols, rows int) error { return nil }

func (t *MockTransport) Close() error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil
	}
	t.closed = true
	t.mu.Unlock()
	t.events <- Event{Closed: true}
	close(t.events)
	return nil
}

func (t *MockTransport) Events() <-chan Event { return t.events }

// Push injects output.
func (t *MockTransport) Push(data []byte) { t.events <- Event{Data: data} }
