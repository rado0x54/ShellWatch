// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Byte-oriented append-only output ring (port of output-buffer.ts, W6 fix).
// The Node buffer was UTF-16-string based with string-length offsets, which
// split multi-byte runes and mid-ANSI escapes; this holds raw bytes with
// monotonic byte offsets. Offsets are opaque cursors clients round-trip
// (docs/go-backend-architecture.md §5.3, parity item K).
package terminal

import (
	"bytes"
	"sync"
)

const defaultMaxSize = 1024 * 1024 // 1 MiB

// OutputBuffer is a thread-safe byte ring with a monotonic base offset.
type OutputBuffer struct {
	mu         sync.Mutex
	buf        []byte
	baseOffset int64
	maxSize    int
}

func NewOutputBuffer(maxSize int) *OutputBuffer {
	if maxSize <= 0 {
		maxSize = defaultMaxSize
	}
	return &OutputBuffer{maxSize: maxSize}
}

// Append adds data, trimming the oldest bytes past maxSize.
func (b *OutputBuffer) Append(data []byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf = append(b.buf, data...)
	if len(b.buf) > b.maxSize {
		excess := len(b.buf) - b.maxSize
		b.buf = b.buf[excess:]
		b.baseOffset += int64(excess)
	}
}

// ReadResult mirrors OutputReadResult (MCP read_output shape).
type ReadResult struct {
	Data    []byte
	Offset  int64
	HasMore bool
}

// Read returns up to limit bytes after afterOffset (read() in output-buffer.ts).
func (b *OutputBuffer) Read(afterOffset int64, limit int) ReadResult {
	b.mu.Lock()
	defer b.mu.Unlock()
	if limit <= 0 {
		limit = 4000
	}
	relStart := afterOffset - b.baseOffset
	if relStart < 0 {
		relStart = 0
	}
	if relStart > int64(len(b.buf)) {
		relStart = int64(len(b.buf))
	}
	end := relStart + int64(limit)
	if end > int64(len(b.buf)) {
		end = int64(len(b.buf))
	}
	data := append([]byte(nil), b.buf[relStart:end]...)
	return ReadResult{
		Data:    data,
		Offset:  b.baseOffset + relStart + int64(len(data)),
		HasMore: relStart+int64(limit) < int64(len(b.buf)),
	}
}

// FromResult mirrors readFrom()'s {data, offset, reset}.
type FromResult struct {
	Data   []byte
	Offset int64
	Reset  bool
}

// ReadFrom returns the tail from afterOffset (readFrom() in output-buffer.ts).
// reset is true when the caller's offset is unrecoverable (evicted or ahead).
func (b *OutputBuffer) ReadFrom(afterOffset *int64) FromResult {
	b.mu.Lock()
	defer b.mu.Unlock()
	cur := b.baseOffset + int64(len(b.buf))
	if afterOffset == nil {
		return FromResult{Data: append([]byte(nil), b.buf...), Offset: cur}
	}
	off := *afterOffset
	if off == cur {
		return FromResult{Data: nil, Offset: cur}
	}
	if off > cur || off < b.baseOffset {
		return FromResult{Data: append([]byte(nil), b.buf...), Offset: cur, Reset: true}
	}
	return FromResult{Data: append([]byte(nil), b.buf[off-b.baseOffset:]...), Offset: cur}
}

// CurrentOffset is the offset past the last byte.
func (b *OutputBuffer) CurrentOffset() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.baseOffset + int64(len(b.buf))
}

// Tail returns up to the last limit bytes, advancing the cut to the first
// ESC when truncation occurred so a renderer never gets a half escape
// sequence (tail() in output-buffer.ts).
func (b *OutputBuffer) Tail(limit int) []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	if limit <= 0 {
		return nil
	}
	if len(b.buf) <= limit {
		return append([]byte(nil), b.buf...)
	}
	slice := b.buf[len(b.buf)-limit:]
	escIdx := bytes.IndexByte(slice, 0x1b)
	if escIdx <= 0 {
		return append([]byte(nil), slice...)
	}
	return append([]byte(nil), slice[escIdx:]...)
}

// Clear resets the buffer.
func (b *OutputBuffer) Clear() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf = nil
	b.baseOffset = 0
}
