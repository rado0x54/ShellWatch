// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { describe, expect, it } from "vitest";
import { OutputBuffer } from "./output-buffer.js";

describe("OutputBuffer", () => {
  it("starts empty", () => {
    const buf = new OutputBuffer();
    const result = buf.read();
    expect(result.data).toBe("");
    expect(result.offset).toBe(0);
    expect(result.hasMore).toBe(false);
  });

  it("appends and reads data", () => {
    const buf = new OutputBuffer();
    buf.append("hello ");
    buf.append("world");
    const result = buf.read();
    expect(result.data).toBe("hello world");
    expect(result.offset).toBe(11);
  });

  it("reads from afterOffset", () => {
    const buf = new OutputBuffer();
    buf.append("hello world");
    const result = buf.read(5);
    expect(result.data).toBe(" world");
    expect(result.offset).toBe(11);
  });

  it("respects limit", () => {
    const buf = new OutputBuffer();
    buf.append("hello world");
    const result = buf.read(0, 5);
    expect(result.data).toBe("hello");
    expect(result.offset).toBe(5);
    expect(result.hasMore).toBe(true);
  });

  it("supports incremental reads", () => {
    const buf = new OutputBuffer();
    buf.append("aaa");
    const r1 = buf.read(0, 2);
    expect(r1.data).toBe("aa");
    expect(r1.offset).toBe(2);
    expect(r1.hasMore).toBe(true);

    const r2 = buf.read(r1.offset);
    expect(r2.data).toBe("a");
    expect(r2.offset).toBe(3);
    expect(r2.hasMore).toBe(false);

    buf.append("bbb");
    const r3 = buf.read(r2.offset);
    expect(r3.data).toBe("bbb");
    expect(r3.offset).toBe(6);
  });

  it("evicts oldest data when exceeding max size", () => {
    const buf = new OutputBuffer(10);
    buf.append("12345");
    buf.append("67890");
    expect(buf.currentOffset).toBe(10);

    buf.append("abc");
    // Buffer is now "890abc" (13 chars total, evicted 3 from front)
    // but max is 10, so buffer holds "4567890abc"... let me recalculate
    // total appended: 13 chars. maxSize: 10. excess: 3. baseOffset: 3.
    // buffer: "4567890abc"
    expect(buf.currentOffset).toBe(13);

    const result = buf.read(0);
    // offset 0 is before baseOffset (3), so starts from baseOffset
    expect(result.data.length).toBeLessThanOrEqual(10);
    expect(result.data).toBe("4567890abc");

    // Reading from offset 3 (the new base) gives everything
    const result2 = buf.read(3);
    expect(result2.data).toBe("4567890abc");
  });

  it("handles read after eviction with stale offset", () => {
    const buf = new OutputBuffer(5);
    buf.append("12345");
    const r1 = buf.read();
    expect(r1.offset).toBe(5);

    buf.append("67890");
    // Now buffer is "67890", baseOffset is 5
    // Stale offset 0 should clamp to baseOffset
    const r2 = buf.read(0);
    expect(r2.data).toBe("67890");
  });

  it("clear resets buffer", () => {
    const buf = new OutputBuffer();
    buf.append("data");
    buf.clear();
    const result = buf.read();
    expect(result.data).toBe("");
    expect(result.offset).toBe(0);
    expect(buf.currentOffset).toBe(0);
  });

  it("returns empty data for offset at end", () => {
    const buf = new OutputBuffer();
    buf.append("hello");
    const result = buf.read(5);
    expect(result.data).toBe("");
    expect(result.hasMore).toBe(false);
  });

  describe("tail", () => {
    it("returns empty string when buffer is empty", () => {
      const buf = new OutputBuffer();
      expect(buf.tail(100)).toBe("");
    });

    it("returns the entire buffer when limit exceeds its length", () => {
      const buf = new OutputBuffer();
      buf.append("hello");
      expect(buf.tail(100)).toBe("hello");
    });

    it("returns the last `limit` chars when buffer is longer", () => {
      const buf = new OutputBuffer();
      buf.append("hello world");
      expect(buf.tail(5)).toBe("world");
    });

    it("returns empty string for non-positive limits", () => {
      const buf = new OutputBuffer();
      buf.append("hello");
      expect(buf.tail(0)).toBe("");
      expect(buf.tail(-1)).toBe("");
    });

    it("respects ring-buffer truncation", () => {
      const buf = new OutputBuffer(10);
      buf.append("0123456789abcdef"); // exceeds maxSize=10, keeps last 10
      expect(buf.tail(4)).toBe("cdef");
      expect(buf.tail(100)).toBe("6789abcdef");
    });

    it("advances to first ESC when truncation cuts mid-sequence", () => {
      const buf = new OutputBuffer();
      // Prefix is "abc\x1b[31m..." — if the cut starts in the middle of the
      // escape sequence, we'd want to resync at the next ESC.
      buf.append("abc\x1b[31mred\x1b[0mreset");
      // limit=9 grabs "ed\x1b[0mreset" — starts mid-plain-text (the "ed" from
      // "red"). The ANSI-safe tail should start at the ESC so xterm parses a
      // clean sequence.
      const t = buf.tail(9);
      expect(t.startsWith("\x1b[0m")).toBe(true);
    });

    it("leaves plain-text tails untouched when no ESC is present", () => {
      const buf = new OutputBuffer();
      buf.append("hello world");
      // limit=5 truncates; slice has no ESC so returned as-is.
      expect(buf.tail(5)).toBe("world");
    });
  });

  describe("readFrom", () => {
    it("returns the full buffer when afterOffset is undefined", () => {
      const buf = new OutputBuffer();
      buf.append("hello world");
      expect(buf.readFrom()).toEqual({ data: "hello world", offset: 11, reset: false });
    });

    it("returns empty when caller is already current", () => {
      const buf = new OutputBuffer();
      buf.append("hello");
      expect(buf.readFrom(5)).toEqual({ data: "", offset: 5, reset: false });
    });

    it("returns the delta when caller is mid-buffer", () => {
      const buf = new OutputBuffer();
      buf.append("hello world");
      expect(buf.readFrom(6)).toEqual({ data: "world", offset: 11, reset: false });
    });

    it("signals reset when caller is ahead of current (e.g. server restarted)", () => {
      const buf = new OutputBuffer();
      buf.append("hello");
      const r = buf.readFrom(500);
      expect(r.reset).toBe(true);
      expect(r.data).toBe("hello");
      expect(r.offset).toBe(5);
    });

    it("signals reset when caller's offset has been evicted", () => {
      const buf = new OutputBuffer(10);
      buf.append("0123456789");
      buf.append("abcdefghij"); // baseOffset now 10, buffer = "abcdefghij"
      const r = buf.readFrom(3);
      expect(r.reset).toBe(true);
      expect(r.data).toBe("abcdefghij");
      expect(r.offset).toBe(20);
    });
  });
});
