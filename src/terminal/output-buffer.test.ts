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
});
