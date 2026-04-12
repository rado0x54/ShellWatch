import type { OutputReadResult } from "./types.js";

const DEFAULT_MAX_SIZE = 1024 * 1024; // 1MB

export class OutputBuffer {
  private buffer = "";
  private baseOffset = 0;
  private maxSize: number;

  constructor(maxSize = DEFAULT_MAX_SIZE) {
    this.maxSize = maxSize;
  }

  append(data: string): void {
    this.buffer += data;

    if (this.buffer.length > this.maxSize) {
      const excess = this.buffer.length - this.maxSize;
      this.buffer = this.buffer.slice(excess);
      this.baseOffset += excess;
    }
  }

  read(afterOffset = 0, limit = 4000): OutputReadResult {
    const relativeStart = Math.max(0, afterOffset - this.baseOffset);
    const available = this.buffer.slice(relativeStart, relativeStart + limit);
    const newOffset = this.baseOffset + relativeStart + available.length;
    const hasMore = relativeStart + limit < this.buffer.length;

    return { data: available, offset: newOffset, hasMore };
  }

  get currentOffset(): number {
    return this.baseOffset + this.buffer.length;
  }

  /**
   * Return up to the last `limit` characters currently in the buffer.
   *
   * When truncation occurs we may cut mid-ANSI-escape-sequence, which would
   * make downstream terminal renderers (xterm.js) interpret the trailing
   * bytes as plain text until they resynchronize. To guarantee a clean
   * parser state we advance the cut to the first `\x1b` in the slice when
   * truncation happened; this may drop a few leading plain characters but
   * never hands the renderer a half-sequence.
   */
  tail(limit: number): string {
    if (limit <= 0) return "";
    if (this.buffer.length <= limit) return this.buffer;
    const slice = this.buffer.slice(-limit);
    const escIdx = slice.indexOf("\x1b");
    return escIdx <= 0 ? slice : slice.slice(escIdx);
  }

  clear(): void {
    this.buffer = "";
    this.baseOffset = 0;
  }
}
