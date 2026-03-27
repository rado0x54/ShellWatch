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

  clear(): void {
    this.buffer = "";
    this.baseOffset = 0;
  }
}
