// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { describe, expect, it } from "vitest";
import { resolveKey, resolveKeys } from "./keys.js";

describe("resolveKey", () => {
  it("maps named control keys", () => {
    expect(resolveKey("ctrl+c")).toBe("\x03");
    expect(resolveKey("ctrl+d")).toBe("\x04");
    expect(resolveKey("ctrl+z")).toBe("\x1a");
    expect(resolveKey("ctrl+l")).toBe("\x0c");
  });

  it("maps navigation keys", () => {
    expect(resolveKey("up")).toBe("\x1b[A");
    expect(resolveKey("down")).toBe("\x1b[B");
    expect(resolveKey("left")).toBe("\x1b[D");
    expect(resolveKey("right")).toBe("\x1b[C");
  });

  it("maps special keys", () => {
    expect(resolveKey("tab")).toBe("\t");
    expect(resolveKey("enter")).toBe("\r");
    expect(resolveKey("escape")).toBe("\x1b");
    expect(resolveKey("backspace")).toBe("\x7f");
  });

  it("is case insensitive", () => {
    expect(resolveKey("Ctrl+C")).toBe("\x03");
    expect(resolveKey("ENTER")).toBe("\r");
    expect(resolveKey("Tab")).toBe("\t");
  });

  it("handles text: prefix", () => {
    expect(resolveKey("text:hello")).toBe("hello");
    expect(resolveKey("text:line\\n")).toBe("line\n");
    expect(resolveKey("text:col\\t")).toBe("col\t");
  });

  it("throws on unknown key", () => {
    expect(() => resolveKey("unknown")).toThrow("Unknown key");
  });
});

describe("resolveKeys", () => {
  it("resolves a sequence of keys", () => {
    const result = resolveKeys(["ctrl+c", "enter"]);
    expect(result).toBe("\x03\r");
  });

  it("mixes named keys and text", () => {
    const result = resolveKeys(["text:hello", "enter"]);
    expect(result).toBe("hello\r");
  });
});
