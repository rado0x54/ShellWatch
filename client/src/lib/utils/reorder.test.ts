// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { describe, expect, it } from "vitest";
import { moveItem, sameOrder } from "./reorder.js";

describe("moveItem", () => {
  it.each([
    [["a", "b", "c"], 0, 2, ["b", "c", "a"]],
    [["a", "b", "c"], 2, 0, ["c", "a", "b"]],
    [["a", "b", "c"], 1, 1, ["a", "b", "c"]],
    [["a", "b", "c"], 0, 9, ["b", "c", "a"]], // clamped
    [["a", "b", "c"], 1, -1, ["b", "a", "c"]], // clamped
    [["a", "b", "c"], 5, 0, ["a", "b", "c"]], // out of range: unchanged
  ])("%j move %i -> %i = %j", (items, from, to, want) => {
    const before = items.slice();
    expect(moveItem(items, from, to)).toEqual(want);
    expect(items).toEqual(before); // input untouched
  });
});

describe("sameOrder", () => {
  it("compares element-wise", () => {
    expect(sameOrder(["a", "b"], ["a", "b"])).toBe(true);
    expect(sameOrder(["a", "b"], ["b", "a"])).toBe(false);
    expect(sameOrder(["a"], ["a", "b"])).toBe(false);
  });
});
