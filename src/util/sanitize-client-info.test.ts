// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { describe, expect, it } from "vitest";
import { CLIENT_HEADER_MAX_LEN, sanitizeClientReportedValue } from "./sanitize-client-info.js";

describe("sanitizeClientReportedValue", () => {
  it("returns the value unchanged for clean strings", () => {
    expect(sanitizeClientReportedValue("claude-desktop")).toBe("claude-desktop");
  });

  it("returns undefined for non-strings", () => {
    expect(sanitizeClientReportedValue(undefined)).toBeUndefined();
    expect(sanitizeClientReportedValue(null)).toBeUndefined();
    expect(sanitizeClientReportedValue(42)).toBeUndefined();
    expect(sanitizeClientReportedValue({ name: "x" })).toBeUndefined();
  });

  it("returns undefined for empty / all-control-char strings", () => {
    expect(sanitizeClientReportedValue("")).toBeUndefined();
    expect(sanitizeClientReportedValue("\x00\x01\n\t\x7f")).toBeUndefined();
  });

  it("strips ASCII control chars including newlines, tabs, DEL", () => {
    expect(sanitizeClientReportedValue("safe\nvalue\tafter\x00null\x7fdel")).toBe(
      "safevalueafternulldel",
    );
  });

  it("clamps to CLIENT_HEADER_MAX_LEN", () => {
    const long = "a".repeat(CLIENT_HEADER_MAX_LEN + 500);
    const result = sanitizeClientReportedValue(long);
    expect(result).toHaveLength(CLIENT_HEADER_MAX_LEN);
  });
});
