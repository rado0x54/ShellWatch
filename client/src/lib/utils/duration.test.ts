// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { describe, expect, it } from "vitest";
import { formatTicketDuration } from "./duration.js";

describe("formatTicketDuration", () => {
  it("uses hours for whole hours and minutes otherwise", () => {
    expect(formatTicketDuration(900)).toBe("15 min");
    expect(formatTicketDuration(3600)).toBe("1 h");
    expect(formatTicketDuration(8 * 3600)).toBe("8 h");
    expect(formatTicketDuration(5400)).toBe("90 min");
  });
});
