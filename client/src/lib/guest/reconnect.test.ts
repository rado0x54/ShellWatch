// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { describe, expect, it } from "vitest";
import {
  ENDED,
  endingFor,
  onConnectionLost,
  RECONNECT_DELAY_MS,
  RECONNECT_GIVE_UP_MS,
} from "./reconnect.js";

describe("guest page reconnect rule (#321)", () => {
  it("reload: two failed handshakes, then the server answers closed → no active session", () => {
    let dropSince: number | null = null;
    for (const now of [0, RECONNECT_DELAY_MS]) {
      const d = onConnectionLost(dropSince, false, now);
      expect(d).toEqual({ retry: true, dropSince: 0 });
      if (d.retry) dropSince = d.dropSince;
    }
    expect(endingFor(false, ENDED)).toEqual({ phase: "invalid" });
  });

  it("a first connect is retried for the whole give-up window, not cut short", () => {
    expect(onConnectionLost(0, false, RECONNECT_GIVE_UP_MS).retry).toBe(true);
  });

  it("gives up past the window: the ending depends only on what this tab saw", () => {
    const past = RECONNECT_GIVE_UP_MS + 1;
    expect(onConnectionLost(0, false, past)).toEqual({
      retry: false,
      ending: { phase: "invalid" },
    });
    expect(onConnectionLost(0, true, past)).toEqual({
      retry: false,
      ending: { phase: "ended", message: ENDED },
    });
  });

  it("a closed frame after a status ends with the generic text", () => {
    expect(endingFor(true, ENDED)).toEqual({ phase: "ended", message: ENDED });
    expect(endingFor(true)).toEqual({ phase: "ended", message: ENDED });
  });

  it("the window-cap text is always shown, even as the first frame", () => {
    const cap = "Too many open windows for this session.";
    expect(endingFor(false, cap)).toEqual({ phase: "ended", message: cap });
  });
});
