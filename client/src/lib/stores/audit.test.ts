// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { describe, expect, it } from "vitest";
import { signingOutcomeLabel } from "./audit.js";

describe("signingOutcomeLabel (#308)", () => {
  it.each([
    ["webauthn-sign", "denied", "skipped"],
    ["key-approve", "denied", "skipped"],
    // A blocked connection is not a skipped key.
    ["host-key-mismatch", "denied", "denied"],
    // A none-auth refusal is neither a skip nor a denial (#311).
    ["unauthenticated-endpoint", "denied", "Refused: no authentication"],
    ["webauthn-sign", "approved", "approved"],
    ["key-approve", "expired", "expired"],
    ["host-key-cleared", "approved", "approved"],
  ])("%s / %s -> %s", (type, outcome, want) => {
    expect(signingOutcomeLabel(type, outcome)).toBe(want);
  });
});
