// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { describe, expect, it } from "vitest";
import { computePkceS256, verifyPkceS256 } from "./pkce.js";

describe("pkce S256", () => {
  it("computes the RFC 7636 reference challenge", () => {
    // From RFC 7636 appendix B:
    // verifier "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    // challenge "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    expect(computePkceS256(verifier)).toBe("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
  });

  it("accepts matching verifier/challenge pairs", () => {
    const verifier = "a".repeat(64);
    const challenge = computePkceS256(verifier);
    expect(verifyPkceS256(verifier, challenge)).toBe(true);
  });

  it("rejects mismatched verifier", () => {
    const challenge = computePkceS256("a".repeat(64));
    expect(verifyPkceS256("b".repeat(64), challenge)).toBe(false);
  });

  it("rejects empty inputs", () => {
    expect(verifyPkceS256("", "")).toBe(false);
    expect(verifyPkceS256("anything", "")).toBe(false);
  });

  it("rejects challenges of the wrong length even if prefix matches", () => {
    const verifier = "x".repeat(64);
    const full = computePkceS256(verifier);
    expect(verifyPkceS256(verifier, full.slice(0, -1))).toBe(false);
  });
});
