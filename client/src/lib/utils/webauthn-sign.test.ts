// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { describe, expect, it } from "vitest";
import { isSafeRedirect, sessionIdFromRedirect } from "./webauthn-sign.js";

describe("isSafeRedirect", () => {
  it.each([
    ["/session/abc", true],
    ["/", true],
    ["//evil.example/session/abc", false],
    ["https://evil.example/", false],
    ["session/abc", false],
    ["", false],
  ])("%j -> %s", (path, want) => {
    expect(isSafeRedirect(path)).toBe(want);
  });
});

describe("sessionIdFromRedirect (#273)", () => {
  it.each([
    ["/session/3f2a-9c", "3f2a-9c"],
    ["/session/a%20b", "a b"],
    [undefined, null], // agent-proxy requests carry no destination
    ["", null],
    ["/session/", null],
    ["/session/abc/extra", null],
    ["/session/abc?x=1", null],
    ["/sign/abc", null],
    ["//evil.example/session/abc", null],
    ["https://evil.example/session/abc", null],
  ])("%j -> %j", (redirectTo, want) => {
    expect(sessionIdFromRedirect(redirectTo)).toBe(want);
  });
});
