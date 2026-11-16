// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  isCeremonyCancelled,
  isSafeRedirect,
  sessionIdFromRedirect,
  signOrAutoSkip,
  SkipFailedError,
  skipAction,
  skipResultMessage,
} from "./webauthn-sign.js";

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

describe("isCeremonyCancelled (#308)", () => {
  it.each([
    [new DOMException("no passkey", "NotAllowedError"), true],
    [{ name: "NotAllowedError" }, true],
    [new DOMException("bad rp", "SecurityError"), false],
    [new DOMException("aborted", "AbortError"), false],
    [new DOMException("x", "InvalidStateError"), false],
    [new Error("No assertion returned"), false],
    [null, false],
    ["NotAllowedError", false],
  ])("%o -> %s", (err, want) => {
    expect(isCeremonyCancelled(err)).toBe(want);
  });
});

describe("signOrAutoSkip (#308)", () => {
  const params = { credentialId: "Y3JlZA", challenge: "Y2hhbA==", rpId: "localhost" };
  const assertion = { authenticatorData: "a", signature: "s", clientDataJSON: "{}" };

  it("signs and resolves when the ceremony succeeds", async () => {
    const skip = vi.fn();
    const out = await signOrAutoSkip("act", params, {
      ceremony: async () => assertion,
      resolve: async () => ({ redirectTo: "/session/s1" }),
      skip,
    });
    expect(out).toEqual({ kind: "signed", response: { redirectTo: "/session/s1" } });
    expect(skip).not.toHaveBeenCalled();
  });

  it("skips automatically on NotAllowedError (cancelled / not on this device)", async () => {
    const skip = vi.fn(async () => ({ kind: "skipped" }) as const);
    const resolve = vi.fn();
    const out = await signOrAutoSkip("act", params, {
      ceremony: async () => {
        throw new DOMException("cancelled", "NotAllowedError");
      },
      resolve,
      skip,
    });
    expect(out).toEqual({ kind: "auto-skipped", skip: { kind: "skipped" } });
    expect(skip).toHaveBeenCalledWith("act");
    expect(resolve).not.toHaveBeenCalled();
  });

  it.each([
    ["SecurityError", new DOMException("rp mismatch", "SecurityError")],
    ["AbortError", new DOMException("aborted", "AbortError")],
    ["plain Error", new Error("No assertion returned")],
  ])("does not skip on %s", async (_, err) => {
    const skip = vi.fn();
    await expect(
      signOrAutoSkip("act", params, {
        ceremony: async () => {
          throw err;
        },
        skip,
      }),
    ).rejects.toBe(err);
    expect(skip).not.toHaveBeenCalled();
  });

  it("does not skip when the resolve call fails", async () => {
    const skip = vi.fn();
    await expect(
      signOrAutoSkip("act", params, {
        ceremony: async () => assertion,
        resolve: async () => {
          throw new Error("Invalid signature");
        },
        skip,
      }),
    ).rejects.toThrow("Invalid signature");
    expect(skip).not.toHaveBeenCalled();
  });

  it("surfaces a failed automatic skip as SkipFailedError", async () => {
    await expect(
      signOrAutoSkip("act", params, {
        ceremony: async () => {
          throw new DOMException("cancelled", "NotAllowedError");
        },
        skip: async () => {
          throw new SkipFailedError("network down");
        },
      }),
    ).rejects.toBeInstanceOf(SkipFailedError);
  });
});

describe("skipAction (#308)", () => {
  afterEach(() => vi.restoreAllMocks());

  const respond = (status: number, body: unknown) =>
    vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(new Response(JSON.stringify(body), { status }));

  it("calls the unchanged deny route", async () => {
    const spy = respond(200, { status: "denied" });
    await expect(skipAction("act-1")).resolves.toEqual({ kind: "skipped" });
    expect(spy.mock.calls[0][0]).toBe("/api/actions/act-1/deny");
    expect((spy.mock.calls[0][1] as RequestInit).method).toBe("POST");
  });

  it("treats an already-expired request as ended", async () => {
    respond(200, { status: "expired" });
    await expect(skipAction("a")).resolves.toEqual({ kind: "ended", status: "expired" });
  });

  it("treats a swept request (404) as ended", async () => {
    respond(404, { error: "Action not found" });
    await expect(skipAction("a")).resolves.toEqual({ kind: "ended", status: "expired" });
  });

  it.each([
    [409, { error: "Action is already completed" }],
    [500, { error: "Internal server error" }],
  ])("throws SkipFailedError on %i", async (status, body) => {
    respond(status, body);
    await expect(skipAction("a")).rejects.toBeInstanceOf(SkipFailedError);
  });

  it("throws SkipFailedError on a network error", async () => {
    vi.spyOn(globalThis, "fetch").mockRejectedValueOnce(new TypeError("Failed to fetch"));
    const err = await skipAction("a").catch((e: unknown) => e);
    expect(err).toBeInstanceOf(SkipFailedError);
    expect((err as Error).message).toBe("Failed to skip: Failed to fetch");
  });
});

describe("skip messages (#308)", () => {
  it("manual skip names the key and announces a possible follow-up", () => {
    expect(skipResultMessage({ kind: "skipped" }, "manual", "YubiKey")).toBe(
      "Skipped YubiKey. If another key matches, a new request follows.",
    );
  });
  it("auto skip says the passkey isn't on this device", () => {
    expect(skipResultMessage({ kind: "skipped" }, "auto", "iPhone")).toBe(
      "Skipped iPhone: not available on this device",
    );
  });
  it("an ended request says so", () => {
    expect(skipResultMessage({ kind: "ended", status: "expired" }, "auto", "iPhone")).toBe(
      "The request had already expired.",
    );
  });
});
