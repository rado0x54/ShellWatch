import { describe, expect, it } from "vitest";
import { CLIENT_HEADER_MAX_LEN, readClientHeader } from "./agent-proxy-route.js";

function req(headers: Record<string, string | undefined>) {
  return { headers } as Parameters<typeof readClientHeader>[0];
}

describe("readClientHeader", () => {
  it("returns the value for present headers", () => {
    expect(
      readClientHeader(req({ "x-shellwatch-hostname": "laptop" }), "x-shellwatch-hostname"),
    ).toBe("laptop");
  });

  it("returns undefined for missing headers", () => {
    expect(readClientHeader(req({}), "x-shellwatch-hostname")).toBeUndefined();
  });

  it("returns undefined for empty strings (after stripping)", () => {
    expect(
      readClientHeader(req({ "x-shellwatch-hostname": "" }), "x-shellwatch-hostname"),
    ).toBeUndefined();
    expect(
      readClientHeader(req({ "x-shellwatch-hostname": "\x00\x01\n\t" }), "x-shellwatch-hostname"),
    ).toBeUndefined();
  });

  it("strips ASCII control characters including newlines, tabs, DEL", () => {
    const raw = "safe\nvalue\tafter\x00null\x7fdel";
    expect(readClientHeader(req({ "x-shellwatch-hostname": raw }), "x-shellwatch-hostname")).toBe(
      "safevalueafternulldel",
    );
  });

  it("clamps values to CLIENT_HEADER_MAX_LEN", () => {
    const long = "a".repeat(CLIENT_HEADER_MAX_LEN + 500);
    const result = readClientHeader(
      req({ "x-shellwatch-hostname": long }),
      "x-shellwatch-hostname",
    );
    expect(result).toHaveLength(CLIENT_HEADER_MAX_LEN);
  });

  it("preserves non-ASCII characters (e.g. unicode letters) below the length cap", () => {
    expect(
      readClientHeader(req({ "x-shellwatch-hostname": "café-01" }), "x-shellwatch-hostname"),
    ).toBe("café-01");
  });

  it("returns undefined when the header value isn't a string (array, unknown)", () => {
    const arrayHeaders = req({} as Record<string, string | undefined>);
    (arrayHeaders.headers as unknown as Record<string, unknown>)["x-shellwatch-hostname"] = [
      "a",
      "b",
    ];
    expect(readClientHeader(arrayHeaders, "x-shellwatch-hostname")).toBeUndefined();
  });
});
