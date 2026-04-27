import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { deriveDisplay, loadBuildInfo } from "./buildInfo.js";

describe("buildInfo.deriveDisplay", () => {
  it("prefers tag when present", () => {
    expect(deriveDisplay("abcdef1234567890", "main", "v0.4.2")).toBe("v0.4.2");
  });

  it("falls back to ref@shortSha", () => {
    expect(deriveDisplay("abcdef1234567890", "develop", null)).toBe("develop@abcdef1");
  });
});

describe("buildInfo.loadBuildInfo", () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "buildinfo-"));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("returns fallback when generated file is missing", () => {
    const info = loadBuildInfo(dir);
    expect(info).toEqual({
      sha: "dev",
      ref: "local",
      tag: null,
      builtAt: null,
      display: "local@dev",
    });
  });

  it("reads sha/ref/tag/builtAt from generated file", () => {
    writeFileSync(
      join(dir, "buildInfo.generated.json"),
      JSON.stringify({
        sha: "abcdef1234567890",
        ref: "develop",
        tag: null,
        builtAt: "2026-04-27T10:00:00Z",
      }),
    );
    const info = loadBuildInfo(dir);
    expect(info).toEqual({
      sha: "abcdef1234567890",
      ref: "develop",
      tag: null,
      builtAt: "2026-04-27T10:00:00Z",
      display: "develop@abcdef1",
    });
  });

  it("uses tag for display when present", () => {
    writeFileSync(
      join(dir, "buildInfo.generated.json"),
      JSON.stringify({
        sha: "abcdef1234567890",
        ref: "main",
        tag: "v0.4.2",
        builtAt: "2026-04-27T10:00:00Z",
      }),
    );
    expect(loadBuildInfo(dir).display).toBe("v0.4.2");
  });

  it("returns fallback on malformed JSON", () => {
    writeFileSync(join(dir, "buildInfo.generated.json"), "not json");
    expect(loadBuildInfo(dir).display).toBe("local@dev");
  });
});
