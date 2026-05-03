// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
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
  let originalGitTag: string | undefined;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "buildinfo-"));
    originalGitTag = process.env.GIT_TAG;
    delete process.env.GIT_TAG;
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
    if (originalGitTag !== undefined) {
      process.env.GIT_TAG = originalGitTag;
    } else {
      delete process.env.GIT_TAG;
    }
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

  it("reads sha/ref/builtAt from generated file", () => {
    writeFileSync(
      join(dir, "buildInfo.generated.json"),
      JSON.stringify({
        sha: "abcdef1234567890",
        ref: "develop",
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

  it("reads tag from GIT_TAG env (stamped at retag time)", () => {
    writeFileSync(
      join(dir, "buildInfo.generated.json"),
      JSON.stringify({
        sha: "abcdef1234567890",
        ref: "main",
        builtAt: "2026-04-27T10:00:00Z",
      }),
    );
    process.env.GIT_TAG = "v0.4.2";
    const info = loadBuildInfo(dir);
    expect(info.tag).toBe("v0.4.2");
    expect(info.display).toBe("v0.4.2");
  });

  it("ignores empty GIT_TAG env", () => {
    process.env.GIT_TAG = "";
    expect(loadBuildInfo(dir).tag).toBeNull();
  });

  it("returns fallback on malformed JSON", () => {
    writeFileSync(join(dir, "buildInfo.generated.json"), "not json");
    expect(loadBuildInfo(dir).display).toBe("local@dev");
  });
});
