// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Separate vitest project for the black-box e2e suite (#244). Never picked up by
// `pnpm test` / `pnpm test:integration` (the root config excludes e2e/**).
// Scenario files run sequentially: each boots the server under test on the
// fixed port 3100 against the shared compose stack.
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    root: ".",
    include: ["e2e/scenarios/**/*.e2e.test.ts"],
    globals: true,
    fileParallelism: false,
    // Scenarios wait on real sshd/Hydra round-trips and, in two cases, on the
    // 60 s pending-action TTL / the idle janitor.
    testTimeout: 120_000,
    hookTimeout: 120_000,
    teardownTimeout: 30_000,
    reporters: process.env.CI ? ["default", "junit"] : ["default"],
    outputFile: { junit: "e2e/out/junit.xml" },
    sequence: { concurrent: false },
    retry: 0,
  },
});
