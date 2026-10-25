// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    include: ["src/**/*.test.ts", "client/src/**/*.test.ts"],
    // The black-box e2e suite has its own project (e2e/vitest.e2e.config.ts).
    exclude: ["e2e/**", "**/node_modules/**", "**/dist/**"],
    coverage: {
      provider: "v8",
      include: ["src/**/*.ts", "client/src/**/*.ts"],
      exclude: ["src/index.ts", "**/*.test.ts"],
    },
  },
});
