// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Client unit tests. Server tests are Go (`go test ./...`); the black-box e2e
// suite has its own project (e2e/vitest.e2e.config.ts).
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    include: ["client/src/**/*.test.ts"],
    exclude: ["e2e/**", "**/node_modules/**", "**/dist/**"],
    coverage: {
      provider: "v8",
      include: ["client/src/**/*.ts"],
      exclude: ["**/*.test.ts"],
    },
  },
});
