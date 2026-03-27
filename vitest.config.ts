import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    include: ["src/**/*.test.ts", "client/src/**/*.test.ts"],
    coverage: {
      provider: "v8",
      include: ["src/**/*.ts", "client/src/**/*.ts"],
      exclude: ["src/index.ts", "**/*.test.ts"],
    },
  },
});
