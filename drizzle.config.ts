// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { defineConfig } from "drizzle-kit";

export default defineConfig({
  schema: "./src/db/schema.ts",
  out: "./drizzle",
  dialect: "sqlite",
  dbCredentials: {
    url: process.env.SHELLWATCH_DB?.replace("sqlite:", "") || "./data/shellwatch.db",
  },
});
