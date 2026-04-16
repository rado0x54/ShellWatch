import { defineConfig } from "drizzle-kit";

export default defineConfig({
  schema: ["./src/db/schema.ts", "./src/oauth/adapter/schema.ts"],
  out: "./drizzle",
  dialect: "sqlite",
  dbCredentials: {
    url: process.env.SHELLWATCH_DB?.replace("sqlite:", "") || "./data/shellwatch.db",
  },
});
