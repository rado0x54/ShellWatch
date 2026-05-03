// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { sveltekit } from "@sveltejs/kit/vite";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [sveltekit()],
  server: {
    port: 3001,
    proxy: {
      "/api": "http://localhost:3000",
      "/ws": { target: "http://localhost:3000", ws: true },
      "/mcp": { target: "http://localhost:3000", ws: true },
      "/health": "http://localhost:3000",
      "/config.js": "http://localhost:3000",
    },
  },
});
