// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import adapter from "@sveltejs/adapter-static";
import { vitePreprocess } from "@sveltejs/vite-plugin-svelte";

/** @type {import('@sveltejs/kit').Config} */
const config = {
  preprocess: vitePreprocess(),
  kit: {
    // The Go server embeds this directory (web/embed.go), so a plain
    // `go build` after `pnpm build:client` yields a self-contained binary.
    adapter: adapter({
      pages: "../web/dist",
      assets: "../web/dist",
      fallback: "index.html",
    }),
    alias: {
      $lib: "src/lib",
    },
  },
};

export default config;
