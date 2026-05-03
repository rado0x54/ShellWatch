// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * Fetches the community-maintained AAGUID registry and extracts a
 * names-only lookup table for use in passkey label suggestions.
 *
 * Source: https://github.com/passkeydeveloper/passkey-authenticator-aaguids
 *
 * Run via: pnpm update:aaguids
 */

import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const COMBINED_URL =
  "https://raw.githubusercontent.com/passkeydeveloper/passkey-authenticator-aaguids/main/combined_aaguid.json";

const OUTPUT = join(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "src",
  "webauthn",
  "aaguid-names.json",
);

interface CommunityEntry {
  name: string;
  icon_dark?: string;
  icon_light?: string;
}

async function main() {
  console.log("Fetching combined_aaguid.json …");
  const res = await fetch(COMBINED_URL);
  if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);

  const data = (await res.json()) as Record<string, CommunityEntry>;

  const names: Record<string, string> = {};
  for (const [aaguid, entry] of Object.entries(data)) {
    if (entry.name) names[aaguid] = entry.name;
  }

  writeFileSync(OUTPUT, JSON.stringify(names, null, 2) + "\n");
  console.log(`Wrote ${Object.keys(names).length} entries to ${OUTPUT}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
