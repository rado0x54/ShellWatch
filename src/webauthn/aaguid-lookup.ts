import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const aaguidNames: Record<string, string> = require("./aaguid-names.json");

/**
 * Look up a human-friendly authenticator name by AAGUID.
 * Returns undefined when the AAGUID is unknown or all-zero (anonymous).
 */
export function lookupAAGUID(aaguid: string): string | undefined {
  if (!aaguid || aaguid === "00000000-0000-0000-0000-000000000000") return undefined;
  return aaguidNames[aaguid];
}
