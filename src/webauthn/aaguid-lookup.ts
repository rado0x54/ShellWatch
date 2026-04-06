// @ts-expect-error — Node 22+ supports JSON import attributes; tsc needs verbatimModuleSyntax for `with`
import aaguidNames from "./aaguid-names.json" with { type: "json" };

/**
 * Look up a human-friendly authenticator name by AAGUID.
 * Returns undefined when the AAGUID is unknown or all-zero (anonymous).
 */
export function lookupAAGUID(aaguid: string): string | undefined {
  if (!aaguid || aaguid === "00000000-0000-0000-0000-000000000000") return undefined;
  return (aaguidNames as Record<string, string>)[aaguid];
}
