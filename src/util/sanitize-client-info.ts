// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * Sanitization for client-reported identity strings that cross a trust boundary
 * into pending-action payloads / approval UI (agent-proxy WS handshake headers,
 * MCP initialize handshake clientInfo).
 *
 * Strips ASCII control chars (incl. newlines, tabs, DEL) and clamps length so
 * downstream payloads stay bounded and the approval UI can't be smuggled
 * formatting tricks.
 */

export const CLIENT_HEADER_MAX_LEN = 128;

export function sanitizeClientReportedValue(raw: unknown): string | undefined {
  if (typeof raw !== "string") return undefined;
  // eslint-disable-next-line no-control-regex
  const cleaned = raw.replace(/[\x00-\x1f\x7f]/g, "").slice(0, CLIENT_HEADER_MAX_LEN);
  return cleaned.length > 0 ? cleaned : undefined;
}
