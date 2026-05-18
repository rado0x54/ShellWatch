// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
const DEFAULT_USERNAME = "shellwatch";
const DEFAULT_PORT = 22;

export interface EndpointAddress {
  username: string;
  host: string;
  port: number;
}

/**
 * Parse an endpoint string in the format `[user@]host[:port]`.
 * Defaults: username = "shellwatch", port = 22.
 *
 * Valid formats:
 *   host
 *   host:port
 *   user@host
 *   user@host:port
 */
export function parseEndpointAddress(address: string): EndpointAddress {
  const trimmed = address.trim();
  if (!trimmed) throw new Error("Endpoint address cannot be empty");

  let username = DEFAULT_USERNAME;
  let rest = trimmed;

  // Extract user@ prefix
  const atIdx = rest.indexOf("@");
  if (atIdx !== -1) {
    username = rest.slice(0, atIdx);
    if (!username) throw new Error(`Invalid endpoint address: empty username in "${address}"`);
    rest = rest.slice(atIdx + 1);
  }

  // Extract host and :port — handle IPv6 in brackets [::1]:port
  let host: string;
  let port = DEFAULT_PORT;

  if (rest.startsWith("[")) {
    // IPv6 bracket notation
    const closeBracket = rest.indexOf("]");
    if (closeBracket === -1)
      throw new Error(`Invalid endpoint address: unclosed bracket in "${address}"`);
    host = rest.slice(1, closeBracket);
    const after = rest.slice(closeBracket + 1);
    if (after.startsWith(":")) {
      port = parsePort(after.slice(1), address);
    } else if (after) {
      throw new Error(
        `Invalid endpoint address: unexpected characters after bracket in "${address}"`,
      );
    }
  } else {
    // Regular host or host:port
    const colonIdx = rest.lastIndexOf(":");
    if (colonIdx !== -1) {
      const possiblePort = rest.slice(colonIdx + 1);
      // Only treat as port if it's all digits (avoid splitting IPv6 bare addresses)
      if (/^\d+$/.test(possiblePort)) {
        host = rest.slice(0, colonIdx);
        port = parsePort(possiblePort, address);
      } else {
        host = rest;
      }
    } else {
      host = rest;
    }
  }

  if (!host) throw new Error(`Invalid endpoint address: empty host in "${address}"`);

  return { username, host, port };
}

function parsePort(portStr: string, original: string): number {
  const port = Number.parseInt(portStr, 10);
  if (!Number.isFinite(port) || port < 1 || port > 65535) {
    throw new Error(`Invalid endpoint address: port out of range in "${original}"`);
  }
  return port;
}

/**
 * Format an endpoint address. The username is always rendered so the display
 * is unambiguous when the endpoint was created without a `user@` prefix and
 * picked up the `shellwatch` default — surfacing the default explicitly
 * matches what sshd actually sees on the wire. The port is still omitted
 * when it's the SSH default (22).
 */
export function formatEndpointAddress(ep: EndpointAddress): string {
  const portPart = ep.port !== DEFAULT_PORT ? `:${ep.port}` : "";
  return `${ep.username}@${ep.host}${portPart}`;
}
