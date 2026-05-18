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
 */
export function parseEndpointAddress(address: string): EndpointAddress {
  const trimmed = address.trim();
  if (!trimmed) throw new Error("Endpoint address cannot be empty");

  let username = DEFAULT_USERNAME;
  let rest = trimmed;

  const atIdx = rest.indexOf("@");
  if (atIdx !== -1) {
    username = rest.slice(0, atIdx);
    if (!username) throw new Error("Invalid address: empty username");
    rest = rest.slice(atIdx + 1);
  }

  let host: string;
  let port = DEFAULT_PORT;

  if (rest.startsWith("[")) {
    const closeBracket = rest.indexOf("]");
    if (closeBracket === -1) throw new Error("Invalid address: unclosed bracket");
    host = rest.slice(1, closeBracket);
    const after = rest.slice(closeBracket + 1);
    if (after.startsWith(":")) {
      port = parsePort(after.slice(1));
    }
  } else {
    const colonIdx = rest.lastIndexOf(":");
    if (colonIdx !== -1 && /^\d+$/.test(rest.slice(colonIdx + 1))) {
      host = rest.slice(0, colonIdx);
      port = parsePort(rest.slice(colonIdx + 1));
    } else {
      host = rest;
    }
  }

  if (!host) throw new Error("Invalid address: empty host");
  return { username, host, port };
}

function parsePort(s: string): number {
  const port = Number.parseInt(s, 10);
  if (!Number.isFinite(port) || port < 1 || port > 65535) throw new Error("Invalid port");
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
