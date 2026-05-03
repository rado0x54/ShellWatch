// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";

interface CidrRange {
  addr: bigint;
  mask: bigint;
}

function ipToBigInt(ip: string): bigint | null {
  // Normalize IPv4-mapped IPv6 before parsing
  let normalized = ip;
  if (normalized.startsWith("::ffff:") && normalized.includes(".")) {
    normalized = normalized.slice(7);
  }

  // IPv4
  if (!normalized.includes(":")) {
    const v4Parts = normalized.split(".");
    if (v4Parts.length === 4) {
      const num = v4Parts.reduce((acc, part) => (acc << 8n) | BigInt(parseInt(part, 10)), 0n);
      return num;
    }
    return null;
  }

  // IPv6 (expand :: and parse)
  let expanded = normalized;
  if (expanded.includes("::")) {
    const [left, right] = expanded.split("::");
    const leftParts = left ? left.split(":") : [];
    const rightParts = right ? right.split(":") : [];
    const missing = 8 - leftParts.length - rightParts.length;
    const middle = Array(missing).fill("0");
    expanded = [...leftParts, ...middle, ...rightParts].join(":");
  }

  const parts = expanded.split(":");
  if (parts.length !== 8) return null;

  let result = 0n;
  for (const part of parts) {
    result = (result << 16n) | BigInt(parseInt(part || "0", 16));
  }
  return result;
}

function parseCidr(cidr: string): CidrRange | null {
  const [addr, prefixStr] = cidr.split("/");
  const ip = ipToBigInt(addr);
  if (ip === null) return null;

  const isV6 = addr.includes(":");
  const bits = isV6 ? 128 : 32;
  const prefix = prefixStr ? parseInt(prefixStr, 10) : bits;

  const mask = prefix === 0 ? 0n : ((1n << BigInt(bits)) - 1n) << BigInt(bits - prefix);

  return { addr: ip & mask, mask };
}

export function createIpChecker(allowedNetworks: string[]): (ip: string) => boolean {
  const ranges = allowedNetworks.map(parseCidr).filter((r): r is CidrRange => r !== null);

  return (ip: string) => {
    const addr = ipToBigInt(ip);
    if (addr === null) return false;

    for (const range of ranges) {
      if ((addr & range.mask) === range.addr) {
        return true;
      }
    }
    return false;
  };
}

export function registerIpAllowlist(
  app: FastifyInstance,
  allowedNetworks: string[],
  protectedPaths: string[],
) {
  const isAllowed = createIpChecker(allowedNetworks);

  app.addHook("onRequest", async (request: FastifyRequest, reply: FastifyReply) => {
    const matchesProtectedPath = protectedPaths.some((path) => request.url.startsWith(path));
    if (!matchesProtectedPath) return;

    const clientIp = request.ip;
    if (!isAllowed(clientIp)) {
      app.log.warn(
        { clientIp, url: request.url },
        "Connection rejected: IP not in allowedNetworks",
      );
      reply.status(403).send({ error: "Forbidden" });
    }
  });
}
