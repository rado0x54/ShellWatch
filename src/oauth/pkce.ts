// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { createHash } from "node:crypto";

export function computePkceS256(verifier: string): string {
  return createHash("sha256").update(verifier).digest("base64url");
}

export function verifyPkceS256(verifier: string, challenge: string): boolean {
  const computed = computePkceS256(verifier);
  if (computed.length !== challenge.length) return false;
  let diff = 0;
  for (let i = 0; i < computed.length; i++) {
    diff |= computed.charCodeAt(i) ^ challenge.charCodeAt(i);
  }
  return diff === 0;
}
