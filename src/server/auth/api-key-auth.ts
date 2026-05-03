// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { createHash } from "node:crypto";

/** SHA-256 of the raw API key string. Used both at storage and lookup time. */
export function hashApiKey(raw: string): string {
  return createHash("sha256").update(raw).digest("hex");
}
