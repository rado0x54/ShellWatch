// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/** Extract a human-readable message from an unknown thrown value. */
export function errorMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  if (typeof err === "string") return err;
  return String(err);
}
