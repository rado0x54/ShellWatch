import { count } from "drizzle-orm";
import type { ShellWatchDB } from "../connection.js";
import { webauthnCredentials } from "../schema.js";

/** Check if any passkeys are registered in the system. */
export function hasPasskeys(db: ShellWatchDB): boolean {
  const result = db.select({ total: count() }).from(webauthnCredentials).get();
  return (result?.total ?? 0) > 0;
}
