// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * Bearer-auth helper for the mini-app integration tests (#217). Replaces the
 * old session-cookie minting: returns a fake Hydra admin (to wire the bearer
 * gate around) plus a `bearerFor(accountId)` that registers a `ui`-scoped token
 * and returns a ready `Authorization` header value.
 */
import { createFakeHydraAdmin } from "./fake-hydra.js";

export function makeTestBearer() {
  const admin = createFakeHydraAdmin();
  let counter = 0;
  function bearerFor(accountId: string): string {
    counter += 1;
    const token = `ui-token-${counter}`;
    admin.registerToken(token, { sub: accountId, scope: "ui", client_id: "shellwatch-web" });
    return `Bearer ${token}`;
  }
  return { admin, bearerFor };
}
