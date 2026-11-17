// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { resolve } from "$app/paths";
import type { Pathname } from "$app/types";

/**
 * `resolve()` for a route held in a `Pathname` variable (tab lists, nav
 * targets). SvelteKit types `resolve` as one rest-tuple overload per route,
 * and TypeScript stops matching a union argument against them once the app
 * has more than 25 routes — so a variable of the full `Pathname` type no
 * longer type-checks even though every member is valid. Literal paths keep
 * calling `resolve` directly.
 */
export function resolvePath(path: Pathname): string {
  return (resolve as (route: string) => string)(path);
}
