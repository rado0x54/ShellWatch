// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { writable } from "svelte/store";

export interface BuildInfo {
  sha: string;
  ref: string;
  tag: string | null;
  builtAt: string | null;
  display: string;
}

const FALLBACK: BuildInfo = {
  sha: "dev",
  ref: "local",
  tag: null,
  builtAt: null,
  display: "local@dev",
};

/** Build identity, populated from window.__BUILD_INFO__ injected by /config.js. */
export const buildInfo = writable<BuildInfo>(FALLBACK);

export function initBuildInfoFromWindow(): void {
  const win = window as unknown as { __BUILD_INFO__?: BuildInfo };
  if (win.__BUILD_INFO__) {
    buildInfo.set(win.__BUILD_INFO__);
  }
}
