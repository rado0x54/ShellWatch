// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * Fixed addresses for the black-box e2e suite (#244). Everything is loopback.
 * Ports deliberately avoid the dev compose (Hydra 4444/4445) and the spike
 * (sshd 2222) so the suite can run next to a developer's local stack. The
 * compose file (e2e/docker-compose.e2e.yml) and Hydra config
 * (e2e/hydra/hydra.e2e.yml) hard-code the same values — keep them in sync.
 */
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const REPO_ROOT = resolve(fileURLToPath(import.meta.url), "../../..");
export const E2E_DIR = resolve(REPO_ROOT, "e2e");
export const OUT_DIR = resolve(E2E_DIR, "out");
export const COMPOSE_FILE = resolve(E2E_DIR, "docker-compose.e2e.yml");
export const COMPOSE_PROJECT = "shellwatch-e2e";

/** Server under test — launched from dist/ by e2e/harness/server.ts. */
export const SERVER_PORT = 3100;
export const SERVER_URL = `http://127.0.0.1:${SERVER_PORT}`;
/** WebAuthn relying party the fake authenticator's credentials are bound to. */
export const RP_ID = "localhost";
/** Origin the fake authenticator stamps into clientDataJSON for login/step-up. */
export const WEBAUTHN_ORIGIN = SERVER_URL;

export const HYDRA_PUBLIC_URL = "http://127.0.0.1:4544";
export const HYDRA_ADMIN_URL = "http://127.0.0.1:4545";
/** First-party SPA client id (config default; provisioned by the server on boot). */
export const SPA_CLIENT_ID = "shellwatch-web";

export type SshdTarget = "modern" | "stable";

export interface SshdInfo {
  service: string;
  host: string;
  port: number;
  /** Whether the image accepts webauthn-sk-* public keys (OpenSSH >= 10.3). */
  webauthnSk: boolean;
}

export const SSHD: Record<SshdTarget, SshdInfo> = {
  modern: { service: "sshd-modern", host: "127.0.0.1", port: 2322, webauthnSk: true },
  stable: { service: "sshd-stable", host: "127.0.0.1", port: 2323, webauthnSk: false },
};

/** sshd users provisioned by e2e/sshd/entrypoint.sh. */
export const SSHD_USER = { fileKey: "filekey", passkey: "passkey" } as const;

/**
 * Which sshd images this run targets. `E2E_SSHD=modern|stable|both`; default
 * both. CI sets one per matrix leg. Scenarios that need webauthn-sk (passkey
 * signing, agent forwarding second hop, agent proxy) only run when `modern`
 * is included.
 */
export function sshdTargets(): SshdTarget[] {
  const raw = (process.env.E2E_SSHD ?? "both").trim().toLowerCase();
  if (raw === "modern" || raw === "stable") return [raw];
  if (raw === "both" || raw === "") return ["modern", "stable"];
  throw new Error(`E2E_SSHD must be modern|stable|both (got "${raw}")`);
}

export function modernEnabled(): boolean {
  return sshdTargets().includes("modern");
}
