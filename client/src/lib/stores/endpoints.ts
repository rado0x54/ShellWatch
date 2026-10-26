// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { apiFetch } from "../api.js";
import { writable } from "svelte/store";

export type UserVerification = "required" | "preferred" | "discouraged";

export const USER_VERIFICATION_OPTIONS: readonly UserVerification[] = [
  "required",
  "preferred",
  "discouraged",
] as const;

export const ENDPOINT_DESCRIPTION_MAX_LENGTH = 1000;

/** The endpoint's pinned SSH host key (#241); null when nothing is pinned. */
export interface EndpointHostKey {
  /** SSH key type (e.g. ssh-ed25519); empty for fingerprint-only pins. */
  type: string;
  /** SHA256:... fingerprint. */
  fingerprint: string;
  pinnedAt: string;
  /** Credential id of the approving passkey, or "manual" / "config" / "demo". */
  pinnedBy: string;
}

export interface Endpoint {
  id: string;
  label: string;
  host: string;
  port: number;
  username: string;
  userVerification: UserVerification;
  agentForward: boolean;
  description: string | null;
  /** True if this is a virtual demo endpoint (read-only, from operator config). */
  isDemo: boolean;
  hostKey: EndpointHostKey | null;
}

export const endpoints = writable<Endpoint[]>([]);

export async function fetchEndpoints(): Promise<void> {
  const res = await apiFetch("/api/endpoints");
  const data = await res.json();
  endpoints.set(data.endpoints);
}

export async function createEndpoint(body: {
  label: string;
  host: string;
  port: number;
  username: string;
  userVerification?: UserVerification;
  agentForward?: boolean;
  description?: string | null;
}): Promise<void> {
  const res = await apiFetch("/api/endpoints", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.error || "Failed to create endpoint");
  }
  await fetchEndpoints();
}

export async function updateEndpoint(
  id: string,
  body: Partial<Omit<Endpoint, "id">>,
): Promise<void> {
  const res = await apiFetch(`/api/endpoints/${id}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.error || "Failed to update endpoint");
  }
  await fetchEndpoints();
}

export async function deleteEndpoint(id: string): Promise<void> {
  const res = await apiFetch(`/api/endpoints/${id}`, { method: "DELETE" });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.error || "Failed to delete endpoint");
  }
  await fetchEndpoints();
}

/**
 * Manually pin an endpoint's SSH host key (#241). Step-up gated: the caller
 * performs the `pin_host_key` step-up first and passes the token. Exactly one
 * of publicKey (OpenSSH line, preferred) or fingerprint ("SHA256:...").
 */
export async function pinEndpointHostKey(
  id: string,
  key: { publicKey?: string; fingerprint?: string },
  stepUpToken: string,
): Promise<void> {
  const res = await apiFetch(`/api/endpoints/${id}/host-key`, {
    method: "PUT",
    headers: { "Content-Type": "application/json", "X-Shellwatch-Stepup-Token": stepUpToken },
    body: JSON.stringify(key),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || "Failed to pin host key");
  }
  await fetchEndpoints();
}

/**
 * Forget an endpoint's pinned SSH host key (#241). Step-up gated
 * (`reset_host_key`); the recovery path after a host-key mismatch.
 */
export async function forgetEndpointHostKey(id: string, stepUpToken: string): Promise<void> {
  const res = await apiFetch(`/api/endpoints/${id}/host-key`, {
    method: "DELETE",
    headers: { "X-Shellwatch-Stepup-Token": stepUpToken },
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || "Failed to forget host key");
  }
  await fetchEndpoints();
}
