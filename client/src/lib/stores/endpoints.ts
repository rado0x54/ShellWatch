// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { writable } from "svelte/store";

export type UserVerification = "required" | "preferred" | "discouraged";

export const USER_VERIFICATION_OPTIONS: readonly UserVerification[] = [
  "required",
  "preferred",
  "discouraged",
] as const;

export const ENDPOINT_DESCRIPTION_MAX_LENGTH = 1000;

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
}

export const endpoints = writable<Endpoint[]>([]);

export async function fetchEndpoints(): Promise<void> {
  const res = await fetch("/api/endpoints");
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
  const res = await fetch("/api/endpoints", {
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
  const res = await fetch(`/api/endpoints/${id}`, {
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
  const res = await fetch(`/api/endpoints/${id}`, { method: "DELETE" });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.error || "Failed to delete endpoint");
  }
  await fetchEndpoints();
}
