import { get, writable } from "svelte/store";
import { basePath } from "./connection.js";

export interface Endpoint {
  id: string;
  label: string;
  host: string;
  port: number;
  username: string;
  keyId?: string | null;
}

export const endpoints = writable<Endpoint[]>([]);

export async function fetchEndpoints(): Promise<void> {
  const base = get(basePath);
  const res = await fetch(`${base}/api/endpoints`);
  const data = await res.json();
  endpoints.set(data.endpoints);
}

export async function createEndpoint(body: {
  label: string;
  host: string;
  port: number;
  username: string;
  keyId?: string;
}): Promise<void> {
  const base = get(basePath);
  const res = await fetch(`${base}/api/endpoints`, {
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
  const base = get(basePath);
  const res = await fetch(`${base}/api/endpoints/${id}`, {
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
  const base = get(basePath);
  const res = await fetch(`${base}/api/endpoints/${id}`, { method: "DELETE" });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.error || "Failed to delete endpoint");
  }
  await fetchEndpoints();
}
