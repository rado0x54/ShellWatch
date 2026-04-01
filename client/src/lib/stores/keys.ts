import { get, writable } from "svelte/store";
import { basePath } from "./connection.js";

export interface SshKeyData {
  id: string;
  label: string;
  type: string;
  fingerprint: string;
  available: boolean;
  authorizedKeysEntry: string | null;
}

export interface ApiKeyData {
  id: string;
  label: string;
  keyPrefix: string;
  scopes: string[];
  enabled: boolean;
  createdAt: string;
}

export const sshKeys = writable<SshKeyData[]>([]);
export const apiKeys = writable<ApiKeyData[]>([]);

export async function fetchSshKeys(): Promise<void> {
  const base = get(basePath);
  const res = await fetch(`${base}/api/keys`);
  const data = await res.json();
  sshKeys.set(data.keys);
}

export async function fetchApiKeys(): Promise<void> {
  const base = get(basePath);
  try {
    const res = await fetch(`${base}/api/keys/api`);
    if (!res.ok) {
      apiKeys.set([]);
      return;
    }
    const data = await res.json();
    apiKeys.set(data.keys);
  } catch {
    apiKeys.set([]);
  }
}

export async function generateApiKey(label: string): Promise<string> {
  const base = get(basePath);
  const res = await fetch(`${base}/api/keys/api`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ label }),
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.error || "Failed to generate key");
  }
  const { key } = await res.json();
  await fetchApiKeys();
  return key;
}

export async function revokeApiKey(id: string): Promise<void> {
  const base = get(basePath);
  await fetch(`${base}/api/keys/api/${id}`, { method: "DELETE" });
  await fetchApiKeys();
}
