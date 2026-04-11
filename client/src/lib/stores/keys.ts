import { writable } from "svelte/store";

export interface SshKeyData {
  id: string;
  label: string;
  type: string;
  algorithm: string;
  fingerprint: string;
  revoked: boolean;
  available: boolean;
  authorizedKeysEntry: string | null;
  createdAt: string;
  lastUsedAt: string | null;
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
  const res = await fetch("/api/keys");
  const data = await res.json();
  sshKeys.set(data.keys);
}

export async function fetchApiKeys(): Promise<void> {
  try {
    const res = await fetch("/api/keys/api");
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
  const res = await fetch("/api/keys/api", {
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
  const res = await fetch(`/api/keys/api/${id}`, { method: "DELETE" });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(err.error || "Failed to revoke API key");
  }
  await fetchApiKeys();
}
