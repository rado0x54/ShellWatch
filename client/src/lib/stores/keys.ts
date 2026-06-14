// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { writable } from "svelte/store";
import { apiFetch } from "../api.js";

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

export const sshKeys = writable<SshKeyData[]>([]);

export async function fetchSshKeys(): Promise<void> {
  const res = await apiFetch("/api/keys");
  const data = await res.json();
  sshKeys.set(data.keys);
}
