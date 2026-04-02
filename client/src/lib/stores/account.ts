import { get, writable } from "svelte/store";
import { basePath } from "./connection.js";

export interface AccountData {
  id: string;
  name: string;
  type: "human" | "agent";
  isAdmin: boolean;
}

export const account = writable<AccountData | null>(null);

export async function fetchAccount(): Promise<void> {
  const base = get(basePath);
  try {
    const res = await fetch(`${base}/api/auth/me`);
    if (!res.ok) {
      account.set(null);
      return;
    }
    const data = await res.json();
    account.set(data);
  } catch {
    account.set(null);
  }
}
