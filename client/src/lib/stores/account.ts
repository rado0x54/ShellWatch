import { writable } from "svelte/store";

export interface AccountData {
  id: string;
  name: string;
  isAdmin: boolean;
  agentForward: boolean;
}

export const account = writable<AccountData | null>(null);

export async function fetchAccount(): Promise<void> {
  try {
    const res = await fetch("/api/auth/me");
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

export async function updateAccountName(name: string): Promise<void> {
  const res = await fetch("/api/auth/me", {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name }),
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.error || "Failed to update account");
  }
  await fetchAccount();
}

export async function updateAgentForward(agentForward: boolean): Promise<void> {
  const res = await fetch("/api/auth/me", {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ agentForward }),
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.error || "Failed to update agent forwarding");
  }
  await fetchAccount();
}
