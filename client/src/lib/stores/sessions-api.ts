import { get } from "svelte/store";
import { basePath } from "./connection.js";

export interface TerminalSession {
  sessionId: string;
  endpointId: string;
  status: string;
  createdAt: string;
  source: string;
}

export async function createSession(endpointId: string): Promise<TerminalSession> {
  const base = get(basePath);
  const res = await fetch(`${base}/api/sessions`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ endpointId }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ message: res.statusText }));
    throw new Error(err.message || "Failed to create session");
  }
  return res.json();
}

export async function closeSession(sessionId: string): Promise<void> {
  const base = get(basePath);
  await fetch(`${base}/api/sessions/${sessionId}`, { method: "DELETE" });
}
