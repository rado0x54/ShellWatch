// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { apiFetch } from "../api.js";
export interface TerminalSession {
  sessionId: string;
  endpointId: string;
  status: string;
  createdAt: string;
  source: string;
}

export async function createSession(endpointId: string): Promise<TerminalSession> {
  const res = await apiFetch("/api/sessions", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ endpointId }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(err.error || "Failed to create session");
  }
  return res.json();
}

export async function closeSession(sessionId: string): Promise<void> {
  const res = await apiFetch(`/api/sessions/${sessionId}`, { method: "DELETE" });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(err.error || "Failed to close session");
  }
}
