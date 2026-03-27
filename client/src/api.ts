export interface Endpoint {
  id: string;
  label: string;
  host: string;
  port: number;
  username: string;
}

export interface TerminalSession {
  sessionId: string;
  endpointId: string;
  status: string;
  createdAt: string;
  source: string;
}

export async function fetchEndpoints(): Promise<Endpoint[]> {
  const res = await fetch("/api/endpoints");
  const data = await res.json();
  return data.endpoints;
}

export async function createSession(endpointId: string): Promise<TerminalSession> {
  const res = await fetch("/api/sessions", {
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

export async function fetchSessions(): Promise<TerminalSession[]> {
  const res = await fetch("/api/sessions");
  const data = await res.json();
  return data.sessions;
}

export async function closeSession(sessionId: string): Promise<void> {
  await fetch(`/api/sessions/${sessionId}`, { method: "DELETE" });
}
