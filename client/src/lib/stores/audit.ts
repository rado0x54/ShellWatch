export interface AuditSessionRow {
  sessionId: string;
  accountId: string;
  endpointId: string;
  source: string;
  status: string;
  createdAt: string;
  closedAt: string | null;
  durationMs: number | null;
  sourceIp: string | null;
  mcpReason: string | null;
  mcpClientName: string | null;
  mcpClientVersion: string | null;
  apiKeyLabel: string | null;
  apiKeyPrefix: string | null;
  clientHostname: string | null;
  clientOs: string | null;
  clientVersion: string | null;
  closeReason: string | null;
}

export interface AuditPage {
  rows: AuditSessionRow[];
  nextCursor: string | null;
}

export interface AuditFilters {
  endpointId?: string;
}

export async function fetchAuditPage(
  filters: AuditFilters,
  cursor?: string,
  limit = 50,
): Promise<AuditPage> {
  const params = new URLSearchParams();
  if (filters.endpointId) params.set("endpointId", filters.endpointId);
  if (cursor) params.set("cursor", cursor);
  params.set("limit", String(limit));
  const res = await fetch(`/api/audit/sessions?${params}`);
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(err.error || "Failed to fetch audit log");
  }
  return res.json();
}
