// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { apiFetch } from "../api.js";
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
  /** Inclusive lower bound on created_at (ISO-8601 string). */
  from?: string;
  /** Inclusive upper bound on created_at (ISO-8601 string). */
  to?: string;
}

export async function fetchAuditPage(
  filters: AuditFilters,
  cursor?: string,
  limit = 50,
): Promise<AuditPage> {
  const params = new URLSearchParams();
  if (filters.endpointId) params.set("endpointId", filters.endpointId);
  if (filters.from) params.set("from", filters.from);
  if (filters.to) params.set("to", filters.to);
  if (cursor) params.set("cursor", cursor);
  params.set("limit", String(limit));
  const res = await apiFetch(`/api/audit/sessions?${params}`);
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(err.error || "Failed to fetch audit log");
  }
  return res.json();
}

// --- Signing requests audit (#186) ---

export interface SigningRequestRow {
  id: string;
  accountId: string;
  type: string;
  source: string;
  createdAt: string;
  resolvedAt: string | null;
  outcome: string | null;
  latencyMs: number | null;
  sourceIp: string | null;
  endpointLabel: string | null;
  endpointAddress: string | null;
  sessionId: string | null;
  mcpReason: string | null;
  mcpClientName: string | null;
  mcpClientVersion: string | null;
  clientHostname: string | null;
  clientOs: string | null;
  clientVersion: string | null;
  credentialId: string | null;
  passkeyLabel: string | null;
  userVerification: string | null;
  keyLabel: string | null;
  keyFingerprint: string | null;
  cancelReason: string | null;
}

export interface SigningsPage {
  rows: SigningRequestRow[];
  nextCursor: string | null;
}

export interface SigningsFilters {
  source?: string;
  outcome?: string;
  from?: string;
  to?: string;
}

export async function fetchSigningsPage(
  filters: SigningsFilters,
  cursor?: string,
  limit = 50,
): Promise<SigningsPage> {
  const params = new URLSearchParams();
  if (filters.source) params.set("source", filters.source);
  if (filters.outcome) params.set("outcome", filters.outcome);
  if (filters.from) params.set("from", filters.from);
  if (filters.to) params.set("to", filters.to);
  if (cursor) params.set("cursor", cursor);
  params.set("limit", String(limit));
  const res = await apiFetch(`/api/audit/signings?${params}`);
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(err.error || "Failed to fetch signing audit log");
  }
  return res.json();
}
