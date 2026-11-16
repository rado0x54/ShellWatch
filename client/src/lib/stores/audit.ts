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
  // Host-key pinning (#241).
  endpointId: string | null;
  hostKeyFingerprint: string | null;
  hostKeyPriorFingerprint: string | null;
  hostKeyPinned: boolean | null;
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

/**
 * Display label for a signing-request outcome. For a sign prompt
 * (webauthn-sign, key-approve) the wire and stored value stay "denied", but
 * the button that produces it is "Skip" — it drops that one key and the next
 * accepted key may be offered (#308) — so the views say "skipped". Other rows
 * keep their outcome: a host-key-mismatch "denied" means the connection was
 * blocked, not that anyone skipped a key. An unauthenticated-endpoint row
 * (#311) reads "Refused: no authentication".
 */
export function signingOutcomeLabel(type: string, outcome: string): string {
  // A none-auth refusal (#311) is stored as "denied", but nothing was denied:
  // the endpoint let ShellWatch in without a key and was refused for it.
  if (type === "unauthenticated-endpoint" && outcome === "denied")
    return "Refused: no authentication";
  const isPrompt = type === "webauthn-sign" || type === "key-approve";
  return isPrompt && outcome === "denied" ? "skipped" : outcome;
}
