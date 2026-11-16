// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { apiFetch } from "../api.js";

/**
 * Loading state of the /sign/:id page (#308 §4). SvelteKit reuses the page
 * component when navigating /sign/A -> /sign/B (e.g. "Details" on a new
 * toast), so loading in onMount left A's end state on screen under B's URL.
 * The page instead calls `load(id)` whenever the id changes: state is reset
 * first, and a response for an id the page has since left is dropped.
 */
export interface SignPageState<A> {
  actionId: string;
  action: A | null;
  loading: boolean;
  error: string | null;
  /** End state reached on this page ("completed", "denied", "expired"). */
  resultStatus: string | null;
  parentSessionTail: string | null;
  /** The bearer token is gone: the page must start a login. */
  needsLogin: boolean;
}

export type SignActionLoad<A> =
  | { kind: "ok"; action: A; parentSessionTail: string | null }
  | { kind: "login" }
  | { kind: "not-found" }
  | { kind: "error" };

export function freshSignPageState<A>(actionId: string): SignPageState<A> {
  return {
    actionId,
    action: null,
    loading: true,
    error: null,
    resultStatus: null,
    parentSessionTail: null,
    needsLogin: false,
  };
}

export function applySignActionLoad<A>(actionId: string, r: SignActionLoad<A>): SignPageState<A> {
  const s = freshSignPageState<A>(actionId);
  s.loading = false;
  switch (r.kind) {
    case "ok":
      s.action = r.action;
      s.parentSessionTail = r.parentSessionTail;
      break;
    case "login":
      s.needsLogin = true;
      break;
    case "not-found":
      s.error = "Action not found";
      break;
    case "error":
      s.error = "Failed to load action";
      break;
  }
  return s;
}

export interface SignPageController {
  /** (Re)load for `actionId`; resets the state synchronously. */
  load(actionId: string): void;
  /**
   * Token for the current visit: every load and every leave starts a new one.
   * Handlers capture it when they start and apply their result only while it
   * is still current — comparing ids is not enough (A -> B -> A is a new
   * visit with the same id).
   */
  visit(): number;
  /** The page is gone (destroyed, or about to load another id). */
  leave(): void;
}

export function createSignPageController<A>(
  fetchAction: (actionId: string) => Promise<SignActionLoad<A>>,
  onState: (s: SignPageState<A>) => void,
): SignPageController {
  let seq = 0;
  return {
    load(actionId) {
      const mine = ++seq;
      onState(freshSignPageState<A>(actionId));
      fetchAction(actionId)
        .catch((): SignActionLoad<A> => ({ kind: "error" }))
        .then((r) => {
          if (mine !== seq) return; // navigated to another id meanwhile
          onState(applySignActionLoad(actionId, r));
        });
    },
    visit: () => seq,
    leave() {
      seq++; // drop any in-flight load and invalidate running handlers
    },
  };
}

/**
 * Fetch an action for the sign page. For agent-forwarding requests the parent
 * session's tail is fetched too (best-effort: a failure hides the preview).
 */
export async function fetchSignAction<A extends { context: { source: string } }>(
  actionId: string,
): Promise<SignActionLoad<A>> {
  const res = await apiFetch(`/api/actions/${actionId}`);
  if (res.status === 401) return { kind: "login" };
  if (!res.ok) return { kind: "not-found" };
  const action = (await res.json()) as A;
  let parentSessionTail: string | null = null;
  const ctx = action.context as { source: string; sessionId?: string };
  if (ctx.source === "agent-forwarding" && ctx.sessionId) {
    try {
      const tailRes = await apiFetch(`/api/sessions/${ctx.sessionId}/tail?limit=2000`);
      if (tailRes.ok) {
        const body = (await tailRes.json()) as { data?: string };
        parentSessionTail = body.data ?? "";
      }
    } catch {
      // ignore — preview is non-essential
    }
  }
  return { kind: "ok", action, parentSessionTail };
}
