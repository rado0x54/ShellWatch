<script lang="ts">
  import { goto } from "$app/navigation";
  import { resolve } from "$app/paths";
  import { page } from "$app/state";
  import { onMount } from "svelte";
  import type { PageProps } from "./$types";
  import TerminalSnapshot from "$lib/components/TerminalSnapshot.svelte";
  import { clearAction, toastError, toastInfo } from "$lib/stores/toasts.js";
  import {
    approveAction,
    performSignCeremony,
    resolveAction,
    sourceLabels,
    triggerKindLabels,
  } from "$lib/utils/webauthn-sign.js";

  const actionId = $derived((page.params as PageProps["params"]).id);

  type EndpointAuthTrigger =
    | { kind: "ui"; sourceIp: string }
    | {
        kind: "mcp";
        reason: string;
        sourceIp: string;
        mcpClientName?: string;
        mcpClientVersion?: string;
      };

  type SignContext =
    | {
        source: "agent-proxy";
        sourceIp: string;
        apiKeyLabel: string;
        apiKeyPrefix: string;
        clientHostname?: string;
        clientOs?: string;
        clientVersion?: string;
      }
    | {
        source: "endpoint-auth";
        endpointLabel: string;
        endpointAddress: string;
        trigger: EndpointAuthTrigger;
      }
    | {
        source: "agent-forwarding";
        endpointLabel: string;
        endpointAddress: string;
        sessionId: string;
      };

  interface ActionData {
    id: string;
    type: "webauthn-sign" | "key-approve";
    accountId: string;
    status: string;
    createdAt: number;
    expiresAt: number;
    context: SignContext;
    redirectTo?: string;
    // webauthn-sign fields
    credentialId?: string;
    challenge?: string;
    rpId?: string;
    passkeyLabel?: string;
    userVerification?: "required" | "preferred" | "discouraged";
    // key-approve fields
    keyLabel?: string;
    keyFingerprint?: string;
  }

  let action = $state<ActionData | null>(null);
  let loading = $state(true);
  let processing = $state(false);
  let error = $state<string | null>(null);
  let resultStatus = $state<string | null>(null);
  let parentSessionTail = $state<string | null>(null);

  const isKeyApprove = $derived(action?.type === "key-approve");

  onMount(async () => {
    try {
      const res = await fetch(`/api/actions/${actionId}`);
      if (res.status === 401) {
        await goto(resolve(`/login?redirect=/sign/${actionId}`));
        return;
      }
      if (!res.ok) {
        error = "Action not found";
        return;
      }
      action = await res.json();

      // For agent-forwarding requests, surface what's happening in the parent
      // session so the approver can see the command that triggered the forward
      // (e.g. `git push`, nested `ssh`). Best-effort — if the fetch fails we
      // just hide the preview rather than blocking approval.
      if (action && action.context.source === "agent-forwarding") {
        try {
          const tailRes = await fetch(`/api/sessions/${action.context.sessionId}/tail?limit=2000`);
          if (tailRes.ok) {
            const body = (await tailRes.json()) as { data?: string };
            parentSessionTail = body.data ?? "";
          }
        } catch {
          // ignore — preview is non-essential
        }
      }
    } catch {
      error = "Failed to load action";
    } finally {
      loading = false;
    }
  });

  async function handleAction() {
    if (!action) return;
    processing = true;
    error = null;

    try {
      let response;
      if (action.type === "key-approve") {
        response = await approveAction(actionId);
      } else {
        const result = await performSignCeremony({
          credentialId: action.credentialId as string,
          challenge: action.challenge as string,
          rpId: action.rpId as string,
          userVerification: action.userVerification,
        });
        response = await resolveAction(actionId, result);
      }
      resultStatus = "completed";
      clearAction(actionId);
      toastInfo(isKeyApprove ? "Key usage approved" : "Signature completed successfully");
      if (response.redirectTo && isSafeRedirect(response.redirectTo)) {
        // Server-computed path (e.g. /session/:id). Use window.location
        // since typed routes can't validate a runtime string.
        window.location.href = response.redirectTo;
      }
    } catch (err) {
      error = (err as Error).message;
      toastError(`${isKeyApprove ? "Approval" : "Signing"} failed: ${error}`);
    } finally {
      processing = false;
    }
  }

  function isSafeRedirect(path: string): boolean {
    return path.startsWith("/") && !path.startsWith("//");
  }

  async function handleDeny() {
    if (!action) return;
    try {
      const res = await fetch(`/api/actions/${actionId}/deny`, { method: "POST" });
      if (res.ok) {
        resultStatus = "denied";
        clearAction(actionId);
      } else {
        const body = await res.json().catch(() => ({ error: "Unknown error" }));
        error = body.error ?? "Failed to deny";
      }
    } catch (err) {
      error = (err as Error).message;
    }
  }

  function viewSession(sessionId: string) {
    goto(resolve(`/session/${sessionId}`));
  }

  const ctx = $derived(action?.context);
  const displayStatus = $derived(resultStatus ?? action?.status);

  /**
   * Client-reported fields grouped in the "self-reported" box.
   *
   * These are advertised by the connecting client (Go agent, MCP client) and
   * NOT verified by the server — an attacker with a compromised API key can
   * set them to anything. They're shown for context only; approvers must
   * rely on the server-verified fields (source IP, API key label, endpoint)
   * for their trust decision.
   */
  interface ReportedItem {
    label: string;
    value: string;
    mono?: boolean;
  }
  const reportedItems = $derived.by((): ReportedItem[] => {
    if (!ctx) return [];
    const items: ReportedItem[] = [];
    if (ctx.source === "agent-proxy") {
      if (ctx.clientHostname) items.push({ label: "Hostname", value: ctx.clientHostname });
      if (ctx.clientOs) items.push({ label: "OS", value: ctx.clientOs, mono: true });
      if (ctx.clientVersion) items.push({ label: "Version", value: ctx.clientVersion, mono: true });
    } else if (ctx.source === "endpoint-auth" && ctx.trigger.kind === "mcp") {
      // Reason is asserted by the agent — same trust boundary as clientInfo,
      // so it belongs in the self-reported box rather than the verified fields.
      items.push({ label: "Reason", value: ctx.trigger.reason });
      if (ctx.trigger.mcpClientName)
        items.push({ label: "MCP Client", value: ctx.trigger.mcpClientName });
      if (ctx.trigger.mcpClientVersion)
        items.push({
          label: "Version",
          value: ctx.trigger.mcpClientVersion,
          mono: true,
        });
    }
    return items;
  });
  const isTerminal = $derived(displayStatus !== "pending");
</script>

<div class="sign-page">
  {#if loading}
    <div class="sign-card">
      <p class="sign-loading">Loading...</p>
    </div>
  {:else if !action}
    <div class="sign-card">
      <h2>Action Not Found</h2>
      <p class="sign-status-msg">{error ?? "This action does not exist or has expired."}</p>
      <div class="sign-actions">
        <button class="btn btn-primary" onclick={() => goto(resolve("/"))}>Go Home</button>
      </div>
    </div>
  {:else if isTerminal}
    <div class="sign-card">
      <h2>
        {#if displayStatus === "completed"}
          {isKeyApprove ? "Key Usage Approved" : "Signature Complete"}
        {:else if displayStatus === "denied"}
          Request Denied
        {:else if displayStatus === "expired"}
          Request Expired
        {:else}
          Request {displayStatus}
        {/if}
      </h2>
      <p class="sign-status-msg">
        {#if displayStatus === "completed"}
          {isKeyApprove
            ? "The SSH key usage was approved successfully."
            : "The passkey signature was completed successfully."}
        {:else if displayStatus === "denied"}
          This request was denied.
        {:else if displayStatus === "expired"}
          This request expired before it could be completed.
        {:else}
          This request is no longer pending.
        {/if}
      </p>
      <div class="sign-actions">
        <button class="btn btn-primary" onclick={() => goto(resolve("/"))}>Go Home</button>
      </div>
    </div>
  {:else}
    <div class="sign-card">
      <h2>{isKeyApprove ? "SSH Key Approval Request" : "Passkey Signature Request"}</h2>

      <div class="sign-fields">
        <div class="sign-field">
          <span class="sign-label">Source</span>
          <span class="sign-value">{sourceLabels[ctx!.source] ?? ctx!.source}</span>
        </div>

        {#if ctx && (ctx.source === "endpoint-auth" || ctx.source === "agent-forwarding")}
          <div class="sign-field">
            <span class="sign-label">Endpoint</span>
            <span class="sign-value">
              {ctx.endpointLabel}
              <span class="sign-muted">({ctx.endpointAddress})</span>
            </span>
          </div>
        {/if}

        {#if ctx && ctx.source === "endpoint-auth"}
          <div class="sign-field">
            <span class="sign-label">Triggered by</span>
            <span class="sign-value">
              {triggerKindLabels[ctx.trigger.kind] ?? ctx.trigger.kind}
              {#if ctx.trigger.sourceIp}
                <span class="sign-muted sign-mono">({ctx.trigger.sourceIp})</span>
              {/if}
            </span>
          </div>
        {/if}

        {#if ctx && ctx.source === "agent-proxy"}
          <div class="sign-field">
            <span class="sign-label">Source IP</span>
            <span class="sign-value sign-mono">{ctx.sourceIp}</span>
          </div>
          <div class="sign-field">
            <span class="sign-label">API Key</span>
            <span class="sign-value">
              {ctx.apiKeyLabel}
              <span class="sign-muted sign-mono">({ctx.apiKeyPrefix}…)</span>
            </span>
          </div>
        {/if}

        {#if isKeyApprove && action.keyLabel}
          <div class="sign-field">
            <span class="sign-label">SSH Key</span>
            <span class="sign-value">{action.keyLabel}</span>
          </div>
          {#if action.keyFingerprint}
            <div class="sign-field">
              <span class="sign-label">Fingerprint</span>
              <span class="sign-value sign-mono">{action.keyFingerprint}</span>
            </div>
          {/if}
        {/if}

        {#if !isKeyApprove && action.passkeyLabel}
          <div class="sign-field">
            <span class="sign-label">Passkey</span>
            <span class="sign-value">{action.passkeyLabel}</span>
          </div>
        {/if}

        {#if ctx && ctx.source === "agent-forwarding" && ctx.sessionId}
          <div class="sign-field">
            <span class="sign-label">Session</span>
            <button class="sign-link" onclick={() => viewSession(ctx.sessionId)}>
              View Session
            </button>
          </div>
        {/if}
      </div>

      {#if ctx && ctx.source === "agent-forwarding" && parentSessionTail}
        <details class="sign-preview" open>
          <summary class="sign-preview-header">
            Parent session output
            <span class="sign-preview-note">— tail of terminal at time of request</span>
          </summary>
          <div class="sign-preview-body">
            <TerminalSnapshot data={parentSessionTail} />
          </div>
        </details>
      {/if}

      {#if reportedItems.length > 0}
        <div class="sign-reported" role="group" aria-labelledby="reported-heading">
          <div class="sign-reported-header" id="reported-heading">
            Self-reported by client
            <span class="sign-reported-note">— not verified, treat as context only</span>
          </div>
          <div class="sign-fields">
            {#each reportedItems as item (item.label)}
              <div class="sign-field">
                <span class="sign-label">{item.label}</span>
                <span class="sign-value" class:sign-mono={item.mono}>{item.value}</span>
              </div>
            {/each}
          </div>
        </div>
      {/if}

      {#if error}
        <div class="sign-error">{error}</div>
      {/if}

      <div class="sign-actions">
        <button class="btn btn-secondary" onclick={handleDeny} disabled={processing}>Deny</button>
        <button class="btn btn-primary" onclick={handleAction} disabled={processing}>
          {#if processing}
            {isKeyApprove ? "Approving..." : "Signing..."}
          {:else}
            {isKeyApprove ? "Approve" : "Sign"}
          {/if}
        </button>
      </div>
    </div>
  {/if}
</div>

<style>
  .sign-page {
    display: flex;
    align-items: center;
    justify-content: center;
    min-height: 100%;
    padding: 2rem;
  }

  .sign-card {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 2rem;
    min-width: 360px;
    max-width: 500px;
    width: 100%;
  }

  .sign-card h2 {
    font-size: 1.1rem;
    font-weight: 600;
    margin-bottom: 1.25rem;
  }

  .sign-loading {
    color: var(--text-muted);
    text-align: center;
    padding: 2rem 0;
  }

  .sign-status-msg {
    color: var(--text-muted);
    font-size: 0.9rem;
    margin-bottom: 1.5rem;
  }

  .sign-fields {
    display: flex;
    flex-direction: column;
    gap: 0.6rem;
    margin-bottom: 1.5rem;
  }

  .sign-preview {
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 0.75rem 1rem;
    margin-bottom: 1.5rem;
    background: var(--bg-primary);
  }

  .sign-preview-header {
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    color: var(--text-muted);
    cursor: pointer;
    user-select: none;
    list-style: none;
    display: flex;
    align-items: baseline;
    gap: 0.4rem;
  }

  /* Safari <details> shows a native disclosure triangle even with list-style:none;
     suppress it so our custom ::before arrow isn't doubled up. */
  .sign-preview-header::-webkit-details-marker {
    display: none;
  }

  .sign-preview-header::before {
    content: "▸";
    display: inline-block;
    font-size: 0.7rem;
    transition: transform 0.15s ease;
  }

  .sign-preview[open] .sign-preview-header::before {
    transform: rotate(90deg);
  }

  .sign-preview-note {
    font-weight: 400;
    text-transform: none;
    letter-spacing: normal;
    font-style: italic;
  }

  .sign-preview-body {
    margin-top: 0.6rem;
    height: 14rem;
    overflow: hidden;
    border-radius: 4px;
  }

  .sign-reported {
    border: 1px dashed var(--border);
    border-radius: 8px;
    padding: 0.75rem 1rem;
    margin-bottom: 1.5rem;
    background: rgba(255, 255, 255, 0.015);
  }

  .sign-reported-header {
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    color: var(--text-muted);
    margin-bottom: 0.6rem;
  }

  .sign-reported-note {
    font-weight: 400;
    text-transform: none;
    letter-spacing: normal;
    font-style: italic;
  }

  .sign-reported .sign-fields {
    margin-bottom: 0;
  }

  .sign-field {
    display: flex;
    gap: 0.75rem;
    align-items: baseline;
  }

  .sign-label {
    font-size: 0.75rem;
    color: var(--text-muted);
    min-width: 5.5rem;
    flex-shrink: 0;
  }

  .sign-value {
    font-size: 0.9rem;
    overflow-wrap: anywhere;
    min-width: 0;
  }

  .sign-muted {
    color: var(--text-muted);
    font-size: 0.8rem;
  }

  .sign-mono {
    font-family: monospace;
    font-size: 0.85rem;
  }

  .sign-link {
    background: none;
    border: none;
    color: var(--accent);
    cursor: pointer;
    font-size: 0.85rem;
    text-decoration: underline;
    padding: 0;
  }

  .sign-link:hover {
    color: var(--accent-hover);
  }

  .sign-error {
    background: rgba(248, 113, 113, 0.1);
    border: 1px solid rgba(248, 113, 113, 0.3);
    border-radius: 6px;
    padding: 0.6rem 0.75rem;
    font-size: 0.8rem;
    color: var(--red);
    margin-bottom: 1rem;
  }

  .sign-actions {
    display: flex;
    justify-content: flex-end;
    gap: 0.5rem;
  }
</style>
