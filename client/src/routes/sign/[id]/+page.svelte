<!-- SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0 -->
<script lang="ts">
  import { beginLogin } from "$lib/oauth.js";
  import { goto } from "$app/navigation";
  import { resolve } from "$app/paths";
  import { page } from "$app/state";
  import type { PageProps } from "./$types";
  import TerminalSnapshot from "$lib/components/TerminalSnapshot.svelte";
  import { clearAction, toastError, toastInfo } from "$lib/stores/toasts.js";
  import { errorMessage } from "$lib/utils/error-message.js";
  import {
    createSignPageController,
    fetchSignAction,
    freshSignPageState,
    type SignPageState,
  } from "$lib/utils/sign-page.js";
  import {
    approveAction,
    sessionIdFromRedirect,
    signOrAutoSkip,
    skipAction,
    skipResultMessage,
    SkipFailedError,
    sourceLabels,
    triggerKindLabels,
    type ResolveResponse,
    type SkipResult,
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
        clientHostname?: string;
        clientOs?: string;
        clientVersion?: string;
      }
    | {
        source: "endpoint-auth";
        endpointLabel: string;
        endpointAddress: string;
        trigger: EndpointAuthTrigger;
        // Host-key pinning (#241): "new" means approving pins the key.
        hostKey?: { type: string; fingerprint: string; status: "new" | "known" };
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

  let st = $state<SignPageState<ActionData>>(freshSignPageState(""));
  let processing = $state(false);

  // Load whenever the id changes, not just on mount (#308 §4): navigating
  // /sign/A -> /sign/B reuses this component, and onMount would leave A's
  // state under B's URL. The controller resets first and drops stale loads.
  const controller = createSignPageController<ActionData>(fetchSignAction, (next) => {
    st = next;
    processing = false;
    if (next.needsLogin) void beginLogin(`/sign/${next.actionId}`);
  });
  $effect(() => {
    controller.load(actionId);
    // Leaving the page (or switching ids) invalidates in-flight handlers, so
    // a late response never navigates a user who has moved on.
    return () => controller.leave();
  });

  const action = $derived(st.action);
  const isKeyApprove = $derived(action?.type === "key-approve");

  /** Still showing the request `id` (the user may have navigated meanwhile). */
  function stillOn(id: string): boolean {
    return controller.current() === id;
  }

  // After a skip the page stays put and shows the end state; the next key's
  // request, if any, arrives as a normal toast. An automatic skip also gets an
  // info toast saying why — the user didn't press anything.
  function afterSkip(id: string, skip: SkipResult, mode: "manual" | "auto", label?: string) {
    clearAction(id);
    if (mode === "auto") toastInfo(skipResultMessage(skip, mode, label));
    if (stillOn(id)) st.resultStatus = skip.kind === "skipped" ? "denied" : skip.status;
  }

  async function handleAction() {
    const a = st.action;
    if (!a) return;
    const id = st.actionId;
    processing = true;
    st.error = null;

    try {
      let response: ResolveResponse;
      if (a.type === "key-approve") {
        response = await approveAction(id);
      } else {
        const outcome = await signOrAutoSkip(id, {
          credentialId: a.credentialId as string,
          challenge: a.challenge as string,
          rpId: a.rpId as string,
          userVerification: a.userVerification,
        });
        if (outcome.kind === "auto-skipped") {
          // Cancelled ceremony / passkey not on this device: skipped.
          afterSkip(id, outcome.skip, "auto", a.passkeyLabel);
          return;
        }
        response = outcome.response;
      }
      clearAction(id);
      toastInfo(
        a.type === "key-approve" ? "Key usage approved" : "Signature completed successfully",
      );
      if (!stillOn(id)) return;
      st.resultStatus = "completed";
      // Land on the session the approval was for — same as approving from
      // the toast (#273). In-app navigation, no reload: the socket and any
      // follow-up prompt (a passkey after a key approval) survive.
      const sessionId = sessionIdFromRedirect(response.redirectTo);
      if (sessionId) await goto(resolve("/session/[id]", { id: sessionId }));
    } catch (err) {
      // A failed resolve, a server error or a failed automatic skip: nothing
      // was skipped, the prompt stays.
      const msg =
        err instanceof SkipFailedError
          ? err.message
          : `${a.type === "key-approve" ? "Approval" : "Signing"} failed: ${errorMessage(err)}`;
      toastError(msg);
      if (stillOn(id)) st.error = errorMessage(err);
    } finally {
      if (stillOn(id)) processing = false;
    }
  }

  async function handleSkip() {
    const a = st.action;
    if (!a) return;
    const id = st.actionId;
    processing = true;
    st.error = null;
    try {
      const skip = await skipAction(id);
      afterSkip(id, skip, "manual");
    } catch (err) {
      // Nothing was skipped: stay on the page and show why.
      toastError(errorMessage(err));
      if (stillOn(id)) st.error = errorMessage(err);
    } finally {
      if (stillOn(id)) processing = false;
    }
  }

  function viewSession(sessionId: string) {
    goto(resolve(`/session/${sessionId}`));
  }

  const ctx = $derived(action?.context);
  const displayStatus = $derived(st.resultStatus ?? action?.status);
  const loading = $derived(st.loading);
  const error = $derived(st.error);
  const parentSessionTail = $derived(st.parentSessionTail);

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
        <button type="button" class="btn btn-primary" onclick={() => goto(resolve("/"))}
          >Go Home</button
        >
      </div>
    </div>
  {:else if isTerminal}
    <div class="sign-card">
      <h2>
        {#if displayStatus === "completed"}
          {isKeyApprove ? "Key Usage Approved" : "Signature Complete"}
        {:else if displayStatus === "denied"}
          Key Skipped
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
          This key was skipped.
        {:else if displayStatus === "expired"}
          This request expired before it could be completed.
        {:else}
          This request is no longer pending.
        {/if}
      </p>
      <div class="sign-actions">
        <button type="button" class="btn btn-primary" onclick={() => goto(resolve("/"))}
          >Go Home</button
        >
      </div>
    </div>
  {:else}
    <div class="sign-card">
      <h2>{isKeyApprove ? "SSH Key Approval Request" : "Passkey Signature Request"}</h2>

      {#if ctx && ctx.source === "endpoint-auth" && ctx.hostKey?.status === "new"}
        <div class="sign-hostkey-banner" role="alert">
          <div class="sign-hostkey-title">First connection to this host</div>
          <p>
            No SSH host key is pinned for <strong>{ctx.endpointLabel}</strong>
            <span class="sign-muted">({ctx.endpointAddress})</span> yet. Approving this request will
            <strong>pin</strong> the key the server presented — verify the fingerprint against the host
            before approving:
          </p>
          <div class="sign-field">
            <span class="sign-label">Key type</span>
            <span class="sign-value sign-mono">{ctx.hostKey.type}</span>
          </div>
          <div class="sign-field">
            <span class="sign-label">Fingerprint</span>
            <span class="sign-value sign-mono">{ctx.hostKey.fingerprint}</span>
          </div>
        </div>
      {/if}

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

        {#if ctx && ctx.source === "endpoint-auth" && ctx.hostKey?.status === "known"}
          <div class="sign-field">
            <span class="sign-label">Known host</span>
            <span class="sign-value sign-mono">{ctx.hostKey.type} {ctx.hostKey.fingerprint}</span>
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
            <button type="button" class="sign-link" onclick={() => viewSession(ctx.sessionId)}>
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
        <button
          type="button"
          class="btn btn-secondary"
          onclick={handleSkip}
          disabled={processing}
          title="Don't use this key; the next matching key may be offered">Skip</button
        >
        <button type="button" class="btn btn-primary" onclick={handleAction} disabled={processing}>
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
    background: var(--surface-container-low);
    padding: 2rem;
    min-width: 360px;
    max-width: 500px;
    width: 100%;
  }

  .sign-card h2 {
    font-family: var(--font-display);
    font-size: var(--title-lg);
    font-weight: 600;
    letter-spacing: -0.02em;
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

  .sign-hostkey-banner {
    border: 1px solid rgba(255, 196, 0, 0.45);
    background: rgba(255, 196, 0, 0.08);
    padding: 0.75rem 1rem;
    margin-bottom: 1.5rem;
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }

  .sign-hostkey-banner p {
    font-size: 0.85rem;
    color: var(--text-muted);
    margin: 0;
  }

  .sign-hostkey-title {
    font-family: var(--font-display);
    font-size: var(--body-md);
    font-weight: 600;
    letter-spacing: -0.01em;
  }

  .sign-preview {
    border: 1px solid var(--outline-variant);
    padding: 0.75rem 1rem;
    margin-bottom: 1.5rem;
    background: var(--surface-dim);
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
    border: 1px dashed var(--outline-variant);
    padding: 0.75rem 1rem;
    margin-bottom: 1.5rem;
    background: var(--surface-container);
  }

  .sign-reported-header {
    font-family: var(--font-mono);
    font-size: var(--label-sm);
    font-weight: 500;
    text-transform: uppercase;
    letter-spacing: 0.14em;
    color: var(--on-surface-variant);
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
    font-family: var(--font-mono);
    font-size: var(--body-md);
    color: var(--primary);
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
    background: rgba(255, 90, 90, 0.08);
    border: 1px solid rgba(255, 90, 90, 0.25);
    padding: 0.6rem 0.75rem;
    font-size: var(--body-md);
    color: var(--error);
    margin-bottom: 1rem;
    box-shadow: var(--glow-error);
  }

  .sign-actions {
    display: flex;
    justify-content: flex-end;
    gap: 0.5rem;
  }
</style>
