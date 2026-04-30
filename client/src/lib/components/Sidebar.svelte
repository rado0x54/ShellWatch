<script lang="ts">
  import { goto } from "$app/navigation";
  import { resolve } from "$app/paths";
  import { page } from "$app/state";
  import Identicon from "$lib/components/Identicon.svelte";
  import Wordmark from "$lib/components/Wordmark.svelte";
  import { account } from "$lib/stores/account.js";
  import { endpoints } from "$lib/stores/endpoints.js";
  import { formatEndpointAddress } from "$lib/utils/endpoint-address.js";
  import { closeSession, createSession } from "$lib/stores/sessions-api.js";
  import { toastError } from "$lib/stores/toasts.js";
  import { errorMessage } from "$lib/utils/error-message.js";
  import { logout } from "$lib/stores/webauthn.js";
  import { sessions, wsReleaseControl, wsTakeControl } from "$lib/stores/ws.js";

  interface Props {
    sessionModes: Record<string, string>;
    onMobileClose?: () => void;
  }

  let { sessionModes, onMobileClose }: Props = $props();

  const currentPath = $derived(page.url.pathname);
  const activeSessionId = $derived(
    currentPath.startsWith("/session/") ? currentPath.split("/session/")[1] : null,
  );

  async function handleConnect(endpointId: string) {
    try {
      const session = await createSession(endpointId);
      await goto(resolve(`/session/${session.sessionId}`));
      onMobileClose?.();
    } catch (err) {
      console.error("Failed to create session:", err);
      toastError(`Failed to create session: ${errorMessage(err)}`);
    }
  }

  async function handleClose(sessionId: string) {
    try {
      await closeSession(sessionId);
    } catch (err) {
      console.error("Failed to close session:", err);
      toastError(`Failed to close session: ${errorMessage(err)}`);
    }
  }

  async function handleSessionClick(sessionId: string) {
    await goto(resolve(`/session/${sessionId}`));
    onMobileClose?.();
  }

  function getEndpointLabel(endpointId: string): string {
    const ep = $endpoints.find((e) => e.id === endpointId);
    return ep?.label ?? endpointId;
  }

  async function navTo(path: import("$app/types").Pathname) {
    await goto(resolve(path));
    onMobileClose?.();
  }
</script>

<nav class="sidebar">
  <div class="sidebar-brand">
    <img class="sidebar-logo" src="/logo.svg" alt="" />
    <span class="sidebar-wordmark"><Wordmark /></span>
  </div>

  <div class="sidebar-section">
    <h2>Endpoints</h2>
    <ul>
      {#each $endpoints as ep (ep.id)}
        <li>
          <div class="endpoint-item">
            <div class="endpoint-info">
              <span class="endpoint-label" title={formatEndpointAddress(ep)}>{ep.label}</span>
            </div>
            <button type="button" class="btn btn-primary" onclick={() => handleConnect(ep.id)}
              >Connect</button
            >
          </div>
        </li>
      {/each}
    </ul>
  </div>

  <div class="sidebar-section">
    <h2>Sessions</h2>
    <ul>
      {#if $sessions.length === 0}
        <li class="no-sessions">No active sessions</li>
      {/if}
      {#each $sessions as sess (sess.sessionId)}
        {@const mode = sessionModes[sess.sessionId] ?? sess.mode}
        {@const isActive = sess.sessionId === activeSessionId}
        {@const isObserver = mode === "observer"}
        <li>
          <!-- svelte-ignore a11y_click_events_have_key_events -->
          <!-- svelte-ignore a11y_no_static_element_interactions -->
          <div
            class="session-item"
            class:active={isActive}
            onclick={(e) => {
              if ((e.target as HTMLElement).tagName !== "BUTTON") {
                handleSessionClick(sess.sessionId);
              }
            }}
          >
            <div class="session-info">
              <span class="session-label">
                <span class="status-dot {sess.status}"></span>{getEndpointLabel(sess.endpointId)}
                {#if isObserver}
                  <span class="badge badge-observer">observer</span>
                {/if}
              </span>
              <span class="session-detail">{sess.sessionId} ({sess.source})</span>
            </div>
            <div class="session-actions">
              {#if isObserver}
                <button
                  type="button"
                  class="btn btn-warn"
                  onclick={() => wsTakeControl(sess.sessionId)}>Take Control</button
                >
              {:else}
                <button
                  type="button"
                  class="btn btn-ghost"
                  onclick={() => wsReleaseControl(sess.sessionId)}>Release</button
                >
              {/if}
              <button
                type="button"
                class="btn btn-secondary"
                onclick={() => handleClose(sess.sessionId)}>Close</button
              >
            </div>
          </div>
        </li>
      {/each}
    </ul>
  </div>

  <div class="sidebar-footer">
    {#if $account}
      <div class="account-info">
        <Identicon uuid={$account.id} size={36} />
        <div class="account-details">
          <span class="account-name">{$account.name}</span>
          {#if $account.isAdmin}
            <span class="badge badge-admin">admin</span>
          {/if}
        </div>
      </div>
    {/if}
    <button
      type="button"
      class="btn-nav"
      class:active={currentPath === "/observer"}
      onclick={() => navTo("/observer")}
    >
      Observer Mode
    </button>
    <button
      type="button"
      class="btn-nav"
      class:active={currentPath.startsWith("/settings")}
      onclick={() => navTo("/settings")}
    >
      Settings
    </button>
    {#if $account?.isAdmin}
      <button
        type="button"
        class="btn-nav"
        class:active={currentPath.startsWith("/admin")}
        onclick={() => navTo("/admin")}
      >
        Admin
      </button>
    {/if}
    <button type="button" class="btn-nav btn-logout" onclick={logout}> Sign Out </button>
  </div>
</nav>

<style>
  .sidebar {
    width: var(--sidebar-width);
    min-width: var(--sidebar-width);
    background: var(--surface-container-low);
    display: flex;
    flex-direction: column;
    overflow-y: auto;
    height: 100%;
  }

  .sidebar-brand {
    display: flex;
    align-items: center;
    gap: var(--space-3);
    padding: var(--space-5) var(--space-4);
  }

  .sidebar-logo {
    width: 56px;
    height: 56px;
    flex-shrink: 0;
  }

  .sidebar-wordmark {
    font-size: var(--title-md);
  }

  .sidebar-section {
    padding: var(--space-5) var(--space-4);
  }

  .sidebar-section h2 {
    font-family: var(--font-mono);
    font-size: var(--label-sm);
    font-weight: 500;
    text-transform: uppercase;
    letter-spacing: 0.14em;
    color: var(--on-surface-variant);
    margin-bottom: var(--space-4);
  }

  .sidebar-section ul {
    list-style: none;
  }

  .sidebar-section li {
    margin-bottom: var(--space-2);
  }

  .no-sessions {
    color: var(--on-surface-faint);
    font-size: var(--body-md);
    padding: var(--space-2) 0;
    font-family: var(--font-mono);
  }

  .endpoint-item {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: var(--space-3);
    padding: var(--space-3) var(--space-4);
    background: transparent;
    position: relative;
  }

  .endpoint-item:hover {
    background: var(--surface-container);
  }

  .endpoint-info {
    display: flex;
    flex-direction: column;
    gap: 0.15rem;
    min-width: 0;
    flex: 1;
  }

  .endpoint-label {
    font-weight: 600;
    font-size: var(--body-md);
    color: var(--on-surface);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .endpoint-item > :global(.btn) {
    flex-shrink: 0;
  }

  .session-item {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: var(--space-3) var(--space-4);
    background: transparent;
    cursor: pointer;
    position: relative;
    transition: background 0.15s;
  }

  .session-item:hover {
    background: var(--surface-container);
  }

  .session-item.active {
    background: var(--surface-container-high);
  }

  /* Power Rail — 2px vertical primary strip on active row */
  .session-item.active::before {
    content: "";
    position: absolute;
    left: 0;
    top: 0;
    bottom: 0;
    width: 2px;
    background: var(--primary);
    box-shadow: 0 0 12px rgba(105, 246, 184, 0.6);
  }

  .session-info {
    display: flex;
    flex-direction: column;
    gap: 0.15rem;
    min-width: 0;
  }

  .session-label {
    font-size: var(--body-md);
    font-weight: 500;
    color: var(--on-surface);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .session-detail {
    font-family: var(--font-mono);
    font-size: var(--label-sm);
    color: var(--on-surface-variant);
  }

  .session-actions {
    display: flex;
    gap: var(--space-1);
    flex-shrink: 0;
  }

  .sidebar-footer {
    margin-top: auto;
    padding: var(--space-5) var(--space-4);
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
  }

  .btn-nav {
    width: 100%;
    background: transparent;
    color: var(--on-surface-variant);
    padding: var(--space-3) var(--space-3);
    border: none;
    cursor: pointer;
    font-family: var(--font-ui);
    font-size: var(--body-md);
    text-align: left;
    letter-spacing: 0.02em;
    transition:
      background 0.15s,
      color 0.15s;
    position: relative;
  }

  .btn-nav:hover {
    color: var(--primary);
    background: var(--surface-container);
  }

  .btn-nav.active {
    color: var(--on-surface);
    background: var(--surface-container-high);
  }

  .btn-nav.active::before {
    content: "";
    position: absolute;
    left: 0;
    top: 0;
    bottom: 0;
    width: 2px;
    background: var(--primary);
    box-shadow: 0 0 12px rgba(105, 246, 184, 0.6);
  }

  .account-info {
    display: flex;
    align-items: center;
    gap: var(--space-3);
    padding: var(--space-3) 0;
    margin-bottom: var(--space-2);
  }

  .account-details {
    display: flex;
    flex-direction: column;
    gap: 0.15rem;
    min-width: 0;
  }

  .account-name {
    font-size: var(--body-md);
    font-weight: 600;
    color: var(--on-surface);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .badge-admin {
    display: inline-flex;
    align-items: center;
    gap: 0.4rem;
    font-family: var(--font-mono);
    font-size: var(--label-sm);
    text-transform: lowercase;
    letter-spacing: 0.04em;
    color: var(--primary);
    font-weight: 500;
  }

  .badge-admin::before {
    content: "";
    width: 6px;
    height: 6px;
    background: var(--primary);
    display: inline-block;
  }

  .btn-logout:hover {
    color: var(--error);
    background: var(--surface-container);
  }

  @media (max-width: 768px) {
    .sidebar {
      width: 100%;
      min-width: 100%;
    }
  }
</style>
