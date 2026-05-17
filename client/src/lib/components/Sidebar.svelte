<!-- SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0 -->
<script lang="ts">
  import { onDestroy } from "svelte";
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

  let accountMenuOpen = $state(false);
  // Tracks which input modality opened the account row. Hover-expanded rows
  // collapse instantly on mouseleave; click-expanded rows linger for 3s so the
  // user can move the cursor to the Sign-out button without it disappearing.
  let expandSource: "click" | "hover" | null = $state(null);
  let collapseTimer: ReturnType<typeof setTimeout> | null = null;

  const CLICK_AUTO_COLLAPSE_MS = 3000;
  const HOVER_AUTO_COLLAPSE_MS = 500;

  function clearCollapseTimer() {
    if (collapseTimer !== null) {
      clearTimeout(collapseTimer);
      collapseTimer = null;
    }
  }

  function collapseNow() {
    clearCollapseTimer();
    accountMenuOpen = false;
    expandSource = null;
  }

  function expandAsHover() {
    // Don't override a click-expanded row.
    if (accountMenuOpen && expandSource === "click") return;
    // Cancel any pending hover-collapse timer — covers re-entry during grace.
    clearCollapseTimer();
    accountMenuOpen = true;
    expandSource = "hover";
  }

  function expandAsClick() {
    clearCollapseTimer();
    accountMenuOpen = true;
    expandSource = "click";
    collapseTimer = setTimeout(collapseNow, CLICK_AUTO_COLLAPSE_MS);
  }

  function handleAccountClick() {
    if (accountMenuOpen && expandSource === "click") {
      collapseNow();
    } else {
      expandAsClick();
    }
  }

  function handleFooterMouseEnter() {
    // Re-entering the row during the hover-collapse grace period cancels it,
    // even if cursor lands on the name or logout button rather than the icon.
    if (accountMenuOpen && expandSource === "hover") {
      clearCollapseTimer();
    }
  }

  function handleFooterMouseLeave() {
    if (accountMenuOpen && expandSource === "hover") {
      clearCollapseTimer();
      collapseTimer = setTimeout(collapseNow, HOVER_AUTO_COLLAPSE_MS);
    }
  }

  function handleAccountKeydown(e: KeyboardEvent) {
    if (e.key === "Escape" && accountMenuOpen) {
      collapseNow();
    }
  }

  async function handleLogout() {
    collapseNow();
    await logout();
  }

  onDestroy(clearCollapseTimer);
</script>

<svelte:window onkeydown={handleAccountKeydown} />

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
              <span class="session-label" title={getEndpointLabel(sess.endpointId)}>
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
                  class="btn btn-warn btn-icon"
                  aria-label="Take control"
                  title="Take control"
                  onclick={() => wsTakeControl(sess.sessionId)}
                >
                  <svg
                    viewBox="0 0 16 16"
                    width="14"
                    height="14"
                    fill="none"
                    stroke="currentColor"
                    stroke-width="1.75"
                    stroke-linecap="round"
                    stroke-linejoin="round"
                    aria-hidden="true"
                  >
                    <path d="M2 8h7M6 5l3 3-3 3" />
                    <path d="M10 3h2a1 1 0 0 1 1 1v8a1 1 0 0 1-1 1h-2" />
                  </svg>
                </button>
              {:else}
                <button
                  type="button"
                  class="btn btn-ghost btn-icon"
                  aria-label="Release control"
                  title="Release control"
                  onclick={() => wsReleaseControl(sess.sessionId)}
                >
                  <svg
                    viewBox="0 0 16 16"
                    width="14"
                    height="14"
                    fill="none"
                    stroke="currentColor"
                    stroke-width="1.75"
                    stroke-linecap="round"
                    stroke-linejoin="round"
                    aria-hidden="true"
                  >
                    <path d="M7 8h7M11 5l3 3-3 3" />
                    <path d="M9 3H4a1 1 0 0 0-1 1v8a1 1 0 0 0 1 1h5" />
                  </svg>
                </button>
              {/if}
              <button
                type="button"
                class="btn btn-secondary btn-icon"
                aria-label="Close session"
                title="Close session"
                onclick={() => handleClose(sess.sessionId)}
              >
                <svg
                  viewBox="0 0 16 16"
                  width="14"
                  height="14"
                  fill="none"
                  stroke="currentColor"
                  stroke-width="1.75"
                  stroke-linecap="round"
                  aria-hidden="true"
                >
                  <path d="M4 4l8 8M12 4l-8 8" />
                </svg>
              </button>
            </div>
          </div>
        </li>
      {/each}
    </ul>
  </div>

  <div class="sidebar-footer">
    {#if $account?.isAdmin}
      <button
        type="button"
        class="btn-nav"
        class:active={currentPath === "/observer"}
        onclick={() => navTo("/observer")}
      >
        Observer Mode
      </button>
    {/if}
    <button
      type="button"
      class="btn-nav"
      class:active={currentPath.startsWith("/audit")}
      onclick={() => navTo("/audit")}
    >
      Audit
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
    <!-- svelte-ignore a11y_no_static_element_interactions -->
    <div
      class="footer-row"
      onmouseenter={handleFooterMouseEnter}
      onmouseleave={handleFooterMouseLeave}
    >
      {#if $account}
        <button
          type="button"
          class="account-trigger"
          onclick={handleAccountClick}
          onmouseenter={expandAsHover}
          aria-expanded={accountMenuOpen}
          aria-label={accountMenuOpen
            ? `Collapse account details for ${$account.name}`
            : `Expand account details for ${$account.name}`}
        >
          <Identicon uuid={$account.id} size={36} />
        </button>

        {#if accountMenuOpen}
          <div class="account-details">
            <span class="account-name">{$account.name}</span>
            {#if $account.isAdmin}
              <span class="badge badge-admin">admin</span>
            {/if}
          </div>
          <button
            type="button"
            class="icon-btn icon-btn-danger"
            onclick={handleLogout}
            title="Sign out"
            aria-label="Sign out"
          >
            <svg
              width="18"
              height="18"
              viewBox="0 0 24 24"
              aria-hidden="true"
              fill="none"
              stroke="currentColor"
              stroke-width="2"
              stroke-linecap="round"
              stroke-linejoin="round"
            >
              <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" />
              <path d="m16 17 5-5-5-5" />
              <path d="M21 12H9" />
            </svg>
          </button>
        {:else}
          <div class="footer-resources" role="group" aria-label="Resources">
            <a
              class="icon-btn"
              href="https://docs.shellwatch.ai"
              target="_blank"
              rel="noopener noreferrer"
              title="Documentation"
              aria-label="Documentation"
            >
              <svg
                width="18"
                height="18"
                viewBox="0 0 24 24"
                aria-hidden="true"
                fill="none"
                stroke="currentColor"
                stroke-width="2"
                stroke-linecap="round"
                stroke-linejoin="round"
              >
                <path
                  d="M12 7v14m4-9h2m-2-4h2M3 18a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1h5a4 4 0 0 1 4 4a4 4 0 0 1 4-4h5a1 1 0 0 1 1 1v13a1 1 0 0 1-1 1h-6a3 3 0 0 0-3 3a3 3 0 0 0-3-3zm3-6h2M6 8h2"
                />
              </svg>
            </a>
            <a
              class="icon-btn"
              href="https://github.com/rado0x54/ShellWatch"
              target="_blank"
              rel="noopener noreferrer"
              title="GitHub"
              aria-label="GitHub"
            >
              <svg
                width="18"
                height="18"
                viewBox="0 0 24 24"
                aria-hidden="true"
                fill="none"
                stroke="currentColor"
                stroke-width="2"
                stroke-linecap="round"
                stroke-linejoin="round"
              >
                <path
                  d="M15 22v-4a4.8 4.8 0 0 0-1-3.5c3 0 6-2 6-5.5c.08-1.25-.27-2.48-1-3.5c.28-1.15.28-2.35 0-3.5c0 0-1 0-3 1.5c-2.64-.5-5.36-.5-8 0C6 2 5 2 5 2c-.3 1.15-.3 2.35 0 3.5A5.4 5.4 0 0 0 4 9c0 3.5 3 5.5 6 5.5c-.39.49-.68 1.05-.85 1.65S8.93 17.38 9 18v4"
                />
                <path d="M9 18c-4.51 2-5-2-7-2" />
              </svg>
            </a>
          </div>
        {/if}
      {/if}
    </div>
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
    flex: 1;
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

  .session-actions :global(.btn-icon) {
    padding: 0.35rem;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    box-shadow: none;
    line-height: 0;
  }

  /* SVG is decorative (aria-hidden); let clicks reach the <button> so the
   * session-item's tagName==="BUTTON" guard isn't bypassed. */
  .session-actions :global(.btn-icon svg) {
    pointer-events: none;
  }

  .session-actions :global(.btn-secondary.btn-icon:hover) {
    color: var(--error);
    box-shadow: none;
  }

  .session-actions :global(.btn-warn.btn-icon:hover) {
    box-shadow: var(--glow-secondary);
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
    align-self: flex-start;
  }

  .badge-admin::before {
    content: "";
    width: 6px;
    height: 6px;
    background: var(--primary);
    display: inline-block;
  }

  .footer-row {
    display: flex;
    align-items: center;
    gap: var(--space-3);
    margin-top: var(--space-3);
    padding-top: var(--space-4);
    border-top: 1px solid var(--outline-variant);
  }

  .account-trigger {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    padding: 2px;
    background: transparent;
    border: none;
    cursor: pointer;
    transition: filter 0.15s;
    flex-shrink: 0;
  }

  .account-trigger:hover {
    filter: brightness(1.15);
  }

  .account-trigger:focus-visible {
    outline: 2px solid var(--primary);
    outline-offset: 2px;
  }

  .account-details {
    display: flex;
    flex-direction: column;
    gap: 0.15rem;
    min-width: 0;
    flex: 1;
  }

  .footer-resources {
    display: flex;
    align-items: center;
    gap: var(--space-1);
    margin-left: auto;
  }

  .icon-btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 36px;
    height: 36px;
    background: transparent;
    border: none;
    color: var(--on-surface-variant);
    cursor: pointer;
    text-decoration: none;
    transition:
      color 0.15s,
      background 0.15s;
  }

  .icon-btn:hover {
    color: var(--on-surface);
    background: var(--surface-container);
  }

  .icon-btn:focus-visible {
    outline: 2px solid var(--primary);
    outline-offset: -2px;
  }

  .icon-btn-danger:hover {
    color: var(--error);
  }

  @media (max-width: 768px) {
    .sidebar {
      width: 100%;
      min-width: 100%;
    }
  }
</style>
