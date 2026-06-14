<!-- SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0 -->
<script lang="ts">
  import { onMount } from "svelte";
  import { page } from "$app/state";
  import "../app.css";
  import Sidebar from "$lib/components/Sidebar.svelte";
  import ToastContainer from "$lib/components/ToastContainer.svelte";
  import Wordmark from "$lib/components/Wordmark.svelte";
  import { fetchAccount } from "$lib/stores/account.js";
  import { initBuildInfoFromWindow } from "$lib/stores/build-info.js";
  import { selfRegistrationEnabled } from "$lib/stores/connection.js";
  import { fetchEndpoints } from "$lib/stores/endpoints.js";
  import { beginLogin, isAuthenticated } from "$lib/oauth.js";
  import { connectWs, onWsMessage } from "$lib/stores/ws.js";

  let { children } = $props();

  let ready = $state(false);
  let mobileMenuOpen = $state(false);
  let sessionModes = $state<Record<string, string>>({});

  // Public, no-token routes that render fullscreen (no sidebar) and skip the
  // auth-gated bootstrap below. There's no SPA /login anymore — Hydra owns the
  // login UI, so an unauthenticated user is sent straight into the OAuth flow.
  function isUnauthPath(path: string): boolean {
    return (
      path.endsWith("/register") ||
      path.includes("/passkey-invite/") ||
      path.includes("/auth/callback")
    );
  }

  const isFullscreenPage = $derived(isUnauthPath(page.url.pathname));

  onMount(async () => {
    // Initialize runtime config from server-injected config.js
    const win = window as unknown as {
      __SELF_REGISTRATION_ENABLED__?: boolean;
    };
    selfRegistrationEnabled.set(win.__SELF_REGISTRATION_ENABLED__ ?? false);
    initBuildInfoFromWindow();

    const currentPath = window.location.pathname;
    const isUnauthPage = isUnauthPath(currentPath);

    if (!isUnauthPage) {
      // Auth is a browser-held OAuth token (#217). isAuthenticated() tries a
      // silent refresh; if there's no usable token, start the OAuth flow rather
      // than showing a local login mask. A remembered Hydra session skips
      // straight through (no prompt); otherwise Hydra renders the passkey login
      // page. The current path is preserved as the post-login destination.
      if (!(await isAuthenticated())) {
        await beginLogin(window.location.pathname + window.location.search);
        ready = true;
        return;
      }
    }

    if (!isUnauthPage) {
      await connectWs();
      await fetchEndpoints();
      fetchAccount();

      onWsMessage((msg) => {
        if (msg.type === "terminal:mode") {
          sessionModes[msg.sessionId] = msg.mode;
        }
      });
    }

    ready = true;
  });
</script>

<ToastContainer />

{#if !ready}
  <div class="loading">
    <span>Loading...</span>
  </div>
{:else if isFullscreenPage}
  {@render children()}
{:else}
  <div class="app-shell">
    <!-- Mobile header -->
    <header class="mobile-header">
      <button type="button" class="hamburger" onclick={() => (mobileMenuOpen = !mobileMenuOpen)}>
        {#if mobileMenuOpen}
          &#x2715;
        {:else}
          &#9776;
        {/if}
      </button>
      <img class="mobile-logo" src="/logo.svg" alt="" />
      <span class="mobile-title"><Wordmark /></span>
    </header>

    <div class="app-body">
      <!-- Sidebar (desktop always visible, mobile toggleable) -->
      <div class="sidebar-container" class:mobile-open={mobileMenuOpen}>
        <Sidebar {sessionModes} onMobileClose={() => (mobileMenuOpen = false)} />
      </div>

      <!-- Mobile overlay -->
      {#if mobileMenuOpen}
        <!-- svelte-ignore a11y_click_events_have_key_events -->
        <!-- svelte-ignore a11y_no_static_element_interactions -->
        <div class="mobile-overlay" onclick={() => (mobileMenuOpen = false)}></div>
      {/if}

      <!-- Main content -->
      <main class="main-content">
        {@render children()}
      </main>
    </div>
  </div>
{/if}

<style>
  .loading {
    display: flex;
    align-items: center;
    justify-content: center;
    height: 100vh;
    color: var(--on-surface-variant);
    font-family: var(--font-mono);
    font-size: var(--label-md);
    text-transform: uppercase;
    letter-spacing: 0.14em;
  }

  .app-shell {
    display: flex;
    flex-direction: column;
    height: 100vh;
  }

  .mobile-header {
    display: none;
    align-items: center;
    gap: var(--space-4);
    padding: var(--space-3) var(--space-5);
    background: var(--surface-container-low);
    flex-shrink: 0;
  }

  .hamburger {
    background: none;
    border: none;
    color: var(--on-surface);
    font-size: 1.5rem;
    cursor: pointer;
    padding: var(--space-1);
    line-height: 1;
  }

  .mobile-logo {
    width: 28px;
    height: 28px;
    flex-shrink: 0;
  }

  .mobile-title {
    font-size: var(--body-lg);
  }

  .app-body {
    display: flex;
    flex: 1;
    min-height: 0;
  }

  .sidebar-container {
    flex-shrink: 0;
  }

  .main-content {
    flex: 1;
    display: flex;
    flex-direction: column;
    min-width: 0;
    min-height: 0;
  }

  .mobile-overlay {
    display: none;
  }

  @media (max-width: 768px) {
    .mobile-header {
      display: flex;
    }

    .sidebar-container {
      position: fixed;
      top: 0;
      left: 0;
      bottom: 0;
      z-index: 100;
      transform: translateX(-100%);
      transition: transform 0.2s ease;
      width: 280px;
    }

    .sidebar-container.mobile-open {
      transform: translateX(0);
    }

    .mobile-overlay {
      display: block;
      position: fixed;
      inset: 0;
      background: rgba(0, 0, 0, 0.5);
      z-index: 99;
    }
  }
</style>
