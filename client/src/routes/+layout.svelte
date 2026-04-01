<script lang="ts">
import { onMount } from "svelte";
import { goto } from "$app/navigation";
import { page } from "$app/stores";
import "../app.css";
import Sidebar from "$lib/components/Sidebar.svelte";
import { basePath } from "$lib/stores/connection.js";
import { endpoints, fetchEndpoints } from "$lib/stores/endpoints.js";
import { checkAuth } from "$lib/stores/webauthn.js";
import { connectWs, onWsMessage, sessions } from "$lib/stores/ws.js";
import { handleFidoSignRequest } from "$lib/utils/fido.js";

let { children } = $props();

let ready = $state(false);
let mobileMenuOpen = $state(false);
let activeSessionId = $state<string | null>(null);
let sessionModes = $state<Record<string, string>>({});

const isLoginPage = $derived($page.url.pathname.endsWith("/login"));

function handleConnect(sessionId: string, mode: "control" | "observer") {
  activeSessionId = sessionId;
  sessionModes[sessionId] = mode;
}

onMount(async () => {
  // Initialize base path from server-injected config
  const base = (window as unknown as { __BASE_PATH__?: string }).__BASE_PATH__ ?? "";
  basePath.set(base);

  const currentPath = window.location.pathname;
  const isLogin = currentPath.endsWith("/login");

  if (!isLogin) {
    const { hasPasskeys, authenticated } = await checkAuth();
    if (hasPasskeys && !authenticated) {
      await goto(`${base}/login`);
      ready = true;
      return;
    }
  }

  if (!isLogin) {
    connectWs();
    await fetchEndpoints();

    // Handle FIDO signing requests
    onWsMessage((msg) => {
      if (msg.type === "fido:sign-request") {
        handleFidoSignRequest(msg);
      }
      if (msg.type === "terminal:mode") {
        sessionModes[msg.sessionId] = msg.mode;
      }
    });
  }

  ready = true;
});
</script>

<svelte:head>
  <script src="config.js"></script>
</svelte:head>

{#if !ready}
  <div class="loading">
    <span>Loading...</span>
  </div>
{:else if isLoginPage}
  {@render children()}
{:else}
  <div class="app-shell">
    <!-- Mobile header -->
    <header class="mobile-header">
      <button class="hamburger" onclick={() => (mobileMenuOpen = !mobileMenuOpen)}>
        {#if mobileMenuOpen}
          &#x2715;
        {:else}
          &#9776;
        {/if}
      </button>
      <span class="mobile-title">ShellWatch</span>
    </header>

    <div class="app-body">
      <!-- Sidebar (desktop always visible, mobile toggleable) -->
      <div class="sidebar-container" class:mobile-open={mobileMenuOpen}>
        <Sidebar
          {activeSessionId}
          {sessionModes}
          onConnect={handleConnect}
          onMobileClose={() => (mobileMenuOpen = false)}
        />
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
    color: var(--text-muted);
    font-size: 1.1rem;
  }

  .app-shell {
    display: flex;
    flex-direction: column;
    height: 100vh;
  }

  .mobile-header {
    display: none;
    align-items: center;
    gap: 0.75rem;
    padding: 0.5rem 1rem;
    background: var(--bg-secondary);
    border-bottom: 1px solid var(--border);
    flex-shrink: 0;
  }

  .hamburger {
    background: none;
    border: none;
    color: var(--text-primary);
    font-size: 1.5rem;
    cursor: pointer;
    padding: 0.25rem;
    line-height: 1;
  }

  .mobile-title {
    font-weight: 600;
    font-size: 1rem;
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
