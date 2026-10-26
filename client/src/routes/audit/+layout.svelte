<!-- SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0 -->
<script lang="ts">
  import { onMount } from "svelte";
  import SectionTabs from "$lib/components/SectionTabs.svelte";
  import { account, fetchAccount } from "$lib/stores/account.js";

  let { children } = $props();

  type Pathname = import("$app/types").Pathname;

  onMount(() => void fetchAccount());

  // Admin-only tab (#242). Every other Audit tab is account-scoped; the OAuth
  // client log is server-wide, because DCR and CIMD both register a client
  // before anyone has signed in, so there is no account to scope it to. The
  // API returns 403 to a non-admin regardless — this just keeps the tab out of
  // their way.
  const tabs = $derived<{ path: Pathname; label: string }[]>([
    { path: "/audit/sessions", label: "Sessions" },
    { path: "/audit/signings", label: "Signing Requests" },
    { path: "/audit/notifications", label: "Notifications" },
    ...($account?.isAdmin === true
      ? [{ path: "/audit/oauth-clients" as Pathname, label: "OAuth Clients" }]
      : []),
  ]);
</script>

<div class="audit-layout">
  <div class="audit-header">
    <h1>Audit</h1>
    <p class="subtitle">
      {#if $account?.isAdmin === true}
        Activity log — newest first. Account-scoped, except the server-wide OAuth client log.
      {:else}
        Account-scoped activity log — newest first.
      {/if}
    </p>
  </div>

  <SectionTabs {tabs} label="Audit sections" />

  <div class="audit-content">
    {@render children()}
  </div>
</div>

<style>
  .audit-layout {
    padding: 2rem;
    overflow-y: auto;
    height: 100%;
  }

  .audit-header {
    margin-bottom: 1.5rem;
  }

  .audit-header h1 {
    font-family: var(--font-display);
    font-size: var(--display-md);
    font-weight: 600;
    letter-spacing: -0.035em;
  }

  .subtitle {
    color: var(--on-surface-variant);
    font-size: var(--body-md);
    margin-top: var(--space-2);
  }

  .audit-content {
    min-height: 0;
  }

  @media (max-width: 768px) {
    .audit-layout {
      padding: 1rem;
    }
  }
</style>
