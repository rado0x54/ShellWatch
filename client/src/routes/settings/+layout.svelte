<!-- SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0 -->
<script lang="ts">
  import { onMount } from "svelte";
  import SectionTabs from "$lib/components/SectionTabs.svelte";
  import { account, fetchAccount } from "$lib/stores/account.js";
  import { fetchSshKeys, sshKeys } from "$lib/stores/keys.js";

  let { children } = $props();

  type Pathname = import("$app/types").Pathname;

  onMount(async () => {
    await fetchAccount();
    // SSH keys are admin-only (the API rejects non-admin requests). Only fetch
    // them when admin so we can conditionally surface the SSH Keys tab.
    if ($account?.isAdmin) {
      await fetchSshKeys();
    }
  });

  // Admin-only tab. Only visible when there's actually a file-based SSH key
  // registered; non-admins never see it.
  const showSshKeysTab = $derived(
    $account?.isAdmin === true && $sshKeys.some((k) => k.type === "file"),
  );

  const tabs = $derived<{ path: Pathname; label: string }[]>([
    { path: "/settings/general", label: "General" },
    { path: "/settings/endpoints", label: "Endpoints" },
    { path: "/settings/keys", label: "Passkeys" },
    ...(showSshKeysTab
      ? [{ path: "/settings/ssh-keys" as Pathname, label: "Other SSH Keys" }]
      : []),
    { path: "/settings/notifications", label: "Notifications" },
    { path: "/settings/setup", label: "Setup" },
  ]);
</script>

<div class="settings-page">
  <div class="settings-header">
    <h1>Settings</h1>
  </div>

  <SectionTabs {tabs} label="Settings sections" />

  <div class="settings-content">
    {@render children()}
  </div>
</div>

<style>
  .settings-page {
    padding: 2rem;
    overflow-y: auto;
    height: 100%;
  }

  .settings-header {
    margin-bottom: 1.5rem;
  }

  .settings-header h1 {
    font-family: var(--font-display);
    font-size: var(--display-md);
    font-weight: 600;
    letter-spacing: -0.035em;
  }

  .settings-content {
    min-height: 0;
  }

  @media (max-width: 768px) {
    .settings-page {
      padding: 1rem;
    }
  }
</style>
