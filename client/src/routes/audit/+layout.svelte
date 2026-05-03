<!-- SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0 -->
<script lang="ts">
  import SectionTabs from "$lib/components/SectionTabs.svelte";

  let { children } = $props();

  type Pathname = import("$app/types").Pathname;
  const tabs: { path: Pathname; label: string }[] = [
    { path: "/audit/sessions", label: "Sessions" },
    { path: "/audit/signings", label: "Signing Requests" },
  ];
</script>

<div class="audit-layout">
  <div class="audit-header">
    <h1>Audit</h1>
    <p class="subtitle">Account-scoped activity log — newest first.</p>
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
