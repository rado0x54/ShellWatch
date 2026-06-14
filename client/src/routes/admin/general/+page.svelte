<!-- SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0 -->
<script lang="ts">
  import { apiFetch } from "$lib/api.js";
  import { toastError } from "$lib/stores/toasts.js";

  interface SeedPasskey {
    credentialId: string;
    publicKeyHex: string;
    counter: number;
    transports: string[];
    label: string;
  }

  interface SeedEndpoint {
    label: string;
    address: string;
    agentForward: boolean;
    passkeyCredentialRef?: string;
  }

  let seedYaml = $state("");
  let exportLoading = $state(false);
  let copied = $state(false);

  /** Escape a string for use as a double-quoted YAML value */
  function yamlEscape(value: string): string {
    return value.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n");
  }

  function yamlStr(value: string): string {
    return `"${yamlEscape(value)}"`;
  }

  function toYaml(passkeys: SeedPasskey[], endpoints: SeedEndpoint[]): string {
    const lines: string[] = [];

    if (passkeys.length > 0) {
      lines.push("seedAdminPasskeys:");
      for (const pk of passkeys) {
        lines.push(`  - credentialId: ${yamlStr(pk.credentialId)}`);
        lines.push(`    publicKeyHex: ${yamlStr(pk.publicKeyHex)}`);
        lines.push(`    counter: ${pk.counter}`);
        if (pk.transports.length > 0) {
          lines.push(`    transports: [${pk.transports.map((t) => yamlStr(t)).join(", ")}]`);
        } else {
          lines.push("    transports: []");
        }
        lines.push(`    label: ${yamlStr(pk.label)}`);
      }
    }

    if (endpoints.length > 0) {
      if (lines.length > 0) lines.push("");
      lines.push("seedAdminEndpoints:");
      for (const ep of endpoints) {
        lines.push(`  - label: ${yamlStr(ep.label)}`);
        lines.push(`    address: ${yamlStr(ep.address)}`);
        // Only emit when off — default is true, keep YAML clean.
        if (!ep.agentForward) {
          lines.push("    agentForward: false");
        }
        if (ep.passkeyCredentialRef) {
          lines.push(`    passkeyCredentialRef: ${yamlStr(ep.passkeyCredentialRef)}`);
        }
      }
    }

    return lines.join("\n");
  }

  async function handleExport() {
    exportLoading = true;
    try {
      const res = await apiFetch("/api/accounts/export-seed");
      if (!res.ok) {
        const err = await res.json();
        toastError(err.error || "Failed to export seed config");
        return;
      }
      const data = await res.json();
      seedYaml = toYaml(data.passkeys, data.endpoints);
    } finally {
      exportLoading = false;
    }
  }

  async function handleCopy() {
    await navigator.clipboard.writeText(seedYaml);
    copied = true;
    setTimeout(() => (copied = false), 2000);
  }
</script>

<section>
  <h2>Export Seed Config</h2>
  <p class="export-desc">
    Generate a YAML snippet for <code>config.yaml</code> to seed the admin passkey and endpoints on a
    fresh instance.
  </p>

  {#if seedYaml}
    <div class="code-block-wrap">
      <button type="button" class="btn btn-secondary copy-btn" onclick={handleCopy}>
        {copied ? "Copied!" : "Copy"}
      </button>
      <pre class="code-block">{seedYaml}</pre>
    </div>
  {/if}

  <button type="button" class="btn btn-primary" disabled={exportLoading} onclick={handleExport}>
    {exportLoading ? "Loading..." : seedYaml ? "Refresh" : "Generate"}
  </button>
</section>

<style>
  h2 {
    font-size: 0.75rem;
    font-weight: 600;
    margin-bottom: 0.75rem;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }

  .export-desc {
    font-size: 0.8rem;
    color: var(--text-muted);
    margin-bottom: 0.75rem;
  }

  .export-desc code {
    background: var(--bg-primary);
    padding: 0.1rem 0.25rem;
    border-radius: 3px;
    font-size: 0.8rem;
  }

  .code-block-wrap {
    position: relative;
    margin-bottom: 0.75rem;
  }

  .copy-btn {
    position: absolute;
    top: 0.5rem;
    right: 0.5rem;
    z-index: 1;
  }
</style>
