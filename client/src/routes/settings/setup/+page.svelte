<!-- SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0 -->
<!--
  Setup reference page — three help sections lifted from the old onboarding
  wizard + the Endpoints page hint-block. The wizard now flows users through
  the SSH-server piece inline; this page is the always-available reference.
-->
<script lang="ts">
  import Wordmark from "$lib/components/Wordmark.svelte";
  import ServerSetupGuide from "$lib/components/ServerSetupGuide.svelte";

  const DOCS_URL = "https://docs.shellwatch.ai";
</script>

<section>
  <h2>SSH Server Setup</h2>
  <p class="hint">
    Two one-time edits on each remote host you want to manage. Required for OpenSSH to accept
    <Wordmark /> passkey credentials.
  </p>
  <ServerSetupGuide />
  <p class="hint">
    <a href={DOCS_URL} target="_blank" rel="noopener noreferrer"
      >Learn more on docs.shellwatch.ai →</a
    >
  </p>
</section>

<section>
  <h2>Endpoint Settings &amp; User Verification</h2>
  <p class="hint">
    <strong>User Verification</strong> controls the WebAuthn <code>userVerification</code> option
    used for passkey sign ceremonies to this endpoint. Defaults to <code>required</code> (PIN / biometric
    always enforced). Relax only if a specific authenticator can't provide UV.
  </p>
  <p class="hint">
    This is a <em>client-side</em> setting — <Wordmark /> requests UV from the authenticator and rejects
    responses without it when set to <code>required</code>, but the authoritative gate is the
    <strong>OpenSSH server</strong>. To make UV load-bearing, configure the target host to require
    it:
  </p>
  <ul class="hint">
    <li>
      <strong>Globally</strong> in <code>sshd_config</code>:
      <code>PubkeyAuthOptions verify-required</code>
    </li>
    <li>
      <strong>Per-key</strong> in <code>~/.ssh/authorized_keys</code> on the server:
      <code>verify-required sk-ecdsa-sha2-nistp256@openssh.com AAAA... user@host</code>
    </li>
  </ul>
  <p class="hint">
    Either source enables enforcement; <code>sshd</code> rejects signatures without the UV bit (<code
      >SSH_SK_USER_VERIFICATION_REQD</code
    >, <code>0x04</code>) set, logging
    <code>user verification requirement not met</code>.
  </p>
  <p class="hint">
    <a href={DOCS_URL} target="_blank" rel="noopener noreferrer"
      >Learn more on docs.shellwatch.ai →</a
    >
  </p>
</section>

<section>
  <h2>Integrations</h2>
  <p class="hint">A few <Wordmark /> features worth knowing about.</p>

  <div class="advanced-list">
    <div class="advanced-item">
      <strong><code>shellwatch-agent</code></strong>
      <p>
        A local SSH agent that brokers signing through <Wordmark />. Run
        <code>ssh user@host</code> from your terminal — your passkey unlocks the connection, no private
        key on disk.
      </p>
    </div>
    <div class="advanced-item">
      <strong>MCP (Model Context Protocol)</strong>
      <p>
        Agents (Claude Desktop, Cursor, etc.) talk to <Wordmark /> via MCP at <code>/mcp</code>.
        OAuth-capable clients negotiate scoped API keys automatically; static-config clients can
        generate keys in <strong>Settings → API Keys</strong>.
      </p>
    </div>
    <div class="advanced-item">
      <strong><code>pam-ssh-agent-webauthn</code></strong>
      <p>
        PAM module that gates remote actions (e.g. <code>sudo</code>) on a passkey signature
        brokered through <Wordmark />. Source at
        <a
          href="https://github.com/rado0x54/pam-ssh-agent-webauthn"
          target="_blank"
          rel="noopener noreferrer">github.com/rado0x54/pam-ssh-agent-webauthn</a
        >.
      </p>
    </div>
    <div class="advanced-item">
      <strong>Docs &amp; guides</strong>
      <p>
        Setup walkthroughs and reference live at
        <a href={DOCS_URL} target="_blank" rel="noopener noreferrer">docs.shellwatch.ai</a>.
      </p>
    </div>
  </div>
</section>

<style>
  section {
    margin-bottom: var(--space-8);
  }

  section + section {
    padding-top: var(--space-6);
    border-top: 1px solid var(--border);
  }

  h2 {
    font-size: 0.75rem;
    font-weight: 600;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin: 0 0 0.75rem;
  }

  .hint {
    font-size: 0.85rem;
    color: var(--text-muted);
    line-height: 1.55;
    margin: 0 0 0.75rem;
  }

  .hint code {
    font-family: var(--font-mono);
    font-size: 0.85em;
    color: var(--primary);
  }

  .hint a {
    color: var(--accent);
    text-decoration: none;
  }

  .hint a:hover {
    text-decoration: underline;
  }

  ul.hint {
    padding-left: 1.25rem;
  }

  ul.hint li {
    margin-bottom: 0.4rem;
  }

  .advanced-list {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }

  .advanced-item {
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.6rem 0.75rem;
    background: var(--bg-primary);
  }

  .advanced-item p {
    margin: 0.25rem 0 0;
    font-size: 0.78rem;
    color: var(--text-muted);
    line-height: 1.5;
  }

  .advanced-item code {
    font-family: var(--font-mono);
    font-size: 0.85em;
    color: var(--primary);
  }

  .advanced-item a {
    color: var(--accent);
    text-decoration: none;
  }

  .advanced-item a:hover {
    text-decoration: underline;
  }
</style>
