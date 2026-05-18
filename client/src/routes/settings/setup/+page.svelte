<!-- SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0 -->
<!--
  Setup reference page — collapsible sections, one per ShellWatch integration
  surface. Each card explains what the piece is and the minimum steps to wire
  it up; the actual config flows live elsewhere (Settings → Endpoints, etc.).
-->
<script lang="ts">
  import Wordmark from "$lib/components/Wordmark.svelte";
  import ServerSetupGuide from "$lib/components/ServerSetupGuide.svelte";

  import { onMount } from "svelte";

  const DOCS_URL = "https://docs.shellwatch.ai";
  const PAM_REPO_URL = "https://github.com/rado0x54/pam-ssh-agent-webauthn";

  // The MCP endpoint lives at the same origin the user is browsing — render
  // the actual URL so it's copy-pastable. window.location is only available
  // client-side; default to a placeholder so SSR doesn't trip over it.
  let mcpUrl = $state("/mcp");
  onMount(() => {
    mcpUrl = `${window.location.origin}/mcp`;
  });
  // Agent binaries are published as their own release stream tagged
  // `agent/vX.Y.Z` (separate from the main ShellWatch `vX.Y.Z` releases).
  // GitHub's release search has no tag-prefix qualifier, so we filter by name
  // — every agent release names itself "ShellWatch Agent <version>".
  const AGENT_RELEASES_URL =
    "https://github.com/rado0x54/ShellWatch/releases?q=%22ShellWatch+Agent%22&expanded=true";
</script>

<section class="setup-page">
  <details class="setup-card">
    <summary>SSH Server Setup</summary>
    <div class="setup-body">
      <p class="hint">
        Configure each remote host you want to manage so OpenSSH accepts the WebAuthn-anchored
        credential <Wordmark /> carries on the user's passkey. Requires
        <strong>OpenSSH 8.4+</strong>.
      </p>
      <ServerSetupGuide />
    </div>
  </details>

  <details class="setup-card">
    <summary>Endpoint Setup</summary>
    <div class="setup-body">
      <p class="hint">
        An <strong>endpoint</strong> is a remote host <Wordmark /> can broker sessions to. Each entry
        carries a label, address, and a few policy controls that govern how passkey ceremonies and agent
        forwarding work for sessions to that host.
      </p>
      <ol class="steps">
        <li>
          Go to <strong>Settings → Endpoints</strong> and click <em>Add Endpoint</em>.
        </li>
        <li>
          Fill in the fields (see reference below) and save. The endpoint shows up in your sidebar
          immediately; click <em>Connect</em> to open a session.
        </li>
      </ol>

      <h4>Field Reference</h4>

      <p class="hint">
        <strong>Label</strong> — A short, human-readable name. Shown in the sidebar, audit log, and
        anywhere this endpoint is referenced. Use whatever distinguishes it for you (<em
          >"prod-db-1"</em
        >, <em>"staging-bastion"</em>, <em>"my-vps"</em>).
      </p>

      <p class="hint">
        <strong>Address</strong> — Standard SSH target in the form <code>[user@]host[:port]</code>.
        If the user is omitted, <code>shellwatch</code> is assumed (and rendered as a gray prefix
        with a warning on blur). The port defaults to <code>22</code>.
      </p>

      <p class="hint">
        <strong>Description</strong> — Optional free-form text (up to 1000 chars).
        <em>Especially important for MCP-driven sessions:</em>
        this string is surfaced to AI agents alongside the endpoint in the
        <code>list_endpoints</code>
        tool response, so it's how the agent learns the
        <em>context</em> of a server. Treat it as a one-paragraph operator brief — e.g.
        <em
          >"Production database host, runs Postgres 15. /srv/data holds nightly dumps; do not touch
          /etc/postgresql without a maintenance window."</em
        > A well-written description is the difference between an agent making a sensible decision and
        one acting blind.
      </p>

      <p class="hint">
        <strong>User Verification</strong> — Controls the WebAuthn <code>userVerification</code>
        option on every passkey ceremony to this endpoint. Default
        <code>required</code> (PIN / biometric always enforced). See the deep-dive below.
      </p>

      <p class="hint">
        <strong>SSH Agent Forwarding</strong> — When on, <Wordmark /> requests SSH-agent forwarding on
        the session so the user's broker socket is forwarded into the remote host. Required for onward
        auth — using <code>ssh</code> / <code>git</code> from the remote host, and for the
        <Wordmark /> PAM module to gate <code>sudo</code>. Default
        <em>on</em>; turn off only when the target sshd disallows forwarding (returns
        <code>request forwarding denied</code> at handshake).
      </p>

      <h4>User Verification (deep-dive)</h4>
      <p class="hint">
        UV is <em>client-side</em> by default — <Wordmark /> requests it from the authenticator and rejects
        responses missing the bit, but the authoritative gate is the
        <strong>OpenSSH server</strong>. To make UV load-bearing, the target sshd must also enforce
        it:
      </p>
      <ul class="steps">
        <li>
          <strong>Globally</strong> in <code>sshd_config</code>:
          <code>PubkeyAuthOptions verify-required</code>
        </li>
        <li>
          <strong>Per-key</strong> in <code>~/.ssh/authorized_keys</code>:
          <code>verify-required sk-ecdsa-sha2-nistp256@openssh.com AAAA…</code>
        </li>
      </ul>
      <p class="hint">
        Either source makes sshd reject signatures without the UV bit (<code
          >SSH_SK_USER_VERIFICATION_REQD</code
        >, <code>0x04</code>), logging
        <code>user verification requirement not met</code>.
      </p>
    </div>
  </details>

  <details class="setup-card">
    <summary>MCP Client Setup</summary>
    <div class="setup-body">
      <p class="hint">
        Agents (Claude Desktop, Cursor, etc.) talk to <Wordmark /> via the Model Context Protocol at
        <code>/mcp</code>. <Wordmark /> exposes session-broker tools to the agent; any session it opens
        shows up in your audit log just like a UI-driven one.
      </p>
      <h4>OAuth (recommended)</h4>
      <ol class="steps">
        <li>
          Point your MCP client at <code>{mcpUrl}</code>.
        </li>
        <li>
          The client redirects through <Wordmark />'s OAuth flow on first use; approve with a
          passkey.
        </li>
        <li>
          <Wordmark /> mints a scoped API key on the fly and injects it into the agent's session — no
          manual key handling, key rotates per session.
        </li>
      </ol>

      <h4>Direct (no-OAuth clients)</h4>
      <ol class="steps">
        <li>
          Go to <strong>Settings → API Keys</strong> and click <em>Generate API Key</em>.
        </li>
        <li>
          Give it a label and enable the <code>mcp</code> scope.
        </li>
        <li>
          Configure your client to send the key as an HTTP
          <code>Authorization: Bearer &lt;KEY&gt;</code> header against <code>{mcpUrl}</code>.
        </li>
      </ol>
    </div>
  </details>

  <details class="setup-card">
    <summary>ShellWatch Agent Setup</summary>
    <div class="setup-body">
      <p class="hint">
        <code>shellwatch-agent</code> is a thin local SSH agent that runs on your workstation and
        brokers every <code>SSH_AGENTC_SIGN_REQUEST</code> through <Wordmark />. With it running,
        ordinary <code>ssh</code>, <code>git</code>, <code>scp</code>, and friends prompt your
        passkey via <Wordmark /> instead of needing a private key on disk. Requires
        <strong>OpenSSH 10.3+</strong> on the client — earlier versions silently drop webauthn-sk signatures
        when forwarded through an agent.
      </p>
      <ol class="steps">
        <li>
          Install <code>shellwatch-agent</code> from
          <a href={AGENT_RELEASES_URL} target="_blank" rel="noopener noreferrer">GitHub Releases</a> (binary
          releases for macOS / Linux).
        </li>
        <li>
          Generate an API key with the <code>agent</code> scope in
          <strong>Settings → API Keys</strong> and hand it to the agent at install time.
        </li>
        <li>
          Export <code>SSH_AUTH_SOCK</code> to point at the agent's socket (the installer prints the exact
          line for your shell).
        </li>
        <li>
          Run <code>ssh user@host</code>. <Wordmark /> intercepts the signing request and prompts your
          passkey; the signature is forwarded to sshd as a normal SSH agent response.
        </li>
      </ol>
    </div>
  </details>

  <details class="setup-card">
    <summary>ShellWatch PAM Setup</summary>
    <div class="setup-body">
      <p class="hint">
        <code>pam-ssh-agent-webauthn</code> is a PAM module that gates privileged actions on the
        remote host — <code>sudo</code>, <code>su</code>, console login, anything PAM authenticates
        — on a fresh passkey signature brokered through <Wordmark />.
      </p>
      <ol class="steps">
        <li>
          Build the module on the remote host from
          <a href={PAM_REPO_URL} target="_blank" rel="noopener noreferrer"
            >github.com/rado0x54/pam-ssh-agent-webauthn</a
          > (Go binary, single static dependency).
        </li>
        <li>
          Drop it into your PAM config — typically <code>/etc/pam.d/sudo</code> — as
          <code>auth required pam_ssh_agent_webauthn.so</code>.
        </li>
        <li>
          The endpoint must be reached with <strong>SSH agent forwarding enabled</strong> so
          <code>SSH_AUTH_SOCK</code> is forwarded into the session — the PAM module reads from that
          socket. Toggle it per endpoint in <Wordmark /> under
          <strong>Settings → Endpoints</strong>; it's <em>on</em> by default for new endpoints.
        </li>
        <li>
          Try <code>sudo &lt;cmd&gt;</code>: instead of a password prompt the user gets a passkey
          ceremony in <Wordmark />.
        </li>
      </ol>
    </div>
  </details>

  <p class="docs-footer">
    Full setup walkthroughs and reference at
    <a href={DOCS_URL} target="_blank" rel="noopener noreferrer">docs.shellwatch.ai</a>.
  </p>
</section>

<style>
  .setup-page {
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
  }

  .setup-card {
    border: 1px solid var(--border);
    border-radius: 8px;
    background: var(--bg-primary);
    overflow: hidden;
  }

  .setup-card > summary {
    list-style: none;
    cursor: pointer;
    padding: 0.85rem 1rem;
    font-size: 0.95rem;
    font-weight: 600;
    color: var(--on-surface);
    display: flex;
    align-items: center;
    gap: 0.6rem;
    user-select: none;
    transition: background-color 0.15s;
  }

  .setup-card > summary::-webkit-details-marker {
    display: none;
  }

  .setup-card > summary::before {
    content: "▸";
    font-size: 0.75rem;
    color: var(--text-muted);
    transition: transform 0.15s;
    width: 0.75rem;
    text-align: center;
  }

  .setup-card[open] > summary::before {
    transform: rotate(90deg);
  }

  .setup-card > summary:hover {
    background: color-mix(in srgb, var(--on-surface) 4%, transparent);
  }

  .setup-card[open] > summary {
    border-bottom: 1px solid var(--border);
  }

  .setup-body {
    padding: 0.85rem 1rem 1rem;
  }

  .setup-body h4 {
    font-size: 0.7rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--text-muted);
    margin: 1.25rem 0 0.5rem;
  }

  .setup-body h4:first-of-type {
    margin-top: 1rem;
  }

  .hint {
    font-size: 0.85rem;
    color: var(--text-muted);
    line-height: 1.55;
    margin: 0 0 0.75rem;
  }

  .hint code,
  .steps code {
    font-family: var(--font-mono);
    font-size: 0.85em;
    color: var(--primary);
  }

  .steps a {
    color: var(--accent);
    text-decoration: none;
  }

  .steps a:hover {
    text-decoration: underline;
  }

  .steps {
    margin: 0 0 0.75rem;
    padding-left: 1.5rem;
    font-size: 0.85rem;
    color: var(--text-muted);
    line-height: 1.6;
  }

  .steps li {
    margin-bottom: 0.4rem;
  }

  .steps li:last-child {
    margin-bottom: 0;
  }

  .docs-footer {
    margin-top: 0.5rem;
    font-size: 0.8rem;
    color: var(--text-muted);
    text-align: center;
  }

  .docs-footer a {
    color: var(--accent);
    text-decoration: none;
  }

  .docs-footer a:hover {
    text-decoration: underline;
  }
</style>
