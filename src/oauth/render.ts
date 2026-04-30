import type { ResolvedScopes } from "./routes.js";

const HTML_ESCAPES: Record<string, string> = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
};

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => HTML_ESCAPES[c] ?? c);
}

export type AuthorizeMode = "existing" | "create";

export interface RenderAuthorizePageParams {
  clientId: string;
  redirectUri: string;
  state: string;
  codeChallenge: string;
  codeChallengeMethod: string;
  /** Resolved scope set + raw client request, plumbed through from routes.ts. */
  resolved: ResolvedScopes;
  /** Shown in a red banner above the submit button when a prior submit failed. */
  errorMessage?: string;
  /**
   * Which radio tab is pre-selected. Defaults to "create" — the common path
   * for first-time setup is "log in, mint a key for this client", and forcing
   * users to know what an API key is before they get one is hostile.
   */
  mode?: AuthorizeMode;
  /** Preserves the "new key" label input value across re-renders on error. */
  newKeyLabel?: string;
}

export function renderAuthorizePage(p: RenderAuthorizePageParams): string {
  const mode: AuthorizeMode = p.mode === "existing" ? "existing" : "create";
  const isExisting = mode === "existing";
  const isCreate = mode === "create";
  const issuedList = p.resolved.issued.join(" ");
  const errorBanner = p.errorMessage
    ? `<div class="error">${escapeHtml(p.errorMessage)}</div>`
    : "";

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>ShellWatch — Authorize client</title>
<link rel="icon" type="image/png" href="/favicon.png" />
<link rel="preconnect" href="https://fonts.googleapis.com" />
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Geist:wght@400;500;600;700&family=Geist+Mono:wght@400;500;600&display=swap" />
<style>
  :root {
    --surface-dim: #0e0e0e;
    --surface-container-low: #131313;
    --surface-container: #1a1a1a;
    --surface-container-high: #1f1f1f;
    --surface-container-highest: #262626;
    --primary: #69f6b8;
    --primary-container: #06b77f;
    --on-primary-container: #002919;
    --secondary: #f8a010;
    --error: #ff5a5a;
    --on-surface: #f2f2f2;
    --on-surface-variant: #adaaaa;
    --on-surface-faint: #6a6866;
    --outline-variant: rgba(73, 72, 71, 0.15);
    --grad-primary: linear-gradient(135deg, #69f6b8 0%, #06b77f 100%);
    --glow-primary: 0 0 24px rgba(105, 246, 184, 0.10);
    --glow-primary-strong: 0 0 32px rgba(105, 246, 184, 0.22);
    --glow-secondary: 0 0 24px rgba(248, 160, 16, 0.14);
    --glow-error: 0 0 24px rgba(255, 90, 90, 0.14);
    --font-display: "Geist", system-ui, sans-serif;
    --font-ui: "Geist", system-ui, sans-serif;
    --font-mono: "Geist Mono", ui-monospace, monospace;
  }
  *, *::before, *::after { box-sizing: border-box; border-radius: 0 !important; }
  body {
    font-family: var(--font-ui);
    background: var(--surface-dim);
    color: var(--on-surface);
    line-height: 1.5;
    min-height: 100vh;
    display: flex;
    align-items: flex-start;
    justify-content: center;
    padding: 3rem 1rem;
    margin: 0;
    -webkit-font-smoothing: antialiased;
  }
  .card {
    background: var(--surface-container-low);
    padding: 2.4rem;
    width: 100%;
    max-width: 520px;
  }

  .brand {
    display: flex;
    align-items: center;
    gap: 0.6rem;
    margin-bottom: 1.8rem;
  }
  .brand img { width: 32px; height: 32px; }
  .wordmark {
    font-family: var(--font-display);
    font-size: 1.25rem;
    font-weight: 600;
    letter-spacing: -0.01em;
    text-transform: uppercase;
  }
  .wordmark .shell { color: #12a26f; }
  .wordmark .watch { color: #f0efea; }

  h1 {
    font-family: var(--font-display);
    font-size: 1.5rem;
    font-weight: 600;
    letter-spacing: -0.02em;
    margin: 0 0 0.4rem;
    color: var(--on-surface);
  }
  p { margin: 0.5rem 0; color: var(--on-surface); }
  code {
    font-family: var(--font-mono);
    background: var(--surface-container-highest);
    padding: 0.1em 0.35em;
    color: var(--primary);
    font-size: 0.9em;
  }
  .subtitle {
    color: var(--on-surface-variant);
    font-size: 0.875rem;
    margin-bottom: 1.25rem;
  }

  .error {
    background: rgba(255, 90, 90, 0.08);
    border: 1px solid rgba(255, 90, 90, 0.25);
    color: var(--error);
    padding: 0.75rem 0.9rem;
    margin: 1rem 0;
    font-size: 0.875rem;
    box-shadow: var(--glow-error);
  }

  .danger {
    background: var(--surface-container);
    border-left: 2px solid var(--secondary);
    padding: 1rem 1.15rem;
    margin: 1.25rem 0;
    box-shadow: var(--glow-secondary);
  }
  .danger h2 {
    font-family: var(--font-mono);
    font-size: 0.65rem;
    color: var(--secondary);
    margin: 0 0 0.6rem;
    text-transform: uppercase;
    letter-spacing: 0.14em;
    font-weight: 500;
  }
  .danger p { margin: 0.4rem 0; font-size: 0.875rem; color: var(--on-surface); }
  .danger strong { color: var(--secondary); }
  .danger .url {
    font-family: var(--font-mono);
    font-size: 0.85rem;
    background: var(--surface-container-highest);
    padding: 0.5rem 0.7rem;
    word-break: break-all;
    display: block;
    margin: 0.6rem 0;
    color: var(--primary);
  }

  .meta {
    font-family: var(--font-mono);
    font-size: 0.8rem;
    color: var(--on-surface-variant);
    background: var(--surface-container);
    padding: 0.75rem 0.9rem;
    word-break: break-all;
    margin-top: 1rem;
  }
  .meta strong {
    color: var(--on-surface-variant);
    font-weight: 500;
    text-transform: uppercase;
    letter-spacing: 0.14em;
    font-size: 0.65rem;
    display: inline-block;
    margin-right: 0.4rem;
  }
  .meta div + div { margin-top: 0.25rem; }

  .mode-toggle {
    display: flex;
    margin: 1.5rem 0 0;
    background: var(--surface-container);
  }
  .mode-option {
    flex: 1;
    padding: 0.75rem 0.8rem;
    text-align: center;
    cursor: pointer;
    color: var(--on-surface-variant);
    font-family: var(--font-mono);
    font-size: 0.65rem;
    text-transform: uppercase;
    letter-spacing: 0.14em;
    font-weight: 500;
    user-select: none;
    position: relative;
    box-shadow: inset 0 -2px 0 transparent;
    transition: color 0.15s, box-shadow 0.15s;
  }
  .mode-option:hover { color: var(--on-surface); }
  .mode-option input { position: absolute; opacity: 0; pointer-events: none; }
  .mode-option.selected {
    color: var(--primary);
    box-shadow: inset 0 -2px 0 var(--primary);
  }

  .field { margin: 1.2rem 0; }
  .field[hidden] { display: none; }
  .field label {
    display: block;
    margin-bottom: 0.4rem;
    font-family: var(--font-mono);
    font-size: 0.65rem;
    font-weight: 500;
    color: var(--on-surface-variant);
    text-transform: uppercase;
    letter-spacing: 0.14em;
  }
  .field input[type="password"],
  .field input[type="text"] {
    width: 100%;
    padding: 0.5rem 0;
    font-family: var(--font-mono);
    font-size: 0.95rem;
    background: transparent;
    border: 0;
    border-bottom: 1px solid var(--outline-variant);
    color: var(--on-surface);
    outline: none;
    transition: border-color 0.15s, box-shadow 0.15s;
  }
  .field input[type="text"] { font-family: var(--font-ui); }
  .field input::placeholder { color: var(--on-surface-faint); }
  .field input:focus {
    border-bottom-color: var(--primary);
    box-shadow: 0 2px 0 -1px var(--primary);
  }

  .help { font-size: 0.8rem; color: var(--on-surface-variant); margin-top: 0.5rem; }
  .help code { font-size: 0.85em; }

  button {
    padding: 0.75rem 1.4rem;
    background: var(--grad-primary);
    color: var(--on-primary-container);
    border: 0;
    cursor: pointer;
    font-family: var(--font-ui);
    font-size: 0.875rem;
    font-weight: 600;
    letter-spacing: 0.02em;
    width: 100%;
    margin-top: 0.8rem;
    box-shadow: var(--glow-primary);
    transition: box-shadow 0.2s;
  }
  button:hover { box-shadow: var(--glow-primary-strong); }

  ::selection { background: rgba(105, 246, 184, 0.25); color: var(--on-surface); }
</style>
</head>
<body>
<div class="card">
<div class="brand">
  <img src="/logo.svg" alt="" />
  <span class="wordmark"><span class="shell">SHELL</span><span class="watch">WATCH</span></span>
</div>
<h1>Authorize client</h1>
<p class="subtitle">A client is requesting an API key for this ShellWatch instance.</p>

<div class="danger">
  <h2>Review before you continue</h2>
  <p>If you authorize, your API key will be delivered to the URL below. <strong>ShellWatch does NOT verify this URL</strong> — it was supplied by the client and could point anywhere on the internet.</p>
  <span class="url">${escapeHtml(p.redirectUri)}</span>
  <p>Only proceed if you recognize this URL as the callback for the client you are setting up. If you did not start this flow yourself, close this page now.</p>
</div>

<div class="meta">
  <div><strong>Client ID:</strong> ${escapeHtml(p.clientId)}</div>
  <div><strong>Issued scopes:</strong> ${escapeHtml(issuedList)}</div>
  ${p.resolved.rawScope ? `<div><strong>Requested:</strong> ${escapeHtml(p.resolved.rawScope)}</div>` : ""}
  ${p.resolved.rawResource ? `<div><strong>Resource:</strong> ${escapeHtml(p.resolved.rawResource)}</div>` : ""}
</div>

<form method="POST" action="/oauth/authorize">
  <div class="mode-toggle" role="tablist">
    <label class="mode-option${isCreate ? " selected" : ""}" data-mode="create">
      <input type="radio" name="mode" value="create"${isCreate ? " checked" : ""} />
      <span>Create new key</span>
    </label>
    <label class="mode-option${isExisting ? " selected" : ""}" data-mode="existing">
      <input type="radio" name="mode" value="existing"${isExisting ? " checked" : ""} />
      <span>Use existing key</span>
    </label>
  </div>

  <div class="field mode-create"${isCreate ? "" : " hidden"}>
    <label for="new_key_label">Name for the new API key</label>
    <input type="text" id="new_key_label" name="new_key_label" autocomplete="off"${isCreate ? " autofocus" : ""} placeholder="e.g. Claude Desktop" value="${escapeHtml(p.newKeyLabel ?? "")}" />
    <div class="help">A fresh key with the issued scopes above will be created. You can revoke it any time in Settings → API Keys.</div>
  </div>

  <div class="field mode-existing"${isExisting ? "" : " hidden"}>
    <label for="api_key">ShellWatch API key</label>
    <input type="password" id="api_key" name="api_key" autocomplete="off"${isExisting ? " autofocus" : ""} placeholder="sw_..." />
    <div class="help">Paste an API key from Settings → API Keys. The key must include the issued scopes above. <strong>Note:</strong> the access token returned to the client is the pasted key verbatim, so any extra scopes on it are forwarded too.</div>
  </div>

  <input type="hidden" name="client_id" value="${escapeHtml(p.clientId)}" />
  <input type="hidden" name="redirect_uri" value="${escapeHtml(p.redirectUri)}" />
  <input type="hidden" name="state" value="${escapeHtml(p.state)}" />
  <input type="hidden" name="code_challenge" value="${escapeHtml(p.codeChallenge)}" />
  <input type="hidden" name="code_challenge_method" value="${escapeHtml(p.codeChallengeMethod)}" />
  ${p.resolved.rawScope !== undefined ? `<input type="hidden" name="scope" value="${escapeHtml(p.resolved.rawScope)}" />` : ""}
  ${p.resolved.rawResource ? `<input type="hidden" name="resource" value="${escapeHtml(p.resolved.rawResource)}" />` : ""}
  ${errorBanner}
  <button type="submit">Authorize</button>
</form>
</div>
<script>
  (function () {
    var radios = document.querySelectorAll('input[name="mode"]');
    var existingBlock = document.querySelector('.field.mode-existing');
    var createBlock = document.querySelector('.field.mode-create');
    var apiKey = document.getElementById('api_key');
    var newKeyLabel = document.getElementById('new_key_label');
    var options = document.querySelectorAll('.mode-option');
    function update() {
      var checked = document.querySelector('input[name="mode"]:checked');
      var mode = checked ? checked.value : 'create';
      options.forEach(function (o) {
        o.classList.toggle('selected', o.getAttribute('data-mode') === mode);
      });
      if (mode === 'create') {
        existingBlock.hidden = true;
        createBlock.hidden = false;
        apiKey.required = false;
        newKeyLabel.required = true;
        setTimeout(function () { newKeyLabel.focus(); }, 0);
      } else {
        existingBlock.hidden = false;
        createBlock.hidden = true;
        apiKey.required = true;
        newKeyLabel.required = false;
        setTimeout(function () { apiKey.focus(); }, 0);
      }
    }
    radios.forEach(function (r) { r.addEventListener('change', update); });
    update();
  })();
</script>
</body>
</html>`;
}
