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
  /** Shown in a red banner above the submit button when a prior submit failed. */
  errorMessage?: string;
  /** Which radio tab is pre-selected. Defaults to "existing". */
  mode?: AuthorizeMode;
  /** Preserves the "new key" label input value across re-renders on error. */
  newKeyLabel?: string;
}

export function renderAuthorizePage(p: RenderAuthorizePageParams): string {
  const mode: AuthorizeMode = p.mode === "create" ? "create" : "existing";
  const isExisting = mode === "existing";
  const isCreate = mode === "create";
  const errorBanner = p.errorMessage
    ? `<div class="error">${escapeHtml(p.errorMessage)}</div>`
    : "";

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>ShellWatch — Authorize MCP client</title>
<style>
  :root {
    --bg-primary: #1a1a2e;
    --bg-secondary: #16213e;
    --border: #2a2a4a;
    --text-primary: #e0e0e0;
    --text-muted: #8888aa;
    --accent: #4a9eff;
    --accent-hover: #3b8de6;
    --amber: #fbbf24;
    --red: #f87171;
  }
  * { box-sizing: border-box; }
  body {
    font-family: system-ui, -apple-system, sans-serif;
    background: var(--bg-primary);
    color: var(--text-primary);
    line-height: 1.5;
    min-height: 100vh;
    display: flex;
    align-items: flex-start;
    justify-content: center;
    padding: 3rem 1rem;
    margin: 0;
  }
  .card {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 2rem 2.25rem;
    width: 100%;
    max-width: 520px;
  }
  h1 { font-size: 1.4rem; font-weight: 600; margin: 0 0 0.5rem; color: var(--text-primary); }
  p { margin: 0.5rem 0; color: var(--text-primary); }
  code { font-family: ui-monospace, monospace; background: var(--bg-primary); padding: 0.1em 0.35em; border-radius: 3px; color: var(--text-primary); }
  .subtitle { color: var(--text-muted); font-size: 0.9rem; margin-bottom: 1.25rem; }

  .error {
    background: rgba(248, 113, 113, 0.12);
    border: 1px solid rgba(248, 113, 113, 0.4);
    color: var(--red);
    padding: 0.75rem 0.9rem;
    border-radius: 6px;
    margin: 1rem 0;
    font-size: 0.9rem;
  }

  .danger {
    background: rgba(251, 191, 36, 0.08);
    border: 1px solid rgba(251, 191, 36, 0.35);
    border-radius: 8px;
    padding: 1rem 1.15rem;
    margin: 1.25rem 0;
  }
  .danger h2 {
    font-size: 0.75rem;
    color: var(--amber);
    margin: 0 0 0.5rem;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    font-weight: 600;
  }
  .danger p { margin: 0.4rem 0; font-size: 0.9rem; color: var(--text-primary); }
  .danger strong { color: var(--amber); }
  .danger .url {
    font-family: ui-monospace, monospace;
    font-size: 0.9rem;
    background: var(--bg-primary);
    border: 1px solid var(--border);
    padding: 0.5rem 0.7rem;
    border-radius: 4px;
    word-break: break-all;
    display: block;
    margin: 0.5rem 0;
    color: var(--text-primary);
    font-weight: 500;
  }

  .meta {
    font-size: 0.85rem;
    color: var(--text-muted);
    background: var(--bg-primary);
    border: 1px solid var(--border);
    padding: 0.75rem 0.9rem;
    border-radius: 6px;
    word-break: break-all;
    margin-top: 1rem;
  }
  .meta strong { color: var(--text-primary); font-weight: 600; }
  .meta div + div { margin-top: 0.25rem; }

  .mode-toggle {
    display: flex;
    margin: 1.5rem 0 0;
    border: 1px solid var(--border);
    border-radius: 6px;
    overflow: hidden;
    background: var(--bg-primary);
  }
  .mode-option {
    flex: 1;
    padding: 0.7rem 0.8rem;
    text-align: center;
    cursor: pointer;
    color: var(--text-muted);
    font-size: 0.9rem;
    user-select: none;
    position: relative;
    transition: background 0.1s, color 0.1s;
  }
  .mode-option + .mode-option { border-left: 1px solid var(--border); }
  .mode-option:hover { color: var(--text-primary); }
  .mode-option input { position: absolute; opacity: 0; pointer-events: none; }
  .mode-option.selected { background: var(--accent); color: #fff; font-weight: 600; }

  .field { margin: 1rem 0; }
  .field[hidden] { display: none; }
  .field label {
    display: block;
    margin-bottom: 0.4rem;
    font-weight: 500;
    color: var(--text-primary);
    font-size: 0.9rem;
  }
  .field input[type="password"],
  .field input[type="text"] {
    width: 100%;
    padding: 0.6rem 0.75rem;
    font-family: ui-monospace, monospace;
    font-size: 0.95rem;
    background: var(--bg-primary);
    border: 1px solid var(--border);
    color: var(--text-primary);
    border-radius: 6px;
    outline: none;
    transition: border-color 0.1s;
  }
  .field input[type="text"] { font-family: inherit; }
  .field input::placeholder { color: var(--text-muted); }
  .field input:focus { border-color: var(--accent); }

  .help { font-size: 0.8rem; color: var(--text-muted); margin-top: 0.4rem; }
  .help code { font-size: 0.85em; }

  button {
    padding: 0.7rem 1.4rem;
    background: var(--accent);
    color: #fff;
    border: 0;
    border-radius: 6px;
    cursor: pointer;
    font-size: 0.95rem;
    font-weight: 500;
    width: 100%;
    margin-top: 0.5rem;
    transition: background 0.1s;
  }
  button:hover { background: var(--accent-hover); }
</style>
</head>
<body>
<div class="card">
<h1>Authorize MCP client</h1>
<p class="subtitle">A client is requesting access to this ShellWatch instance's <code>/mcp</code> endpoint.</p>

<div class="danger">
  <h2>Review before you continue</h2>
  <p>If you authorize, your API key will be delivered to the URL below. <strong>ShellWatch does NOT verify this URL</strong> — it was supplied by the client and could point anywhere on the internet.</p>
  <span class="url">${escapeHtml(p.redirectUri)}</span>
  <p>Only proceed if you recognize this URL as the callback for the MCP client you are setting up. If you did not start this flow yourself, close this page now.</p>
</div>

<div class="meta">
  <div><strong>Client ID:</strong> ${escapeHtml(p.clientId)}</div>
</div>

<form method="POST" action="/oauth/authorize">
  <div class="mode-toggle" role="tablist">
    <label class="mode-option${isExisting ? " selected" : ""}" data-mode="existing">
      <input type="radio" name="mode" value="existing"${isExisting ? " checked" : ""} />
      <span>Use existing key</span>
    </label>
    <label class="mode-option${isCreate ? " selected" : ""}" data-mode="create">
      <input type="radio" name="mode" value="create"${isCreate ? " checked" : ""} />
      <span>Create new key</span>
    </label>
  </div>

  <div class="field mode-existing"${isExisting ? "" : " hidden"}>
    <label for="api_key">ShellWatch API key</label>
    <input type="password" id="api_key" name="api_key" autocomplete="off"${isExisting ? " autofocus" : ""} placeholder="sw_..." />
    <div class="help">Paste an API key from Settings → API Keys. The key must have the <code>mcp</code> scope.</div>
  </div>

  <div class="field mode-create"${isCreate ? "" : " hidden"}>
    <label for="new_key_label">Name for the new API key</label>
    <input type="text" id="new_key_label" name="new_key_label" autocomplete="off"${isCreate ? " autofocus" : ""} placeholder="e.g. Claude Desktop" value="${escapeHtml(p.newKeyLabel ?? "")}" />
    <div class="help">A fresh key with the <code>mcp</code> scope will be created for this client. You can revoke it any time in Settings → API Keys.</div>
  </div>

  <input type="hidden" name="client_id" value="${escapeHtml(p.clientId)}" />
  <input type="hidden" name="redirect_uri" value="${escapeHtml(p.redirectUri)}" />
  <input type="hidden" name="state" value="${escapeHtml(p.state)}" />
  <input type="hidden" name="code_challenge" value="${escapeHtml(p.codeChallenge)}" />
  <input type="hidden" name="code_challenge_method" value="${escapeHtml(p.codeChallengeMethod)}" />
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
      var mode = checked ? checked.value : 'existing';
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
