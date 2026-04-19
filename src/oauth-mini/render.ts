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
  * { box-sizing: border-box; }
  body { font-family: system-ui, -apple-system, sans-serif; max-width: 520px; margin: 3em auto; padding: 0 1em; color: #222; line-height: 1.5; }
  .card { border: 1px solid #ddd; border-radius: 8px; padding: 1.5em; background: #fff; }
  h1 { font-size: 1.2em; margin: 0 0 0.5em; }
  p { margin: 0.5em 0; }
  .error { background: #fde8e8; border: 1px solid #f5a3a3; color: #a30000; padding: 0.75em; border-radius: 4px; margin: 0 0 1em; font-size: 0.9em; }
  .danger { background: #fff0f0; border: 2px solid #d93030; border-radius: 6px; padding: 1em 1.15em; margin: 1.25em 0 0.5em; }
  .danger h2 { font-size: 1em; color: #a30000; margin: 0 0 0.5em; text-transform: uppercase; letter-spacing: 0.03em; }
  .danger p { margin: 0.35em 0; }
  .danger .url { font-family: ui-monospace, monospace; font-size: 0.95em; background: #fff; border: 1px solid #f5c2c2; padding: 0.45em 0.6em; border-radius: 4px; word-break: break-all; display: inline-block; margin-top: 0.35em; }
  .danger .url.attention { display: block; font-weight: 600; }
  .meta { font-size: 0.85em; color: #555; background: #f6f6f6; padding: 0.75em; border-radius: 4px; word-break: break-all; margin-top: 0.75em; }
  .meta div + div { margin-top: 0.25em; }
  .mode-toggle { display: flex; margin: 1.25em 0 0; border: 1px solid #bbb; border-radius: 6px; overflow: hidden; }
  .mode-option { flex: 1; padding: 0.65em 0.8em; text-align: center; cursor: pointer; background: #f6f6f6; font-size: 0.9em; user-select: none; position: relative; }
  .mode-option + .mode-option { border-left: 1px solid #bbb; }
  .mode-option input { position: absolute; opacity: 0; pointer-events: none; }
  .mode-option.selected { background: #e6f0fa; color: #0066cc; font-weight: 600; }
  .field { margin: 1em 0; }
  .field[hidden] { display: none; }
  .field label { display: block; margin-bottom: 0.35em; font-weight: 600; }
  .field input[type="password"], .field input[type="text"] { width: 100%; padding: 0.55em 0.65em; font-family: ui-monospace, monospace; font-size: 0.95em; border: 1px solid #bbb; border-radius: 4px; }
  .field input[type="text"] { font-family: inherit; }
  .field input:focus { outline: 2px solid #0066cc; outline-offset: -1px; border-color: #0066cc; }
  .help { font-size: 0.8em; color: #666; margin-top: 0.35em; }
  button { padding: 0.65em 1.25em; background: #0066cc; color: #fff; border: 0; border-radius: 4px; cursor: pointer; font-size: 1em; font-weight: 500; }
  button:hover { background: #0052a3; }
</style>
</head>
<body>
<div class="card">
<h1>Authorize MCP client</h1>
<p>A client is requesting access to this ShellWatch instance's <code>/mcp</code> endpoint.</p>

<div class="danger">
  <h2>Review before you continue</h2>
  <p>If you authorize, your API key will be delivered to the URL below. <strong>ShellWatch does NOT verify this URL</strong> — it was supplied by the client and could point anywhere on the internet.</p>
  <p><span class="url attention">${escapeHtml(p.redirectUri)}</span></p>
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
