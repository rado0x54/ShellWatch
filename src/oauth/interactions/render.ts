/**
 * Minimal HTML renderers for the OAuth interaction pages. Server-rendered
 * static pages with a pinch of inline JavaScript — no SvelteKit, no
 * bundler, no client framework. The flow is rare enough (user adds a new
 * MCP client once in a while) that shipping 500kb of SPA just for a
 * two-page flow would be out of proportion.
 *
 * Styling is spartan by design. A follow-up can theme these to match the
 * main UI without touching the interaction protocol.
 */

interface LoginViewModel {
  uid: string;
  clientName: string;
  rpId: string;
}

interface ConsentViewModel {
  uid: string;
  clientName: string;
  accountName: string;
  scopes: string[];
  redirectUri: string;
  resource: string;
}

function esc(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/**
 * Safe embedding of a JS value inside a `<script>` tag via
 * `JSON.stringify`. `JSON.stringify` alone does NOT escape `</` — if
 * the serialised value ever contained `</script>`, the browser's HTML
 * parser would close the script element and execute arbitrary markup.
 * The `\u003c` replacement is the standard mitigation.
 */
function safeJsonEmbed(value: unknown): string {
  return JSON.stringify(value).replace(/</g, "\\u003c");
}

const baseStyles = /* css */ `
  :root { color-scheme: dark light; }
  body {
    font: 14px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif;
    margin: 0; padding: 40px 20px;
    background: #0f1419; color: #e6edf3;
    min-height: 100vh;
  }
  .card {
    max-width: 480px; margin: 0 auto;
    background: #161b22; border: 1px solid #30363d; border-radius: 8px;
    padding: 28px 32px;
  }
  h1 { margin: 0 0 8px; font-size: 20px; font-weight: 600; }
  .muted { color: #8b949e; font-size: 13px; }
  .muted-label { color: #8b949e; font-size: 11px; text-transform: uppercase; letter-spacing: .04em; }
  .client-name { color: #e6edf3; font-weight: 500; }
  button {
    appearance: none; border: 0; cursor: pointer; font: inherit;
    padding: 10px 16px; border-radius: 6px;
    margin-right: 8px;
  }
  button.primary { background: #238636; color: white; }
  button.primary:hover { background: #2ea043; }
  button.primary:disabled { background: #30363d; cursor: not-allowed; }
  button.secondary { background: transparent; color: #e6edf3; border: 1px solid #30363d; }
  button.secondary:hover { border-color: #8b949e; }
  ul.scopes { list-style: none; padding: 0; margin: 16px 0; }
  ul.scopes li {
    padding: 8px 12px; background: #0d1117; border: 1px solid #30363d;
    border-radius: 4px; margin-bottom: 6px; font-family: monospace; font-size: 13px;
  }
  .meta-row { display: flex; gap: 12px; padding: 8px 0; border-bottom: 1px solid #21262d; }
  .meta-row:last-child { border-bottom: 0; }
  .meta-row .muted-label { width: 88px; flex-shrink: 0; }
  .error { color: #f85149; font-size: 13px; margin-top: 8px; min-height: 1.5em; }
`;

export function renderLoginPage(vm: LoginViewModel): string {
  // We script inline on purpose — one file for one two-request flow. A
  // nonce-based CSP can be added when this page actually ships to
  // real users; the OAuth interaction view is low-surface enough that
  // the usual "ban inline scripts" payoff isn't big yet.
  return /* html */ `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ShellWatch — Sign in to continue</title>
<style>${baseStyles}</style>
</head>
<body>
<main class="card">
  <h1>Sign in with a passkey</h1>
  <p class="muted">
    <span class="client-name">${esc(vm.clientName)}</span>
    is requesting access to your ShellWatch account.
  </p>
  <div style="margin-top: 24px;">
    <button id="submit" class="primary" type="button">Use passkey</button>
    <button id="abort" class="secondary" type="button">Cancel</button>
  </div>
  <div id="err" class="error" role="alert"></div>
</main>
<script>
const uid = ${safeJsonEmbed(vm.uid)};
const rpId = ${safeJsonEmbed(vm.rpId)};
const errEl = document.getElementById("err");
const submitBtn = document.getElementById("submit");

function setError(msg) { errEl.textContent = msg; submitBtn.disabled = false; }

document.getElementById("abort").addEventListener("click", async () => {
  const res = await fetch("/oidc/interaction/" + uid + "/abort", { method: "POST" });
  const body = await res.json().catch(() => ({}));
  if (body.redirect) location.href = body.redirect;
});

submitBtn.addEventListener("click", async () => {
  setError("");
  submitBtn.disabled = true;
  try {
    const optsRes = await fetch("/api/webauthn/login/options", { method: "POST" });
    const opts = await optsRes.json();
    if (opts.error) { setError("No passkeys available: " + opts.error); return; }

    const toB = (s) => Uint8Array.from(atob(s.replace(/-/g,"+").replace(/_/g,"/") + "===".slice((s.length+3)%4)), c => c.charCodeAt(0));
    const fromB = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\\+/g,"-").replace(/\\//g,"_").replace(/=+$/,"");

    const cred = await navigator.credentials.get({
      publicKey: {
        challenge: toB(opts.challenge),
        rpId,
        allowCredentials: (opts.allowCredentials || []).map(c => ({ ...c, id: toB(c.id) })),
        userVerification: opts.userVerification || "required",
        timeout: opts.timeout || 60000,
      },
    });
    if (!cred) { setError("Passkey ceremony aborted."); return; }

    const body = {
      challengeId: opts.challengeId,
      credential: {
        id: cred.id,
        rawId: fromB(cred.rawId),
        type: cred.type,
        response: {
          clientDataJSON: fromB(cred.response.clientDataJSON),
          authenticatorData: fromB(cred.response.authenticatorData),
          signature: fromB(cred.response.signature),
          userHandle: cred.response.userHandle ? fromB(cred.response.userHandle) : undefined,
        },
      },
    };
    const verifyRes = await fetch("/oidc/interaction/" + uid + "/login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    const verifyJson = await verifyRes.json();
    if (!verifyRes.ok) { setError(verifyJson.error || "Sign-in failed"); return; }
    if (verifyJson.redirect) location.href = verifyJson.redirect;
    else setError("Unexpected server response.");
  } catch (e) {
    setError(e.message || String(e));
  }
});
</script>
</body>
</html>`;
}

export function renderConsentPage(vm: ConsentViewModel): string {
  const scopeItems = vm.scopes.map((s) => `<li>${esc(s)}</li>`).join("");
  return /* html */ `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ShellWatch — Authorize ${esc(vm.clientName)}</title>
<style>${baseStyles}</style>
</head>
<body>
<main class="card">
  <h1>Authorize <span class="client-name">${esc(vm.clientName)}</span>?</h1>
  <p class="muted">
    You are signed in as <strong>${esc(vm.accountName)}</strong>. The
    client below is requesting access to your ShellWatch resources.
  </p>

  <div class="meta-row">
    <span class="muted-label">Client name</span>
    <span>${esc(vm.clientName)}</span>
  </div>
  <div class="meta-row">
    <span class="muted-label">Redirect</span>
    <span style="font-family: monospace; font-size: 12px; word-break: break-all;">${esc(vm.redirectUri)}</span>
  </div>
  <div class="meta-row">
    <span class="muted-label">Resource</span>
    <span style="font-family: monospace; font-size: 12px; word-break: break-all;">${esc(vm.resource)}</span>
  </div>

  <p class="muted" style="margin-top: 20px;">
    <strong>Note:</strong> the client name and redirect above are
    reported by the client during registration and are not verified
    by ShellWatch. Make sure they match the app you intended to
    connect before approving.
  </p>

  <p class="muted-label" style="margin-top: 24px;">Scopes requested</p>
  <ul class="scopes">${scopeItems}</ul>

  <!-- The interaction UID (panva-generated, high-entropy, ~60s TTL)
       acts as an implicit CSRF token: it's unguessable, short-lived,
       and scoped to a single authorization request. A traditional
       hidden CSRF field would add nothing that the UID doesn't already
       provide. -->
  <div style="margin-top: 20px;">
    <button id="approve" class="primary" type="button">Approve</button>
    <button id="deny" class="secondary" type="button">Deny</button>
  </div>
  <div id="err" class="error" role="alert"></div>
</main>
<script>
const uid = ${safeJsonEmbed(vm.uid)};
async function postAction(path) {
  const res = await fetch("/oidc/interaction/" + uid + "/" + path, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: "{}",
    redirect: "manual",
  });
  if (res.status >= 300 && res.status < 400) {
    location.href = res.headers.get("location") || "/";
    return;
  }
  const body = await res.json().catch(() => ({}));
  if (body.redirect) { location.href = body.redirect; return; }
  if (res.redirected) { location.href = res.url; return; }
  document.getElementById("err").textContent = body.error || "Unexpected error";
}
document.getElementById("approve").addEventListener("click", () => postAction("confirm"));
document.getElementById("deny").addEventListener("click", () => postAction("abort"));
</script>
</body>
</html>`;
}
