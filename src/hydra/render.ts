// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * Server-rendered HTML for the Hydra login + consent providers and the error
 * page (#217). These are self-contained Fastify-served pages (not SvelteKit) so
 * the passkey ceremony works identically under `pnpm dev` (Vite on :3001) and a
 * built client served by Fastify — the OAuth redirect path never depends on the
 * SPA build. Replaces the old src/oauth/render.ts.
 */

function esc(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/**
 * JSON for embedding inside an inline `<script>`: escape `<` to `<` so a
 * value can never smuggle a closing `</script>` (or `<!--`) and break out of
 * the block. Parses back to the original string at JS load time. Today the
 * embedded values are server-controlled (challenge ids, URLs), so this is
 * defence-in-depth — but it's the correct thing if a user-controlled value ever
 * flows in.
 */
function jsonForScript(value: unknown): string {
  return JSON.stringify(value).replace(/</g, "\\u003c");
}

/**
 * Styles mirror the SvelteKit /login page (client/src/routes/login/+page.svelte
 * + Wordmark.svelte) so the passkey login/consent providers are visually
 * indistinguishable from the SPA. The design tokens and @font-face rules are
 * inlined (rather than referenced from the SPA's hashed app.css) to keep these
 * pages self-contained; the Geist woff2 files are served statically from
 * /fonts/ by the built client. Keep these values in sync with app.css :root.
 */
const STYLE = `
@font-face { font-family: "Geist"; font-style: normal; font-display: swap;
  font-weight: 100 900; src: url("/fonts/geist-latin-wght-normal.woff2") format("woff2-variations"); }
@font-face { font-family: "Geist Mono"; font-style: normal; font-display: swap;
  font-weight: 100 900; src: url("/fonts/geist-mono-latin-wght-normal.woff2") format("woff2-variations"); }
:root {
  color-scheme: dark;
  --surface-dim: #0e0e0e;
  --surface-container-low: #131313;
  --surface-container: #1a1a1a;
  --surface-container-high: #1f1f1f;
  --primary: #69f6b8;
  --on-primary-container: #002919;
  --on-surface: #f2f2f2;
  --on-surface-variant: #adaaaa;
  --on-surface-faint: #6a6866;
  --outline-variant: rgba(73, 72, 71, 0.15);
  --error: #ff5a5a;
  --grad-primary: linear-gradient(135deg, #69f6b8 0%, #06b77f 100%);
  --glow-primary: 0 0 24px rgba(105, 246, 184, 0.1);
  --glow-primary-strong: 0 0 32px rgba(105, 246, 184, 0.22);
  --font-ui: "Geist", system-ui, sans-serif;
  --font-mono: "Geist Mono", ui-monospace, monospace;
  --body-md: 0.875rem;
  --label-sm: 0.65rem;
  --space-2: 0.4rem; --space-4: 0.9rem; --space-5: 1.2rem; --space-7: 2.4rem;
}
* { box-sizing: border-box; }
body { margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
  font-family: var(--font-ui); background: var(--surface-dim); color: var(--on-surface); }
.card { background: var(--surface-container-low); padding: var(--space-7);
  text-align: center; max-width: 380px; width: 90%; }
.logo { width: 176px; height: 176px; display: block; margin: 0 auto var(--space-2); }
h1 { font-size: 2rem; line-height: 1; margin: 0 0 var(--space-7);
  font-weight: 600; letter-spacing: -0.01em; text-transform: uppercase; white-space: nowrap; }
.wordmark-shell { color: #12a26f; }
.wordmark-watch { color: #f0efea; }
p { color: var(--on-surface-variant); font-size: var(--body-md); line-height: 1.5;
  margin: 0 0 var(--space-5); }
.lead { text-align: left; }
.scopes { list-style: none; padding: 0; margin: 0 0 var(--space-5); text-align: left; }
.scopes li { background: var(--surface-container); border: 1px solid var(--outline-variant);
  padding: 8px 12px; margin-bottom: 6px; font-size: 13px; font-family: var(--font-mono);
  color: var(--on-surface-variant); }
.client { font-weight: 600; color: var(--primary); }
button { width: 100%; padding: 0.75rem 2rem; border: 0; cursor: pointer;
  background: var(--grad-primary); color: var(--on-primary-container);
  font-family: var(--font-ui); font-size: var(--body-md); font-weight: 600;
  letter-spacing: 0.02em; box-shadow: var(--glow-primary); transition: box-shadow 0.2s; }
button:hover { box-shadow: var(--glow-primary-strong); }
button:disabled { background: var(--surface-container-high); color: var(--on-surface-faint);
  box-shadow: none; cursor: default; }
.status { font-family: var(--font-mono); color: var(--on-surface-variant); font-size: var(--label-sm);
  text-transform: uppercase; letter-spacing: 0.14em; margin-top: var(--space-4); min-height: 1em; }
.status.err { color: var(--error); text-transform: none; letter-spacing: normal;
  font-family: var(--font-ui); font-size: var(--body-md); }
.muted { color: var(--on-surface-faint); font-size: var(--label-sm); margin-top: var(--space-5);
  text-transform: uppercase; letter-spacing: 0.14em; }
.register-link { margin-top: var(--space-5); font-size: var(--body-md); color: var(--on-surface-variant); }
.register-link a { color: var(--primary); text-decoration: none; }
.register-link a:hover { text-decoration: underline; }
`;

function ceremonyScript(
  optionsUrl: string,
  verifyUrl: string,
  extra: Record<string, string>,
): string {
  return `
const OPTIONS_URL=${jsonForScript(optionsUrl)};
const VERIFY_URL=${jsonForScript(verifyUrl)};
const EXTRA=${jsonForScript(extra)};
const statusEl=document.getElementById('status');
const btn=document.getElementById('go');
function setStatus(m){statusEl.className='status';statusEl.textContent=m;}
function setError(m){statusEl.className='status err';statusEl.textContent=m;btn.disabled=false;btn.textContent='Try again';}
function b64uToBuf(s){s=s.replace(/-/g,'+').replace(/_/g,'/');const pad=s.length%4;if(pad)s+='='.repeat(4-pad);const bin=atob(s);const u=new Uint8Array(bin.length);for(let i=0;i<bin.length;i++)u[i]=bin.charCodeAt(i);return u.buffer;}
function bufToB64u(b){const u=new Uint8Array(b);let s='';for(const x of u)s+=String.fromCharCode(x);return btoa(s).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'');}
async function run(){
  btn.disabled=true;setStatus('Requesting passkey…');
  let opt;
  try{const r=await fetch(OPTIONS_URL,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(EXTRA)});opt=await r.json();if(!r.ok||opt.error)throw new Error(opt.error||'Failed to start');}
  catch(e){setError(e.message||'Failed to start');return;}
  const publicKey={challenge:b64uToBuf(opt.challenge),rpId:opt.rpId,timeout:opt.timeout,userVerification:opt.userVerification||'required',allowCredentials:(opt.allowCredentials||[]).map(c=>({id:b64uToBuf(c.id),type:'public-key',transports:c.transports}))};
  let cred;
  try{cred=await navigator.credentials.get({publicKey});}
  catch(e){setError('Passkey prompt was cancelled.');return;}
  const resp={id:cred.id,rawId:bufToB64u(cred.rawId),type:cred.type,clientExtensionResults:cred.getClientExtensionResults?cred.getClientExtensionResults():{},authenticatorAttachment:cred.authenticatorAttachment||undefined,response:{authenticatorData:bufToB64u(cred.response.authenticatorData),clientDataJSON:bufToB64u(cred.response.clientDataJSON),signature:bufToB64u(cred.response.signature),userHandle:cred.response.userHandle?bufToB64u(cred.response.userHandle):undefined}};
  setStatus('Verifying…');
  let ver;
  try{const r=await fetch(VERIFY_URL,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(Object.assign({},EXTRA,{challengeId:opt.challengeId,credential:resp}))});ver=await r.json();if(!r.ok||!ver.redirectTo)throw new Error(ver.error||'Verification failed');}
  catch(e){setError(e.message||'Verification failed');return;}
  setStatus('Success — redirecting…');
  window.location.href=ver.redirectTo;
}
btn.addEventListener('click',run);
`;
}

/**
 * Client script for the no-passkey consent *approve* page (option-1): the user
 * already proved presence at the login step moments ago, so authorizing the
 * client is an explicit informed click (not a second passkey). POSTs `extra`
 * (the consent_challenge) and follows the returned redirect.
 */
function approveScript(approveUrl: string, extra: Record<string, string>): string {
  return `
const APPROVE_URL=${jsonForScript(approveUrl)};
const EXTRA=${jsonForScript(extra)};
const statusEl=document.getElementById('status');
const btn=document.getElementById('go');
function setStatus(m){statusEl.className='status';statusEl.textContent=m;}
function setError(m){statusEl.className='status err';statusEl.textContent=m;btn.disabled=false;}
btn.addEventListener('click',async()=>{
  btn.disabled=true;setStatus('Authorizing…');
  let res;
  try{const r=await fetch(APPROVE_URL,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(EXTRA)});res=await r.json();if(!r.ok||!res.redirectTo)throw new Error(res.error||'Authorization failed');}
  catch(e){setError(e.message||'Authorization failed');return;}
  setStatus('Success — redirecting…');
  window.location.href=res.redirectTo;
});
`;
}

/** Full HTML document wrapped in the shared card shell (logo + wordmark).
 * `inner` is the card body; `script`, if given, is inlined after the card. */
function page(title: string, inner: string, script?: string): string {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)}</title><style>${STYLE}</style></head>
<body><div class="card">
<img class="logo" src="/logo.svg" alt="">
<h1><span class="wordmark-shell">SHELL</span><span class="wordmark-watch">WATCH</span></h1>
${inner}
</div>${script ? `\n<script>${script}</script>` : ""}
</body></html>`;
}

/** Disclosure block shared by the passkey + approve consent pages: an optional
 * description line, the requesting client, and the requested scopes. */
function consentBody(p: { description?: string; clientName?: string; scopes?: string[] }): string {
  const description = p.description ? `<p>${esc(p.description)}</p>` : "";
  const clientLine = p.clientName
    ? `<p class="lead"><span class="client">${esc(p.clientName)}</span> is requesting access to your ShellWatch account with these scopes:</p>`
    : "";
  const scopeList =
    p.scopes && p.scopes.length
      ? `<ul class="scopes">${p.scopes.map((s) => `<li>${esc(s)}</li>`).join("")}</ul>`
      : "";
  return `${description}${clientLine}${scopeList}`;
}

export interface CeremonyPageParams {
  title: string;
  /** Optional explanatory line under the wordmark; omit to show only the logo + wordmark. */
  description?: string;
  optionsUrl: string;
  verifyUrl: string;
  /** Hidden flow params echoed into every POST (login_challenge / consent_challenge). */
  extra: Record<string, string>;
  /** Consent only: client name + requested scopes to display. */
  clientName?: string;
  scopes?: string[];
  buttonLabel?: string;
  /** Login only: omit the passkey button (+ ceremony) when no passkeys exist
   * yet, leaving only the create-account link. Defaults to true. */
  showButton?: boolean;
  /** Login only: when set, render a "Create new account" link to this path. */
  registerUrl?: string;
}

export function renderPasskeyPage(p: CeremonyPageParams): string {
  const showButton = p.showButton ?? true;
  const button = showButton
    ? `<button id="go">${esc(p.buttonLabel ?? "Continue with passkey")}</button>
<div id="status" class="status"></div>`
    : "";
  const registerLink = p.registerUrl
    ? `<p class="register-link"><a href="${esc(p.registerUrl)}">Create new account</a></p>`
    : "";
  const inner = `${consentBody(p)}
${button}${registerLink}
<div class="muted">Passkey-only authentication</div>`;
  // The ceremony is button-initiated (the script only wires the click handler,
  // it no longer auto-runs) — WebAuthn wants a user gesture, and the page is now
  // a real login landing, not an auto-popping prompt. No button → no script.
  return page(
    p.title,
    inner,
    showButton ? ceremonyScript(p.optionsUrl, p.verifyUrl, p.extra) : undefined,
  );
}

export interface ApprovePageParams {
  title: string;
  description?: string;
  /** Endpoint the Approve button POSTs `extra` to; expects `{ redirectTo }`. */
  approveUrl: string;
  /** Hidden flow params echoed into the POST (consent_challenge). */
  extra: Record<string, string>;
  clientName: string;
  scopes: string[];
  buttonLabel?: string;
}

/**
 * Consent page WITHOUT a passkey ceremony (option-1). Shown when the user
 * authenticated with a passkey moments earlier in the same flow, so granting
 * the client is an explicit Approve click rather than a redundant second
 * passkey. Still shows the client + scopes — informed consent is the point.
 */
export function renderApprovePage(p: ApprovePageParams): string {
  const inner = `${consentBody(p)}
<button id="go">${esc(p.buttonLabel ?? "Approve")}</button>
<div id="status" class="status"></div>
<div class="muted">You're signed in — approve to continue.</div>`;
  return page(p.title, inner, approveScript(p.approveUrl, p.extra));
}

export function renderErrorPage(error: string, description?: string): string {
  const inner = `<p>${esc(description || error || "Something went wrong during authentication.")}</p>
<a href="/" style="text-decoration:none"><button id="go">Back to ShellWatch</button></a>`;
  return page("Authentication error", inner);
}
