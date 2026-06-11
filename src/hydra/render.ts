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

const STYLE = `
:root { color-scheme: dark; }
* { box-sizing: border-box; }
body { margin: 0; min-height: 100vh; display: grid; place-items: center;
  font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
  background: #0b0d12; color: #e6e8ee; }
.card { width: min(420px, 92vw); background: #141821; border: 1px solid #232a36;
  border-radius: 14px; padding: 28px; box-shadow: 0 10px 40px rgba(0,0,0,.4); }
h1 { font-size: 20px; margin: 0 0 6px; }
p { color: #9aa3b2; font-size: 14px; line-height: 1.5; margin: 0 0 16px; }
.scopes { list-style: none; padding: 0; margin: 0 0 18px; }
.scopes li { background: #0f1320; border: 1px solid #232a36; border-radius: 8px;
  padding: 8px 12px; margin-bottom: 6px; font-size: 13px; font-family: ui-monospace, monospace; }
.client { font-weight: 600; color: #e6e8ee; }
button { width: 100%; padding: 12px 16px; border: 0; border-radius: 10px; cursor: pointer;
  background: #4f8cff; color: white; font-size: 15px; font-weight: 600; }
button:disabled { opacity: .6; cursor: default; }
.status { margin-top: 14px; font-size: 13px; min-height: 18px; }
.status.err { color: #ff6b6b; }
.muted { color: #6b7280; font-size: 12px; margin-top: 16px; }
`;

function ceremonyScript(
  optionsUrl: string,
  verifyUrl: string,
  extra: Record<string, string>,
): string {
  return `
const OPTIONS_URL=${JSON.stringify(optionsUrl)};
const VERIFY_URL=${JSON.stringify(verifyUrl)};
const EXTRA=${JSON.stringify(extra)};
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
run();
`;
}

export interface CeremonyPageParams {
  title: string;
  heading: string;
  description: string;
  optionsUrl: string;
  verifyUrl: string;
  /** Hidden flow params echoed into every POST (login_challenge / consent_challenge). */
  extra: Record<string, string>;
  /** Consent only: client name + requested scopes to display. */
  clientName?: string;
  scopes?: string[];
  buttonLabel?: string;
}

export function renderPasskeyPage(p: CeremonyPageParams): string {
  const scopeList =
    p.scopes && p.scopes.length
      ? `<ul class="scopes">${p.scopes.map((s) => `<li>${esc(s)}</li>`).join("")}</ul>`
      : "";
  const clientLine = p.clientName
    ? `<p><span class="client">${esc(p.clientName)}</span> is requesting access to your ShellWatch account with these scopes:</p>`
    : "";
  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(p.title)}</title><style>${STYLE}</style></head>
<body><div class="card">
<h1>${esc(p.heading)}</h1>
<p>${esc(p.description)}</p>
${clientLine}${scopeList}
<button id="go">${esc(p.buttonLabel ?? "Continue with passkey")}</button>
<div id="status" class="status"></div>
<div class="muted">ShellWatch · passkey-only authentication</div>
</div>
<script>${ceremonyScript(p.optionsUrl, p.verifyUrl, p.extra)}</script>
</body></html>`;
}

export function renderErrorPage(error: string, description?: string): string {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Authentication error</title><style>${STYLE}</style></head>
<body><div class="card">
<h1>Authentication error</h1>
<p>${esc(description || error || "Something went wrong during authentication.")}</p>
<a href="/"><button id="go">Back to ShellWatch</button></a>
</div></body></html>`;
}
