// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Server-rendered HTML for the Hydra passkey login + consent providers and the
// error page (port of src/hydra/render.ts). Self-contained pages (not the
// SvelteKit SPA) so the OAuth redirect path never depends on the client build.
// The ceremony script POSTs to the /options + /verify JSON endpoints.
package hydra

import (
	"encoding/json"
	"html"
	"strings"
)

// clientIdentity is what the consent page shows about a client whose
// client_id is a URL (CIMD). The hostname leads: it is the only part of a URL
// client_id an attacker cannot choose freely
// (draft-ietf-oauth-client-id-metadata-document-02 §9.1), whereas client_name
// is a self-assigned claim, so the page presents it as a claim.
//
// No logo is ever rendered. §9.3 wants a logo_uri prefetched, cached and
// moderated before display; ShellWatch does none of that, so it does not carry
// logo_uri into Hydra at all and shows no image here.
type clientIdentity struct {
	// Host is the client_id URL's hostname.
	Host string
	// ClientURIHost is client_uri's host, shown only when it differs from Host
	// (a mismatch is worth seeing).
	ClientURIHost string
	// Recent marks a client registered or materially changed within the last
	// hour — the signal that this is new or just moved.
	Recent bool
}

// ceremonyParams configure the passkey ceremony page.
type ceremonyParams struct {
	Title       string
	Description string
	OptionsURL  string
	VerifyURL   string
	Extra       map[string]string
	ClientName  string
	Scopes      []string
	ButtonLabel string
	ShowButton  bool
	RegisterURL string
	// Identity is set for a URL client_id; nil for the SPA and DCR clients.
	Identity *clientIdentity
}

func esc(s string) string { return html.EscapeString(s) }

// jsonForScript escapes `<` so an embedded value can't break out of the
// <script> block (defence-in-depth; embedded values are server-controlled).
func jsonForScript(v any) string {
	b, _ := json.Marshal(v)
	return strings.ReplaceAll(string(b), "<", "\\u003c")
}

func renderPasskeyPage(p ceremonyParams) string {
	button := ""
	var script string
	if p.ShowButton {
		label := p.ButtonLabel
		if label == "" {
			label = "Continue with passkey"
		}
		button = `<button id="go">` + esc(label) + `</button>
<div id="status" class="status"></div>`
		script = ceremonyScript(p.OptionsURL, p.VerifyURL, p.Extra)
	}
	registerLink := ""
	if p.RegisterURL != "" {
		registerLink = `<p class="register-link"><a href="` + esc(p.RegisterURL) + `">Create new account</a></p>`
	}
	inner := consentBody(p.Description, p.ClientName, p.Scopes, p.Identity) + "\n" + button + registerLink +
		"\n" + `<div class="muted">Passkey-only authentication</div>`
	return page(p.Title, inner, script)
}

// approveParams configure the no-passkey consent approve page.
type approveParams struct {
	Title       string
	ApproveURL  string
	Extra       map[string]string
	ClientName  string
	Scopes      []string
	ButtonLabel string
	Identity    *clientIdentity
}

func renderApprovePage(p approveParams) string {
	label := p.ButtonLabel
	if label == "" {
		label = "Approve"
	}
	inner := consentBody("", p.ClientName, p.Scopes, p.Identity) + "\n" +
		`<button id="go">` + esc(label) + `</button>
<div id="status" class="status"></div>
<div class="muted">You're signed in — approve to continue.</div>`
	return page(p.Title, inner, approveScript(p.ApproveURL, p.Extra))
}

func renderErrorPage(errMsg, description string) string {
	msg := description
	if msg == "" {
		msg = errMsg
	}
	if msg == "" {
		msg = "Something went wrong during authentication."
	}
	inner := `<p>` + esc(msg) + `</p>
<a href="/" style="text-decoration:none"><button id="go">Back to ShellWatch</button></a>`
	return page("Authentication error", inner, "")
}

func page(title, inner, script string) string {
	scriptTag := ""
	if script != "" {
		scriptTag = "\n<script>" + script + "</script>"
	}
	return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>` + esc(title) + `</title><style>` + styleCSS + `</style></head>
<body><div class="card">
<img class="logo" src="/logo.svg" alt="">
<h1><span class="wordmark-shell">SHELL</span><span class="wordmark-watch">WATCH</span></h1>
` + inner + `
</div>` + scriptTag + `
</body></html>`
}

func consentBody(description, clientName string, scopes []string, identity *clientIdentity) string {
	var b strings.Builder
	if description != "" {
		b.WriteString(`<p>` + esc(description) + `</p>`)
	}
	if identity != nil {
		// Order matters (#242): hostname first, then the self-assigned name,
		// then client_uri's host, then the scopes.
		b.WriteString(`<div class="cimd-id">` +
			`<div class="cimd-host-label">Client hosted at</div>` +
			`<div class="cimd-host">` + esc(identity.Host) + `</div>`)
		if clientName != "" {
			b.WriteString(`<p class="cimd-meta">calls itself <span class="claim">` +
				esc(clientName) + `</span></p>`)
		}
		if identity.ClientURIHost != "" {
			b.WriteString(`<p class="cimd-meta">home page: <span class="claim">` +
				esc(identity.ClientURIHost) + `</span></p>`)
		}
		b.WriteString(`</div>`)
		if identity.Recent {
			b.WriteString(`<p class="first-seen">This client was registered or last changed ` +
				`less than an hour ago.</p>`)
		}
		b.WriteString(`<p class="lead">It is requesting access to your ShellWatch account ` +
			`with these scopes:</p>`)
	} else if clientName != "" {
		b.WriteString(`<p class="lead"><span class="client">` + esc(clientName) +
			`</span> is requesting access to your ShellWatch account with these scopes:</p>`)
	}
	if len(scopes) > 0 {
		b.WriteString(`<ul class="scopes">`)
		for _, s := range scopes {
			b.WriteString(`<li>` + esc(s) + `</li>`)
		}
		b.WriteString(`</ul>`)
	}
	return b.String()
}

func ceremonyScript(optionsURL, verifyURL string, extra map[string]string) string {
	return `
const OPTIONS_URL=` + jsonForScript(optionsURL) + `;
const VERIFY_URL=` + jsonForScript(verifyURL) + `;
const EXTRA=` + jsonForScript(extra) + `;
const statusEl=document.getElementById('status');
const btn=document.getElementById('go');
function setStatus(m){statusEl.className='status';statusEl.textContent=m;}
function setError(m){statusEl.className='status err';statusEl.textContent=m;btn.disabled=false;btn.textContent='Try again';}
function b64uToBuf(s){s=s.replace(/-/g,'+').replace(/_/g,'/');const pad=s.length%4;if(pad)s+='='.repeat(4-pad);const bin=atob(s);const u=new Uint8Array(bin.length);for(let i=0;i<bin.length;i++)u[i]=bin.charCodeAt(i);return u.buffer;}
function bufToB64u(b){const u=new Uint8Array(b);let s='';for(const x of u)s+=String.fromCharCode(x);return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');}
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
`
}

func approveScript(approveURL string, extra map[string]string) string {
	return `
const APPROVE_URL=` + jsonForScript(approveURL) + `;
const EXTRA=` + jsonForScript(extra) + `;
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
`
}
