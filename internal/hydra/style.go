// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
package hydra

// styleCSS mirrors the SPA login styling (app.css tokens) so the passkey
// provider pages are visually indistinguishable from the client. Ported
// verbatim from src/hydra/render.ts STYLE.
const styleCSS = `
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
`
