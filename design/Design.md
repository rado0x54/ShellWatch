# ShellWatch Design System

> **The Obsidian Command** — Terminal Precision & Kinetic Depth. A dark-only ops console that stays out of the terminal's way but illuminates crisply when something needs attention.

This document describes the visual language as implemented in `client/src/` and `src/oauth/render.ts`. It supersedes the "Obsidian Terminal" palette that shipped in the first design bundle.

---

## 1. North Star

ShellWatch is a WebAuthn-native SSH broker with a browser terminal UI and an MCP interface for AI agents. Both surfaces share one real-time state: sessions created by an agent appear in the UI and vice versa. Every signature is gated by a passkey, so the chrome has to communicate **trust, liveness, and supervision** at a glance.

The design treats the UI like a precision instrument machined from a single block of dark glass. We prioritize the **glow of live data** over the **structure of the container** — a dark canvas that the status of active sessions can illuminate without the UI getting in the way.

---

## 2. Palette — Tonal Luminescence

Deep obsidian surfaces; emerald gradient as the UI's light source. Secondary amber signals control / warning. Crimson for errors.

### Surfaces — tonal ladder (no borders for sectioning)

| Token                         | Hex       | Usage                                                       |
| ----------------------------- | --------- | ----------------------------------------------------------- |
| `--surface-lowest`            | `#0a0a0a` | Deepest void (reserved)                                     |
| `--surface-dim`               | `#0e0e0e` | App canvas, main background                                 |
| `--surface-container-low`     | `#131313` | Sidebar, card, login card, settings row, settings tab strip |
| `--surface-container`         | `#1a1a1a` | Row hover, reported-fields box                              |
| `--surface-container-high`    | `#1f1f1f` | Active row, elevated state                                  |
| `--surface-container-highest` | `#262626` | Active interactive (terminal panel, inline code)            |
| `--surface-bright`            | `#2c2c2c` | Frosted-obsidian toast + modal base                         |

**The "No-Line" rule.** 1px borders are banned for sectioning. To separate a sidebar from the main pane, shift from `surface-container-low` on `surface-dim` — let the eye find the edge through the change in value, not a stroke. Ghost borders (`--outline-variant: rgba(73,72,71,0.15)`) may appear only when density demands a container (e.g. `.sign-preview`).

### Primary — emerald

| Token                    | Hex       | Usage                                                            |
| ------------------------ | --------- | ---------------------------------------------------------------- |
| `--primary`              | `#69f6b8` | Active text, open status, observer mode, power rails, focus ring |
| `--primary-container`    | `#06b77f` | Gradient endpoint, active tab marker deep end                    |
| `--primary-dim`          | `#3fbe8a` | Non-interactive data (currently unused)                          |
| `--on-primary-container` | `#002919` | Text on primary gradient fills                                   |

**Gradient rule.** Primary action buttons and login/authorize CTAs use `linear-gradient(135deg, #69f6b8 0%, #06b77f 100%)` — stored as `--grad-primary`. This is the one place the UI "has a soul"; plain color fills are prohibited on primary buttons.

### Secondary — amber

| Token                   | Hex       | Usage                                                                 |
| ----------------------- | --------- | --------------------------------------------------------------------- |
| `--secondary`           | `#f8a010` | Control mode, opening status, "Take Control", danger banners on OAuth |
| `--secondary-container` | `#b87700` | —                                                                     |
| `--secondary-dim`       | `#b07a1a` | —                                                                     |

### Error — crimson

| Token     | Hex       | Usage                                   |
| --------- | --------- | --------------------------------------- |
| `--error` | `#ff5a5a` | Errors, destructive hover, error toasts |

### Text — on-surface ramp

| Token                  | Hex       | Usage                                  |
| ---------------------- | --------- | -------------------------------------- |
| `--on-surface`         | `#f2f2f2` | Body, headings (never pure `#ffffff`)  |
| `--on-surface-variant` | `#adaaaa` | Eyebrows, metadata, secondary text     |
| `--on-surface-faint`   | `#6a6866` | Empty-state placeholder text, dividers |

**Selection color:** `rgba(105, 246, 184, 0.25)` on text.

### Legacy aliases

Old tokens (`--bg-primary`, `--accent`, `--text-muted`, …) are kept in `client/src/app.css` as aliases that map to the new palette, so scoped component styles pick up the new look without edits. New code should use the new tokens.

---

## 3. Elevation & Depth — Tonal Layering, Scoped Glow

Traditional drop shadows are too heavy for a precision UI. Depth comes from two sources:

1. **Surface ladder** — a "floating" panel is defined by being `surface-container-highest` set against a `surface-dim` background.
2. **Ambient glow** — a short-radius colored glow (not a neutral shadow) applied **only to live state**. This is load-bearing: a glow means "this is alive / needs attention."

### The glow scoping rule

Glow is reserved for **live signals and required decisions**. It never decorates static containers.

| Element                                     | Glow                                                     | Reason                                                                            |
| ------------------------------------------- | -------------------------------------------------------- | --------------------------------------------------------------------------------- |
| `.btn-primary`, `.login-btn`                | `var(--glow-primary)` → `--glow-primary-strong` on hover | The gradient CTA is the brand                                                     |
| `.status-dot.open`                          | 8px emerald glow                                         | Session is live                                                                   |
| `.status-dot.error`                         | 8px crimson glow                                         | Session is errored                                                                |
| `.terminal-observer`                        | `--glow-primary-strong`                                  | Active session, observer mode                                                     |
| `.terminal-control`                         | `--glow-secondary-strong`                                | Active session, control mode — amber because "take control" is attention-grabbing |
| `.session-item.active::before` (power rail) | 12px emerald                                             | Active row in sidebar                                                             |
| `.btn-nav.active::before` (power rail)      | 12px emerald                                             | Active nav destination                                                            |
| `.toast-sign-request`                       | `--glow-primary-strong`                                  | Decision-critical interrupt                                                       |
| `.toast-error`                              | `--glow-error`                                           | Error that needs acknowledgment                                                   |
| OAuth `.danger` banner                      | `--glow-secondary`                                       | User needs to verify a redirect URI                                               |
| OAuth `.error` banner                       | `--glow-error`                                           | Submission failed                                                                 |

**Do not** glow: login card, sign card, modal, default (info) toast, observer cells, code-block hover, settings tab underline, brand logo silhouettes, section dividers.

### Hard edges

Border radius is set to `0` globally via `* { border-radius: 0 !important }` in `client/src/app.css`. Sharp corners convey robustness and precision. Exceptions are impossible — if something visually needs rounding, revisit the layout instead.

---

## 4. Typography — Dual Engine

Geist + Geist Mono, served from Google Fonts. `system-ui` remains as a fallback.

| Token            | Family     | Use                                                                  |
| ---------------- | ---------- | -------------------------------------------------------------------- |
| `--font-display` | Geist      | Headings, hero copy, wordmark                                        |
| `--font-ui`      | Geist      | Body, labels, buttons                                                |
| `--font-mono`    | Geist Mono | Eyebrows, metadata, code, fingerprints, terminal text, SSH addresses |

Mono stylistic sets `ss01` + `cv11` are enabled globally for tabular / alt-zero — cleaner wallet IDs and fingerprints.

### Scale

| Token          | Size     | Use                                 |
| -------------- | -------- | ----------------------------------- |
| `--display-lg` | 3.5rem   | Reserved                            |
| `--display-md` | 2.5rem   | Settings / admin page title         |
| `--title-lg`   | 1.5rem   | Section headings, sign card title   |
| `--title-md`   | 1.25rem  | Sidebar wordmark, in-app h2         |
| `--body-lg`    | 1rem     | Mobile brand                        |
| `--body-md`    | 0.875rem | Body text, form inputs              |
| `--label-md`   | 0.75rem  | Captions, button labels             |
| `--label-sm`   | 0.65rem  | Eyebrows, status badges, meta lines |

### Eyebrow style

Section headers, settings tabs, table-less "column headers" inside row cards, toast field labels, empty-state text. All share:

```css
font-family: var(--font-mono);
font-size: var(--label-sm); /* or --label-md */
font-weight: 500;
text-transform: uppercase;
letter-spacing: 0.14em;
color: var(--on-surface-variant);
```

This is the one place we embrace density — the eyebrow is the "machined label" look that separates an ops tool from a marketing site.

### Display heading tracking

`h1/h2/h3…` are Geist display at weight 600 with `letter-spacing: -0.02em`. `--display-md` bumps the negative tracking to `-0.035em` so the hero text on login / settings hits editorial weight.

---

## 5. Spacing — Machined

0.2rem base. Consistent half-steps produce the "precision instrument" look.

| Token       | rem |
| ----------- | --- |
| `--space-1` | 0.2 |
| `--space-2` | 0.4 |
| `--space-3` | 0.6 |
| `--space-4` | 0.9 |
| `--space-5` | 1.2 |
| `--space-6` | 1.8 |
| `--space-7` | 2.4 |

Sidebar is a fixed `280px` (`--sidebar-width`). Settings pages are padded `2rem` on desktop, `1rem` on mobile.

---

## 6. Brand

### Logo

The mark is a nautilus-in-shield in two colors (`#F0EFEA` shield outline, `#12A26F` nautilus). Source of truth: `design/shellwatch_logo.svg` (transparent, no background, single-path fills).

- **In-app**: always reference the transparent SVG (`/logo.svg`) so any future background change flows through without re-rasterization.
- **Favicon + PWA icons**: `client/static/{favicon.png, icon-{32,64,128,180,192,512}.png}` — generated via ImageMagick from the SVG with `#131313` (surface-container-low) baked in as the background.
- **Logo + wordmark PNG exports**: `design/shellwatch_logo-wordmark-dark-bg.png` and `design/shellwatch_logo-wordmark-light-bg.png` — 1280 × 360 horizontal assets for contexts that need a baked background. `design/shellwatch_logo-wordmark-stacked-dark-bg.png` and `design/shellwatch_logo-wordmark-stacked-light-bg.png` — 718 × 501 stacked assets matching the README lockup with symmetric padding. The dark exports use `#131313`; the light exports use `#f0efea` and swap the shield outline to `#1f1f1f` for contrast.
- **Monochrome silhouette**: on the empty "no session" page the mark is rendered as a CSS `mask` filled with `currentColor` (`--on-surface-faint`), giving a one-tone silhouette.

### Wordmark — SHELL + WATCH

The shared `Wordmark.svelte` component renders `SHELL` in `#12a26f` and `WATCH` in `#f0efea` — the two logo colors. All caps, Geist display, weight 600, `letter-spacing: -0.01em`.

Used wherever "ShellWatch" appears as a visible identifier:

- Login card (`2rem` size)
- Sidebar brand header (`--title-md`, next to a 56px logo)
- Mobile header (`--body-lg`, 28px logo next to the hamburger)
- Register page headings + body paragraphs
- Settings → Endpoints help copy
- OAuth authorize header

**Not replaced:**

- `<title>ShellWatch</title>` in `app.html` (browser chrome can't render HTML color)
- Push-notification title (OS chrome)
- `accountName` default "ShellWatch Account" (written into the passkey blob, not displayed)

---

## 7. Components

### Buttons

- `.btn-primary` — emerald gradient, `--on-primary-container` text, glow on default + stronger glow on hover. Disabled variant drops to `--surface-container-high` background with `--on-surface-faint` text.
- `.btn-secondary` — ghost, `--on-surface-variant` text with a 1px bottom edge; hover flips text + edge to `--error` (destructive hint).
- `.btn-warn` — amber text + amber bottom edge, glow-on-hover; used for "Take Control."
- `.btn-ghost` — no chrome, label only; hover tints to primary.

All buttons use Geist with 0.02em positive tracking and weight 600.

### Signal chips (badges)

A 6px colored dot + lowercase label, no background, no border, no pill. Four variants:

- `.badge-observer` — amber dot, amber label
- `.badge-available` — emerald dot, emerald label
- `.badge-unavailable` — crimson dot, crimson label
- `.badge-pending` — amber dot, amber label (e.g. "pending confirmation" on a key awaiting approval)

Example usage: session list entries, settings rows ("required", "active", "admin").

### Status dots

6px colored square (not a circle — no radius). `.open` glows emerald (live signal), `.error` glows crimson, `.opening` flat amber, `.closed` faint grey.

### Inputs — filled fields

Text-like `<input>`, `<select>`, and `<textarea>` share one global rule (in `app.css`) so fields look identical in modals, settings forms, and standalone pages: filled `--surface-container`, 1px `--outline-variant` border, padded `0.5rem 0.625rem`. Focus flips the border to `--primary` and adds a 1px primary ring (`box-shadow: 0 0 0 1px var(--primary)`) — no underline, no glow halo. There are no scoped per-page or `.modal`-scoped input overrides; the global rule wins.

`<select>` is forced to `appearance: none` for consistent rendering across browsers, then gets a custom caret drawn via two stacked `linear-gradient` backgrounds. Date / time inputs adopt `color-scheme: dark` so the native picker popup uses the dark palette, and the calendar-icon affordance is recolored with `filter: invert(0.7)` for visibility.

### Lists & rows — power rail

Forbid dividers between rows. Hover is a tonal shift to `--surface-container`; active is a deeper shift to `--surface-container-high` **plus** a 2px vertical emerald power rail with glow on the extreme left of the row. Used by both the session list and the sidebar nav.

### Terminal panels

The active terminal is `surface-container-highest` on `surface-dim`. The ring around it is an **ambient glow** — `--glow-primary-strong` when in observer mode, `--glow-secondary-strong` when in control mode. No colored border frame.

xterm.js theme matches: background `#0e0e0e`, foreground `#f2f2f2`, cursor + green-byte `#69f6b8`, yellow `#f8a010`, red `#ff5a5a`, white `#f2f2f2`.

### Toast — frosted obsidian

`rgba(44, 44, 44, 0.6)` + `backdrop-filter: blur(20px)` + 1px outline-variant. No background shadow. Variants:

- **Info (default)** — no glow.
- **Error** — adds `--glow-error` + crimson edge.
- **Sign-request** — adds `--glow-primary-strong` + emerald edge. Headline has a 🔐 / 🔑 emoji. Fields render as mono-uppercase label → value pairs; fingerprints are truncated via `shortFingerprint(...)` to `SHA256:xxxxxxxx…xxxxxxxx` (first 8 + last 8 of the base64 body, prefix preserved), with the full value on the element's `title` attribute.

**Mobile (≤768px) — bottom sheet.** Container re-anchors to `bottom: space-3, left: space-3, right: space-3`, `column-reverse` stack so the newest toast sits at the top (furthest from the thumb). Fields switch to vertical stacking (label above value). Action buttons become `flex: 1` side-by-side for thumb reach. Animation flips from slide-in-from-right to slide-up-from-below.

### Modal

Opaque `--surface-bright` (`#2c2c2c`) panel with a 1px `--outline-variant` edge, sitting over a `rgba(0,0,0,0.6)` dimmed overlay. No backdrop blur, no glow — it's a container, not a live signal. (Toast still uses the frosted-obsidian recipe; modal does not, so the two surfaces feel deliberately distinct: toast floats over content, modal blocks it.) Inputs inside the modal pick up the global filled-field style — there are no modal-scoped input overrides.

### Settings rows — `SettingsList` + `SettingsRow`

Lives in `client/src/lib/components/`. Replaces every `<table>` in the settings and admin areas. Each row has:

- **Primary line** — bold label + inline signal chips + any mono meta (e.g. algorithm, scopes). Truncates with ellipsis.
- **Secondary line (optional)** — small mono copy: address, fingerprint, "created …, last used …" joined by `·`. `word-break: break-all` so fingerprints wrap instead of clipping.
- **Detail disclosure (optional)** — `<details>` with a mono-uppercase summary like `▸ Description`; body accepts either a `detail` plain-text prop or a rich `detailSlot` snippet. Long endpoint descriptions (up to 1000 chars) live here, collapsed by default.
- **Actions slot** — right-aligned Edit/Delete-style buttons.

**Mobile (≤768px)**: `row-head` flips to column; actions wrap under the primary row at `justify-content: flex-end`. No horizontal scroll.

### OAuth authorize page (`src/oauth/render.ts`)

Server-rendered HTML, so styles are inlined. Mirrors the in-app look: Obsidian Command tokens, Geist + Geist Mono from Google Fonts, brand header (logo + SHELL/WATCH), danger banner as a left-rail power bar with amber glow, mode-toggle as a mono-uppercase tab row with primary underline, ghost-underline inputs, emerald gradient Authorize button. Favicon + logo reference `/favicon.png` and `/logo.svg` (served from `dist/client/` by `@fastify/static`).

---

## 8. Motion

- **Toasts**: slide in 0.2s ease-out — from the right on desktop, from the bottom on mobile.
- **Mobile sidebar drawer**: `transform: translateX()` 0.2s ease.
- **Hover transitions**: 0.15–0.2s for `color`, `background`, and `box-shadow`.
- **No** page transitions, skeleton shimmers, or press-scale effects. This is a precision tool.
- xterm's native cursor blink is the only "living" animation inside the terminal panel.

---

## 9. Layout

### App shell (`client/src/routes/+layout.svelte`)

- **Desktop**: fixed `280px` sidebar (`--surface-container-low`) + fluid main (`--surface-dim`). Tonal shift at the boundary; no vertical divider.
- **Mobile (≤768px)**: 40px top bar with hamburger, 28px logo, and Wordmark. Sidebar slides in from the left as a drawer with a semi-transparent overlay.

### Sidebar (`client/src/lib/components/Sidebar.svelte`)

- Brand row (56px logo + wordmark)
- Endpoints section — compact rows with truncating label (native `title` attribute gives the full `user@host:port` on desktop hover)
- Sessions section — status dot + endpoint label + action buttons; active row shows the power rail
- Footer — account identicon + name, nav buttons for Observer / Settings / Admin / Sign Out

### Empty state

`/` route renders a centered flex column: 128px monochrome logo silhouette on top, mono-uppercase "SELECT AN ENDPOINT OR SESSION FROM THE SIDEBAR" below. Constrained to `max-width: 28rem` + `padding: --space-5` so the text doesn't touch the viewport edges on narrow phones.

---

## 10. Content Fundamentals (voice and copy)

Preserved from the original bundle — the copy register is the one thing that didn't change in the repaint.

- **Register**: technical, declarative, second-person imperative ("Touch your passkey", "Add Endpoint"). Never "we". No marketing voice.
- **Casing**:
  - Eyebrows / section headers / settings tabs: `UPPERCASE, TRACKED +0.14em` (mono).
  - Button labels: _Title Case_ ("Add Endpoint", "Take Control", "Sign in with Passkey").
  - Badges: `lowercase` (`observer`, `active`, `available`, `required`).
  - Inline code: monospaced, never styled as a button.
- **Placeholders are examples**: `user@host:port`, `My server`, `e.g., production DB host, runs Postgres 15, /srv/data holds nightly dumps`.
- **Hints are paragraphs, not tooltips** — settings pages ship multi-sentence blocks that explain the server-side consequence of a client-side toggle, with literal config snippets (`PubkeyAuthOptions verify-required`).
- **Status is color first, word second** — "open / opening / closed / error" exist as dot colors before they exist as text.
- **Emoji**: none in product copy. The only pictograms are Unicode glyphs used as functional icons: `✕` (close), `☰` (hamburger), `✓` / `✗` (affirm / dismiss), `ℹ` (info toast), `🔐` (passkey sign request), `🔑` (SSH key approval).

Rule of thumb: if a sentence could live in a README code-block, it belongs in ShellWatch. If it reads like marketing, it doesn't.

---

## 11. Do's and Don'ts

### Do

- Use extreme information density. Users are pros; small, well-organized text is correct.
- Use `--on-surface-variant` for non-critical data so the "light" stays focused on what matters.
- Use the spacing scale religiously. Inconsistent spacing breaks the "machined" feel immediately.
- Put long free-form content behind a `<details>` disclosure or the `SettingsRow` detail slot.

### Don't

- Don't use `border-radius`. 0px is the law — the global `!important` reset enforces it.
- Don't use neutral grey drop shadows. If something needs to lift, use a colored glow or a tonal shift.
- Don't glow containers. Glow signals live state — modals, login cards, default toasts, and observer cells all stay flat.
- Don't use pure `#ffffff` for long-form text; `--on-surface` (`#f2f2f2`) prevents eye strain during long sessions.
- Don't centre terminal data. Everything is left-aligned or grid-aligned to maintain the modular feel.
- Don't add a new table. Use `SettingsList` + `SettingsRow`.
- Don't add a new icon library. Unicode glyphs are the pattern; the mark-only SVG is the only custom graphic.

---

## 12. File map

| Concern                                | File                                                                                                                |
| -------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| Tokens, base styles, legacy aliases    | `client/src/app.css`                                                                                                |
| Google Fonts import + theme-color meta | `client/src/app.html`                                                                                               |
| Wordmark                               | `client/src/lib/components/Wordmark.svelte`                                                                         |
| Settings row pattern                   | `client/src/lib/components/{SettingsList, SettingsRow}.svelte`                                                      |
| Sidebar                                | `client/src/lib/components/Sidebar.svelte`                                                                          |
| Terminal (xterm theme)                 | `client/src/lib/components/{Terminal, TerminalSnapshot}.svelte`                                                     |
| Toast (desktop + mobile bottom-sheet)  | `client/src/lib/components/ToastContainer.svelte`                                                                   |
| Modal                                  | `client/src/lib/components/Modal.svelte` (styled via `.modal` rules in `app.css`)                                   |
| OAuth authorize page                   | `src/oauth/render.ts`                                                                                               |
| Logo source of truth                   | `design/shellwatch_logo.svg`                                                                                        |
| In-app logo asset                      | `client/static/logo.svg`                                                                                            |
| PWA icons + favicon                    | `client/static/{icon-*.png, favicon.png}` — regenerated from `design/shellwatch_logo.svg` with `#131313` background |
| PWA manifest theme                     | `client/static/manifest.json`                                                                                       |

---

## 13. Regenerating PWA icons

The raster icons are regenerated from the SVG whenever the logo changes. On macOS with ImageMagick:

```sh
cd client/static
for s in 32 64 128 180 192 512; do
  magick -background "#131313" -density 400 \
    ../../design/shellwatch_logo.svg \
    -resize ${s}x${s} -flatten icon-${s}.png
done
magick -background "#131313" -density 400 \
  ../../design/shellwatch_logo.svg \
  -resize 32x32 -flatten favicon.png
```

The `client/static/logo.svg` is a direct copy of `design/shellwatch_logo.svg` — keep them in sync when iterating on the mark.
