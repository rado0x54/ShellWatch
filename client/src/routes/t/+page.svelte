<!-- SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0 -->
<script lang="ts">
  // One-time access guest page (#306), opened on an untrusted browser from
  // the owner's link `/t#<token>`: the guest states a reason, redeems the
  // ticket and waits for the owner's approval, then gets a terminal on one
  // endpoint and nothing else. A public path: the root layout skips the
  // authenticated bootstrap. It never reads the SPA's stored tokens, never
  // sends Authorization, stores nothing and links nowhere into the app; the
  // HttpOnly guest cookie is its only credential.
  import { onDestroy, onMount } from "svelte";
  import Terminal from "$lib/components/Terminal.svelte";
  import {
    GuestSocket,
    checkTicket,
    REDEEM_FAILURE_TEXT,
    redeemTicket,
    takeTokenFromLocation,
    type GuestStatus,
    type RedeemFailure,
    clockOffsetMs,
  } from "$lib/guest/guest-client.js";
  import {
    endingFor,
    onConnectionLost,
    RECONNECT_DELAY_MS,
    type Ending,
  } from "$lib/guest/reconnect.js";

  type Phase =
    | "loading"
    | "form"
    | "redeeming"
    | "connecting"
    | "pending"
    | "open"
    | "ended"
    | "invalid";

  let phase = $state<Phase>("loading");
  let token = $state("");
  let reason = $state("");
  /** From the check; unknown (null) when it could not tell: then the field
   * is shown as before and redeem enforces it. */
  let reasonRequired = $state<boolean | null>(null);
  let failure = $state<RedeemFailure | null>(null);
  let code = $state("");
  let admissionDeadline = $state<number | null>(null);
  let lifetimeDeadline = $state<number | null>(null);
  let endedMessage = $state("");
  /** Shown when a second link was pasted during a live session. */
  let linkNotice = $state("");
  let reconnecting = $state(false);
  /** Server clock minus this device's clock: deadlines come from the server,
   * and the guest device's clock may be wrong. */
  let clockOffset = 0;
  /** The server's idea of now, advanced by the ticker. */
  const serverNow = (): number => Date.now() + clockOffset;
  let now = $state(Date.now());
  /** One per run: a reconnect reopens it, so the terminal keeps its transport. */
  let socket = $state.raw<GuestSocket | null>(null);
  let dropSince: number | null = null;
  /** Whether this run has received any status: decides which ending text a
   * guest session gets (see endingFor). */
  let sawStatus = false;
  let ticker: ReturnType<typeof setInterval> | null = null;
  let reconnectTimer: ReturnType<typeof setTimeout> | null = null;

  const secondsLeft = (deadline: number | null): number =>
    // Rounded up: a countdown never reaches 0 before the deadline itself.
    deadline === null ? 0 : Math.max(0, Math.ceil((deadline - now) / 1000));

  const fmt = (seconds: number): string =>
    `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, "0")}`;

  function onStatus(st: GuestStatus): void {
    if (st.serverTime) {
      clockOffset = clockOffsetMs(st.serverTime, Date.now());
      now = serverNow();
    }
    if (st.state === "closed") {
      showEnding(endingFor(sawStatus, st.message));
      socket?.close();
      socket = null;
      return;
    }
    sawStatus = true;
    reconnecting = false;
    dropSince = null;
    if (st.code) code = st.code;
    if (st.admissionDeadline) admissionDeadline = Date.parse(st.admissionDeadline);
    if (st.lifetimeDeadline) lifetimeDeadline = Date.parse(st.lifetimeDeadline);
    phase = st.state;
  }

  function showEnding(e: Ending): void {
    reconnecting = false;
    failure = null;
    if (e.phase === "ended") endedMessage = e.message;
    phase = e.phase;
  }

  /** A failed handshake (first connect included) or a dropped socket: the
   * server could not be reached, so retry until the give-up. */
  function onDrop(): void {
    if (phase === "ended" || phase === "invalid") return;
    const d = onConnectionLost(dropSince, sawStatus, Date.now());
    if (!d.retry) {
      showEnding(d.ending);
      return;
    }
    dropSince = d.dropSince;
    reconnecting = true;
    reconnectTimer = setTimeout(connect, RECONNECT_DELAY_MS);
  }

  function connect(): void {
    // Callbacks of a socket from an earlier run (closed by start()) are
    // ignored, so a late frame cannot overwrite the new link's state.
    const mine = run;
    socket ??= new GuestSocket({
      onStatus: (st) => {
        if (mine === run) onStatus(st);
      },
      onDrop: () => {
        if (mine === run) onDrop();
      },
    });
    socket.connect();
  }

  function submit(event: SubmitEvent): void {
    event.preventDefault();
    void redeem();
  }

  async function redeem(replaceCurrent = false): Promise<void> {
    const mine = run;
    failure = null;
    phase = "redeeming";
    const res = await redeemTicket(token, reason, fetch, replaceCurrent);
    if (mine !== run) return; // a newer link replaced this one meanwhile
    if (!res.ok) {
      failure = res.failure;
      phase = res.failure === "not-found" || res.failure === "forbidden" ? "invalid" : "form";
      return;
    }
    // The ticket is spent now; the link cannot be used again.
    token = "";
    code = res.redeemed.confirmationCode;
    clockOffset = res.clockOffsetMs;
    phase = "connecting";
    connect();
  }

  onMount(() => {
    ticker = setInterval(() => (now = serverNow()), 1000);
    // A new link typed or pasted into a tab already on /t changes only the
    // fragment: the browser fires hashchange instead of loading the page, so
    // the page starts over itself.
    window.addEventListener("hashchange", onHashChange);
    start(takeTokenFromLocation(window.location, window.history));
  });

  /** Phases with a live guest session in this tab (or one being set up). */
  const LIVE: Phase[] = ["redeeming", "connecting", "pending", "open"];

  function onHashChange(): void {
    const t = takeTokenFromLocation(window.location, window.history);
    if (t === null) return;
    if (LIVE.includes(phase)) {
      // One guest session at a time: a second link never replaces the live
      // one from here. It is dropped (the address bar is already clean);
      // the guest finishes or ends this session, then opens the link again.
      linkNotice =
        "This tab already has a guest session. End it first, then open the new link again.";
      return;
    }
    start(t);
  }

  /** Bumped by every (re)start: a request or socket of an earlier run ignores
   * its late results. */
  let run = 0;

  /** (Re)start the page for a token from the address bar, or for none. */
  function start(t: string | null): void {
    run++;
    socket?.close();
    socket = null;
    if (reconnectTimer) clearTimeout(reconnectTimer);
    reconnectTimer = null;
    token = reason = code = endedMessage = linkNotice = "";
    reasonRequired = failure = admissionDeadline = lifetimeDeadline = dropSince = null;
    reconnecting = sawStatus = false;
    if (t === null) {
      // No link in the address bar: a reload of a live guest session (the
      // cookie reattaches), or nothing to do here.
      phase = "connecting";
      connect();
      return;
    }
    if (t === "") {
      phase = "invalid";
      failure = "not-found";
      return;
    }
    token = t;
    phase = "loading";
    void checkLink();
  }

  /** Ask the server whether the link is still good before showing the form. */
  async function checkLink(): Promise<void> {
    const mine = run;
    const res = await checkTicket(token);
    if (mine !== run) return; // a newer link replaced this one meanwhile
    if (res.ok) reasonRequired = res.reasonRequired;
    else if (res.failure === "not-found" || res.failure === "forbidden") failure = res.failure;
    // Anything else could not tell (network, rate limit, server busy): show
    // the form; redeem gives the definite answer.
    phase = failure ? "invalid" : "form";
  }

  onDestroy(() => {
    window.removeEventListener("hashchange", onHashChange);
    if (ticker) clearInterval(ticker);
    if (reconnectTimer) clearTimeout(reconnectTimer);
    socket?.close();
  });
</script>

<svelte:head>
  <title>ShellWatch — guest access</title>
  <meta name="referrer" content="no-referrer" />
  <meta name="robots" content="noindex" />
</svelte:head>

{#snippet notice()}
  {#if linkNotice}
    <p class="link-notice" role="status">
      {linkNotice}
      <button type="button" class="btn btn-ghost" onclick={() => (linkNotice = "")}>OK</button>
    </p>
  {/if}
{/snippet}

{#if phase === "open"}
  <div class="guest-shell">
    <header class="guest-bar">
      <span class="guest-title">Guest session</span>
      <span class="guest-meta">
        {#if reconnecting}
          <span class="reconnecting">Reconnecting…</span>
        {/if}
        {#if lifetimeDeadline !== null}
          Ends in {fmt(secondsLeft(lifetimeDeadline))}
        {/if}
      </span>
      <button type="button" class="btn btn-secondary" onclick={() => socket?.end()}
        >End session</button
      >
    </header>
    {@render notice()}
    <div class="guest-term">
      {#if socket}
        <Terminal transport={socket} />
      {/if}
    </div>
  </div>
{:else}
  <main class="guest-page">
    <div class="guest-card">
      <h1>Guest access</h1>
      {@render notice()}

      {#if phase === "loading" || phase === "redeeming" || phase === "connecting"}
        <p class="muted">{reconnecting ? "Reconnecting…" : "Please wait…"}</p>
      {:else if phase === "form"}
        <p>
          Someone shared one-time access to a terminal with you. Say why you need it; the person who
          shared it has to approve the request.
        </p>
        <form onsubmit={submit}>
          <label for="reason"
            >Reason for access{#if reasonRequired === false}
              <span class="muted">(optional)</span>{/if}</label
          >
          <textarea
            id="reason"
            bind:value={reason}
            maxlength="200"
            required={reasonRequired === true}
            rows="3"
            autocomplete="off"
            placeholder="e.g. Fixing the print server, as discussed on the phone"
          ></textarea>
          {#if failure}
            <p class="error" role="alert">{REDEEM_FAILURE_TEXT[failure]}</p>
          {/if}
          {#if failure === "live-session"}
            <!-- 409: the server ends this browser's current guest session in the
              same step that redeems this link (the owner is not prompted for it). -->
            <button type="button" class="btn btn-warn" onclick={() => void redeem(true)}>
              End the current session and use this link
            </button>
          {:else}
            <button type="submit" class="btn btn-primary">Request access</button>
          {/if}
        </form>
        <p class="fineprint">
          Everything you type and see is visible to the owner, who can end the session at any time.
        </p>
      {:else if phase === "pending"}
        <p>Tell the person who shared the link this code:</p>
        <p class="code" aria-label="Confirmation code">{code}</p>
        <p class="muted">Waiting for approval… {fmt(secondsLeft(admissionDeadline))} left.</p>
        {#if reconnecting}
          <p class="muted">Reconnecting…</p>
        {/if}
        <button type="button" class="btn btn-ghost" onclick={() => socket?.end()}>Cancel</button>
      {:else if phase === "ended"}
        <p>{endedMessage}</p>
        <p class="muted">You can close this window.</p>
      {:else if phase === "invalid"}
        <p class="error" role="alert">
          {failure
            ? REDEEM_FAILURE_TEXT[failure]
            : "There is no active guest session in this browser."}
        </p>
        <p class="muted">Ask the person who shared it for a new link.</p>
      {/if}
    </div>
  </main>
{/if}

<style>
  .guest-page {
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: var(--space-5, 16px);
    background: var(--surface, #0e0e0e);
    color: var(--on-surface, #f2f2f2);
  }

  .guest-card {
    width: 100%;
    max-width: 440px;
    display: flex;
    flex-direction: column;
    gap: var(--space-4, 12px);
    padding: var(--space-6, 24px);
    background: var(--surface-container-low, #161616);
    border-radius: var(--radius-md, 8px);
  }

  h1 {
    margin: 0;
    font-size: var(--title-lg, 1.25rem);
  }

  form {
    display: flex;
    flex-direction: column;
    gap: var(--space-3, 8px);
  }

  textarea {
    width: 100%;
    resize: vertical;
    font: inherit;
    padding: var(--space-3, 8px);
    background: var(--surface-container, #1c1c1c);
    color: inherit;
    border: 1px solid var(--outline-variant, #333);
    border-radius: var(--radius-sm, 4px);
  }

  .code {
    font-family: var(--font-mono, monospace);
    font-size: 2.5rem;
    letter-spacing: 0.3em;
    text-align: center;
    margin: var(--space-2, 4px) 0;
    color: var(--primary, #69f6b8);
  }

  .muted,
  .fineprint {
    color: var(--on-surface-variant, #adaaaa);
  }

  .fineprint {
    font-size: var(--label-md, 0.8rem);
  }

  .error {
    color: var(--error, #ff5a5a);
  }

  .link-notice {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--space-3, 8px);
    margin: 0;
    padding: var(--space-2, 4px) var(--space-4, 12px);
    background: color-mix(in srgb, var(--warning, #f8a010) 12%, transparent);
    color: var(--on-surface, #f2f2f2);
    font-size: var(--label-md, 0.8rem);
  }

  .guest-shell {
    height: 100vh;
    display: flex;
    flex-direction: column;
    background: #0e0e0e;
  }

  .guest-bar {
    display: flex;
    align-items: center;
    gap: var(--space-4, 12px);
    padding: var(--space-2, 4px) var(--space-4, 12px);
    background: var(--surface-container-low, #161616);
    color: var(--on-surface, #f2f2f2);
    flex-shrink: 0;
  }

  .guest-title {
    font-weight: 600;
  }

  .guest-meta {
    flex: 1;
    color: var(--on-surface-variant, #adaaaa);
    font-family: var(--font-mono, monospace);
    font-size: var(--label-md, 0.8rem);
  }

  .reconnecting {
    color: var(--warning, #f8a010);
    margin-right: var(--space-3, 8px);
  }

  .guest-term {
    flex: 1;
    min-height: 0;
    padding: var(--space-2, 4px);
  }
</style>
