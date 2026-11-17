<!-- SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0 -->
<script lang="ts">
  // One-time access guest page (#306). Opened on an untrusted browser from a
  // link the owner shared: `/t#<token>`. The guest states a reason, redeems
  // the ticket, and waits while the owner approves on a trusted device. It
  // ends up with a terminal on one endpoint and nothing else.
  //
  // This page is a public path: the root layout skips the authenticated
  // bootstrap here (no token refresh, no OAuth redirect, no /ws, no fetches).
  // It never reads the SPA's stored tokens, never sends Authorization and
  // stores nothing; the HttpOnly guest cookie is its only credential. It has
  // no client-side links into the app.
  import { onDestroy, onMount } from "svelte";
  import GuestTerminal from "$lib/components/GuestTerminal.svelte";
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

  type Phase =
    | "loading"
    | "form"
    | "redeeming"
    | "connecting"
    | "pending"
    | "refused"
    | "open"
    | "ended"
    | "invalid";

  const RECONNECT_DELAY_MS = 2000;
  /** Matches the server's reconnect grace: past it the session is gone. */
  const RECONNECT_GIVE_UP_MS = 60_000;
  /** A reload with no token: how long to retry the first handshake before
   * concluding this browser has no guest session. */
  const RELOAD_ATTACH_RETRY_MS = 5000;

  let phase = $state<Phase>("loading");
  let token = $state("");
  let reason = $state("");
  /** From the check; unknown (null) when it could not tell: then the field
   * is shown as before and redeem enforces it. */
  let reasonRequired = $state<boolean | null>(null);
  let failure = $state<RedeemFailure | null>(null);
  let code = $state("");
  let admissionDeadline = $state<number | null>(null);
  let retryAt = $state<number | null>(null);
  let attemptsLeft = $state<number | null>(null);
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
  let socket: GuestSocket | null = null;
  let term = $state<GuestTerminal | null>(null);
  let dropSince: number | null = null;
  /** Until when a failed first handshake is retried: right after redeeming
   * this is the server's attach deadline (the session stays attachable until
   * then), so one network blip or 429 cannot lock out a guest whose ticket
   * is already spent. */
  let firstConnectDeadline = 0;
  let ticker: ReturnType<typeof setInterval> | null = null;
  let reconnectTimer: ReturnType<typeof setTimeout> | null = null;

  const secondsLeft = (deadline: number | null): number =>
    // Rounded up: a countdown (and the Ask again button) never reaches 0
    // before the deadline itself.
    deadline === null ? 0 : Math.max(0, Math.ceil((deadline - now) / 1000));

  function fmt(seconds: number): string {
    const m = Math.floor(seconds / 60);
    const s = seconds % 60;
    return `${m}:${String(s).padStart(2, "0")}`;
  }

  function onStatus(st: GuestStatus): void {
    if (st.serverTime) {
      clockOffset = clockOffsetMs(st.serverTime, Date.now());
      now = serverNow();
    }
    reconnecting = false;
    dropSince = null;
    if (st.code) code = st.code;
    if (st.admissionDeadline) admissionDeadline = Date.parse(st.admissionDeadline);
    switch (st.state) {
      case "pending":
        phase = "pending";
        break;
      case "refused":
        retryAt = st.retryAt ? Date.parse(st.retryAt) : null;
        attemptsLeft = st.attemptsLeft ?? null;
        phase = "refused";
        break;
      case "open":
        if (st.lifetimeDeadline) lifetimeDeadline = Date.parse(st.lifetimeDeadline);
        phase = "open";
        break;
      case "closed":
        endedMessage = st.message ?? "The session has ended.";
        phase = "ended";
        socket?.close();
        socket = null;
        break;
    }
  }

  function onDrop(): void {
    if (phase === "ended" || phase === "invalid") return;
    if (phase === "connecting" && dropSince === null && !reconnecting) {
      // The first handshake failed. Keep trying while the session can still
      // be attached. Past that, there is no guest session for this browser
      // (reload after the session ended, or a copied URL).
      if (Date.now() < firstConnectDeadline) {
        reconnectTimer = setTimeout(connect, RECONNECT_DELAY_MS);
        return;
      }
      phase = "invalid";
      failure = null;
      return;
    }
    const t = Date.now();
    dropSince ??= t;
    if (t - dropSince > RECONNECT_GIVE_UP_MS) {
      endedMessage = "The connection was lost and the session has ended.";
      phase = "ended";
      return;
    }
    reconnecting = true;
    reconnectTimer = setTimeout(connect, RECONNECT_DELAY_MS);
  }

  // Output that arrives before the terminal is mounted (the catch-up frame
  // follows the open status immediately) is held until it is.
  const heldOutput: Array<{ data: string; reset: boolean }> = [];

  $effect(() => {
    if (term) for (const o of heldOutput.splice(0)) term.write(o.data, o.reset);
  });

  function connect(): void {
    // Callbacks of a socket from an earlier run (closed by start()) are
    // ignored, so a late frame cannot overwrite the new link's state.
    const mine = run;
    socket = new GuestSocket({
      onStatus: (st) => {
        if (mine === run) onStatus(st);
      },
      onOutput: (data, reset) => {
        if (mine !== run) return;
        if (term) term.write(data, reset);
        else heldOutput.push({ data, reset });
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
    // In local time: the server's attach deadline shifted by the offset.
    const attachBy = Date.parse(res.redeemed.attachDeadline) - clockOffset;
    firstConnectDeadline = Number.isNaN(attachBy) ? Date.now() + 30_000 : attachBy;
    phase = "connecting";
    connect();
  }

  /** 409: the server ends this browser's current guest session in the same
   * step that redeems this link (no reconnect to the old session, so the
   * owner is not prompted for it). */
  function endCurrentAndContinue(): void {
    void redeem(true);
  }

  function askAgain(): void {
    socket?.retry();
  }

  function endSession(): void {
    socket?.end();
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
  const LIVE: Phase[] = ["redeeming", "connecting", "pending", "refused", "open"];

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
    heldOutput.length = 0;
    token = "";
    reason = "";
    reasonRequired = null;
    failure = null;
    code = "";
    admissionDeadline = null;
    retryAt = null;
    attemptsLeft = null;
    lifetimeDeadline = null;
    endedMessage = "";
    linkNotice = "";
    reconnecting = false;
    dropSince = null;
    if (t === null) {
      // No link in the address bar: a reload of a live guest session (the
      // cookie reattaches), or nothing to do here.
      phase = "connecting";
      firstConnectDeadline = Date.now() + RELOAD_ATTACH_RETRY_MS;
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
    if (res.ok) {
      reasonRequired = res.reasonRequired;
      phase = "form";
      return;
    }
    if (res.failure === "not-found" || res.failure === "forbidden") {
      failure = res.failure;
      phase = "invalid";
      return;
    }
    // Could not tell (network, rate limit, server busy): show the form;
    // redeem gives the definite answer.
    phase = "form";
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
      <button type="button" class="btn btn-secondary" onclick={endSession}>End session</button>
    </header>
    {#if linkNotice}
      <p class="link-notice" role="status">
        {linkNotice}
        <button type="button" class="btn btn-ghost" onclick={() => (linkNotice = "")}>OK</button>
      </p>
    {/if}
    <div class="guest-term">
      <GuestTerminal
        bind:this={term}
        onInput={(data) => socket?.input(data)}
        onResize={(cols, rows) => socket?.resize(cols, rows)}
      />
    </div>
  </div>
{:else}
  <main class="guest-page">
    <div class="guest-card">
      <h1>Guest access</h1>
      {#if linkNotice}
        <p class="link-notice" role="status">
          {linkNotice}
          <button type="button" class="btn btn-ghost" onclick={() => (linkNotice = "")}>OK</button>
        </p>
      {/if}

      {#if phase === "loading" || phase === "redeeming" || phase === "connecting"}
        <p class="muted">Please wait…</p>
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
            <button type="button" class="btn btn-warn" onclick={endCurrentAndContinue}>
              End the current session and use this link
            </button>
          {:else}
            <button type="submit" class="btn btn-primary">Request access</button>
          {/if}
        </form>
        <p class="fineprint">
          Everything you type and see is visible to the owner, who can end the session at any time.
        </p>
      {:else if phase === "pending" || phase === "refused"}
        <p>Tell the person who shared the link this code:</p>
        <p class="code" aria-label="Confirmation code">{code}</p>
        {#if phase === "pending"}
          <p class="muted">Waiting for approval… {fmt(secondsLeft(admissionDeadline))} left.</p>
        {:else}
          <p class="error" role="alert">Access was not granted.</p>
          {@const wait = secondsLeft(retryAt)}
          <p class="muted">
            You can ask again for {fmt(secondsLeft(admissionDeadline))}{attemptsLeft !== null
              ? ` (${attemptsLeft} ${attemptsLeft === 1 ? "try" : "tries"} left)`
              : ""}.
          </p>
          <button type="button" class="btn btn-primary" onclick={askAgain} disabled={wait > 0}>
            {wait > 0 ? `Ask again in ${fmt(wait)}` : "Ask again"}
          </button>
        {/if}
        {#if reconnecting}
          <p class="muted">Reconnecting…</p>
        {/if}
        <button type="button" class="btn btn-ghost" onclick={endSession}>Cancel</button>
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
