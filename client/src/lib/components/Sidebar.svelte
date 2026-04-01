<script lang="ts">
import { goto } from "$app/navigation";
import { page } from "$app/stores";
import { endpoints, fetchEndpoints } from "$lib/stores/endpoints.js";
import { closeSession, createSession } from "$lib/stores/sessions-api.js";
import { sessions, wsReleaseControl, wsTakeControl } from "$lib/stores/ws.js";

interface Props {
  activeSessionId: string | null;
  sessionModes: Record<string, string>;
  onConnect: (sessionId: string, mode: "control" | "observer") => void;
  onMobileClose?: () => void;
}

let { activeSessionId, sessionModes, onConnect, onMobileClose }: Props = $props();

const currentPath = $derived($page.url.pathname);

async function handleConnect(endpointId: string) {
  try {
    if (currentPath !== "/") {
      await goto("/");
    }
    const session = await createSession(endpointId);
    onConnect(session.sessionId, "control");
    onMobileClose?.();
  } catch (err) {
    console.error("Failed to create session:", err);
  }
}

async function handleClose(sessionId: string) {
  try {
    await closeSession(sessionId);
  } catch (err) {
    console.error("Failed to close session:", err);
  }
}

function handleSessionClick(sessionId: string, mode: "control" | "observer") {
  if (currentPath !== "/") {
    goto("/");
  }
  onConnect(sessionId, mode);
  onMobileClose?.();
}

function getEndpointLabel(endpointId: string): string {
  const ep = $endpoints.find((e) => e.id === endpointId);
  return ep?.label ?? endpointId;
}

function navTo(path: string) {
  goto(path);
  onMobileClose?.();
}
</script>

<nav class="sidebar">
  <div class="sidebar-section">
    <h2>Endpoints</h2>
    <ul>
      {#each $endpoints as ep (ep.id)}
        <li>
          <div class="endpoint-item">
            <div class="endpoint-info">
              <span class="endpoint-label">{ep.label}</span>
              <span class="endpoint-detail">{ep.username}@{ep.host}:{ep.port}</span>
            </div>
            <button class="btn btn-primary" onclick={() => handleConnect(ep.id)}>Connect</button>
          </div>
        </li>
      {/each}
    </ul>
  </div>

  <div class="sidebar-section">
    <h2>Sessions</h2>
    <ul>
      {#if $sessions.length === 0}
        <li class="no-sessions">No active sessions</li>
      {/if}
      {#each $sessions as sess (sess.sessionId)}
        {@const mode = sessionModes[sess.sessionId] ?? sess.mode}
        {@const isActive = sess.sessionId === activeSessionId}
        {@const isObserver = mode === "observer"}
        <li>
          <!-- svelte-ignore a11y_click_events_have_key_events -->
          <!-- svelte-ignore a11y_no_static_element_interactions -->
          <div
            class="session-item"
            class:active={isActive}
            onclick={(e) => {
              if ((e.target as HTMLElement).tagName !== "BUTTON") {
                handleSessionClick(sess.sessionId, mode as "control" | "observer");
              }
            }}
          >
            <div class="session-info">
              <span class="session-label">
                <span class="status-dot {sess.status}"></span>{getEndpointLabel(sess.endpointId)}
                {#if isObserver}
                  <span class="badge badge-observer">observer</span>
                {/if}
              </span>
              <span class="session-detail">{sess.sessionId} ({sess.source})</span>
            </div>
            <div class="session-actions">
              {#if isObserver}
                <button class="btn btn-warn" onclick={() => wsTakeControl(sess.sessionId)}>Take Control</button>
              {:else}
                <button class="btn btn-ghost" onclick={() => wsReleaseControl(sess.sessionId)}>Release</button>
              {/if}
              <button class="btn btn-secondary" onclick={() => handleClose(sess.sessionId)}>Close</button>
            </div>
          </div>
        </li>
      {/each}
    </ul>
  </div>

  <div class="sidebar-footer">
    <button class="btn-nav" class:active={currentPath === "/observer"} onclick={() => navTo("/observer")}>
      Observer Mode
    </button>
    <button class="btn-nav" class:active={currentPath.startsWith("/settings")} onclick={() => navTo("/settings")}>
      Settings
    </button>
  </div>
</nav>

<style>
  .sidebar {
    width: var(--sidebar-width);
    min-width: var(--sidebar-width);
    background: var(--bg-secondary);
    border-right: 1px solid var(--border);
    display: flex;
    flex-direction: column;
    overflow-y: auto;
    height: 100%;
  }

  .sidebar-section {
    padding: 1rem;
    border-bottom: 1px solid var(--border);
  }

  .sidebar-section h2 {
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--text-muted);
    margin-bottom: 0.75rem;
  }

  .sidebar-section ul {
    list-style: none;
  }

  .sidebar-section li {
    margin-bottom: 0.5rem;
  }

  .no-sessions {
    color: #555;
    font-size: 0.8rem;
    padding: 0.25rem;
  }

  .endpoint-item {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 0.5rem 0.75rem;
    background: var(--bg-primary);
    border-radius: 6px;
    border: 1px solid var(--border);
  }

  .endpoint-info {
    display: flex;
    flex-direction: column;
    gap: 0.15rem;
  }

  .endpoint-label {
    font-weight: 600;
    font-size: 0.875rem;
  }

  .endpoint-detail {
    font-size: 0.75rem;
    color: var(--text-muted);
  }

  .session-item {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 0.5rem 0.75rem;
    background: var(--bg-primary);
    border-radius: 6px;
    border: 1px solid var(--border);
    cursor: pointer;
  }

  .session-item.active {
    border-color: var(--accent);
  }

  .session-info {
    display: flex;
    flex-direction: column;
    gap: 0.15rem;
    min-width: 0;
  }

  .session-label {
    font-size: 0.875rem;
    font-weight: 500;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .session-detail {
    font-size: 0.7rem;
    color: var(--text-muted);
  }

  .session-actions {
    display: flex;
    gap: 0.25rem;
    flex-shrink: 0;
  }

  .sidebar-footer {
    margin-top: auto;
    padding: 1rem;
    border-top: 1px solid var(--border);
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }

  .btn-nav {
    width: 100%;
    background: #2a2a4a;
    color: var(--text-muted);
    padding: 0.5rem;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    font-size: 0.8rem;
  }

  .btn-nav:hover {
    background: #3a3a5a;
    color: var(--text-primary);
  }

  .btn-nav.active {
    background: var(--accent);
    color: #fff;
  }

  @media (max-width: 768px) {
    .sidebar {
      width: 100%;
      min-width: 100%;
    }
  }
</style>
