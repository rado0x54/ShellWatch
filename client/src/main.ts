import { closeSession, createSession, type Endpoint, fetchEndpoints } from "./api.js";
import { TerminalView } from "./terminal-view.js";
import { type SessionListEntry, WsClient } from "./ws-client.js";

const wsClient = new WsClient();
wsClient.connect();

const terminalView = new TerminalView(wsClient);

const endpointList = document.getElementById("endpoint-list") as HTMLElement;
const sessionList = document.getElementById("session-list") as HTMLElement;
const terminalContainer = document.getElementById("terminal-container") as HTMLElement;

// Track state
let endpoints: Endpoint[] = [];
let sessions: SessionListEntry[] = [];

// --- Render functions ---

function renderEndpoints() {
  endpointList.innerHTML = "";
  for (const ep of endpoints) {
    const li = document.createElement("li");
    li.innerHTML = `
      <div class="endpoint-item">
        <div class="endpoint-info">
          <span class="endpoint-label">${ep.label}</span>
          <span class="endpoint-detail">${ep.username}@${ep.host}:${ep.port}</span>
        </div>
        <button class="btn btn-connect" data-endpoint-id="${ep.id}">Connect</button>
      </div>
    `;
    li.querySelector("button")?.addEventListener("click", () => onConnect(ep.id));
    endpointList.appendChild(li);
  }
}

function renderSessions() {
  sessionList.innerHTML = "";
  if (sessions.length === 0) {
    sessionList.innerHTML =
      '<li style="color:#555;font-size:0.8rem;padding:0.25rem">No active sessions</li>';
    return;
  }
  const activeId = terminalView.getActiveSessionId();
  for (const sess of sessions) {
    const ep = endpoints.find((e) => e.id === sess.endpointId);
    const label = ep?.label ?? sess.endpointId;
    const isActive = sess.sessionId === activeId;

    const li = document.createElement("li");
    li.innerHTML = `
      <div class="session-item ${isActive ? "active" : ""}">
        <div class="session-info">
          <span class="session-label">
            <span class="status-dot ${sess.status}"></span>${label}
          </span>
          <span class="session-detail">${sess.sessionId} (${sess.source})</span>
        </div>
        <button class="btn btn-close" data-session-id="${sess.sessionId}">Close</button>
      </div>
    `;
    li.querySelector(".session-item")?.addEventListener("click", (e) => {
      if ((e.target as HTMLElement).tagName !== "BUTTON") {
        onAttach(sess.sessionId);
      }
    });
    li.querySelector(".btn-close")?.addEventListener("click", () => onClose(sess.sessionId));
    sessionList.appendChild(li);
  }
}

// --- Actions ---

async function onConnect(endpointId: string) {
  try {
    const session = await createSession(endpointId);
    // Session list will update via sessions:changed event
    onAttach(session.sessionId);
  } catch (err) {
    console.error("Failed to create session:", err);
  }
}

function onAttach(sessionId: string) {
  terminalView.attach(sessionId, terminalContainer);
  renderSessions();
}

async function onClose(sessionId: string) {
  try {
    await closeSession(sessionId);
    terminalView.removeSession(sessionId);
    // Session list will update via sessions:changed event
    if (sessions.length === 0) {
      terminalContainer.innerHTML =
        '<div id="terminal-placeholder">Select an endpoint to connect</div>';
    }
  } catch (err) {
    console.error("Failed to close session:", err);
  }
}

// --- Listen for real-time session updates ---

wsClient.onMessage((msg) => {
  if (msg.type === "sessions:changed") {
    const oldIds = new Set(sessions.map((s) => s.sessionId));
    sessions = msg.sessions;
    renderSessions();

    // Clean up terminals for sessions that no longer exist
    for (const oldId of oldIds) {
      if (!sessions.some((s) => s.sessionId === oldId)) {
        terminalView.removeSession(oldId);
      }
    }

    // Auto-attach to a new session if none is active
    if (!terminalView.getActiveSessionId() && sessions.length > 0) {
      const newSession = sessions.find((s) => !oldIds.has(s.sessionId));
      if (newSession) {
        onAttach(newSession.sessionId);
      }
    }

    // Show placeholder if no sessions left
    if (sessions.length === 0 && !terminalView.getActiveSessionId()) {
      terminalContainer.innerHTML =
        '<div id="terminal-placeholder">Select an endpoint to connect</div>';
    }
  }

  if (msg.type === "terminal:closed") {
    terminalView.removeSession(msg.sessionId);
  }
});

// --- Init ---

async function init() {
  endpoints = await fetchEndpoints();
  renderEndpoints();
  // Session list comes via WebSocket sessions:changed on connect
}

init();
