import { closeSession, createSession, type Endpoint, fetchEndpoints } from "./api.js";
import { TerminalView } from "./terminal-view.js";
import { type SessionListEntry, WsClient } from "./ws-client.js";

const wsClient = new WsClient();
wsClient.connect();

const terminalView = new TerminalView(wsClient);

const endpointList = document.getElementById("endpoint-list") as HTMLElement;
const sessionList = document.getElementById("session-list") as HTMLElement;
const terminalContainer = document.getElementById("terminal-container") as HTMLElement;

let endpoints: Endpoint[] = [];
let sessions: SessionListEntry[] = [];

// Re-render sessions when a terminal's mode changes
terminalView.setModeChangeCallback(() => renderSessions());

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
    const mode = terminalView.getMode(sess.sessionId) ?? sess.mode;
    const isObserver = mode === "observer";

    const li = document.createElement("li");
    li.innerHTML = `
      <div class="session-item ${isActive ? "active" : ""}">
        <div class="session-info">
          <span class="session-label">
            <span class="status-dot ${sess.status}"></span>${label}
            ${isObserver ? '<span class="badge badge-observer">observer</span>' : ""}
          </span>
          <span class="session-detail">${sess.sessionId} (${sess.source})</span>
        </div>
        <div class="session-actions">
          ${isObserver ? `<button class="btn btn-take-control" data-session-id="${sess.sessionId}">Take Control</button>` : ""}
          <button class="btn btn-close" data-session-id="${sess.sessionId}">Close</button>
        </div>
      </div>
    `;
    li.querySelector(".session-item")?.addEventListener("click", (e) => {
      const target = e.target as HTMLElement;
      if (target.tagName !== "BUTTON") {
        onAttach(sess.sessionId, mode);
      }
    });
    li.querySelector(".btn-take-control")?.addEventListener("click", () => {
      wsClient.takeControl(sess.sessionId);
    });
    li.querySelector(".btn-close")?.addEventListener("click", () => onClose(sess.sessionId));
    sessionList.appendChild(li);
  }
}

async function onConnect(endpointId: string) {
  try {
    const session = await createSession(endpointId);
    onAttach(session.sessionId, "control");
  } catch (err) {
    console.error("Failed to create session:", err);
  }
}

function onAttach(sessionId: string, mode: "control" | "observer" = "control") {
  terminalView.attach(sessionId, terminalContainer, mode);
  renderSessions();
}

async function onClose(sessionId: string) {
  try {
    await closeSession(sessionId);
    terminalView.removeSession(sessionId);
    if (sessions.length === 0) {
      terminalContainer.innerHTML =
        '<div id="terminal-placeholder">Select an endpoint to connect</div>';
    }
  } catch (err) {
    console.error("Failed to close session:", err);
  }
}

wsClient.onMessage((msg) => {
  if (msg.type === "sessions:changed") {
    const oldIds = new Set(sessions.map((s) => s.sessionId));
    sessions = msg.sessions;
    renderSessions();

    for (const oldId of oldIds) {
      if (!sessions.some((s) => s.sessionId === oldId)) {
        terminalView.removeSession(oldId);
      }
    }

    // Auto-attach new sessions as observer if none is active
    if (!terminalView.getActiveSessionId() && sessions.length > 0) {
      const newSession = sessions.find((s) => !oldIds.has(s.sessionId));
      if (newSession) {
        onAttach(newSession.sessionId, newSession.mode);
      }
    }

    if (sessions.length === 0 && !terminalView.getActiveSessionId()) {
      terminalContainer.innerHTML =
        '<div id="terminal-placeholder">Select an endpoint to connect</div>';
    }
  }

  if (msg.type === "terminal:closed") {
    terminalView.removeSession(msg.sessionId);
  }
});

// --- Passkey management ---

import {
  deleteCredential,
  listCredentials,
  registerPasskey,
  type WebAuthnCredential,
} from "./webauthn.js";

const passkeyList = document.getElementById("passkey-list") as HTMLElement;
const registerBtn = document.getElementById("register-passkey-btn") as HTMLElement;

let passkeys: WebAuthnCredential[] = [];

function renderPasskeys() {
  passkeyList.innerHTML = "";
  if (passkeys.length === 0) {
    passkeyList.innerHTML =
      '<li style="color:#555;font-size:0.8rem;padding:0.25rem">No passkeys registered</li>';
    return;
  }
  for (const pk of passkeys) {
    const li = document.createElement("li");
    li.innerHTML = `
      <div class="endpoint-item" style="flex-direction:column;align-items:stretch;gap:0.4rem">
        <div style="display:flex;justify-content:space-between;align-items:center">
          <div class="endpoint-info">
            <span class="endpoint-label">${pk.label}</span>
            <span class="endpoint-detail">${pk.algorithm} &middot; ${pk.fingerprint.slice(0, 20)}...</span>
          </div>
          <button type="button" class="btn btn-close" data-id="${pk.id}">Remove</button>
        </div>
        ${
          pk.authorizedKeysEntry
            ? `<div style="display:flex;gap:0.25rem">
            <button type="button" class="btn btn-copy-key" style="font-size:0.65rem;padding:0.2rem 0.4rem;background:#2a2a4a;color:#8888aa">Copy SSH Key</button>
            <button type="button" class="btn btn-copy-config" style="font-size:0.65rem;padding:0.2rem 0.4rem;background:#2a2a4a;color:#8888aa">Copy sshd_config</button>
          </div>`
            : ""
        }
      </div>
    `;
    li.querySelector(".btn-close")?.addEventListener("click", async () => {
      await deleteCredential(pk.id);
      await refreshPasskeys();
    });
    li.querySelector(".btn-copy-key")?.addEventListener("click", () => {
      if (pk.authorizedKeysEntry) {
        navigator.clipboard.writeText(pk.authorizedKeysEntry);
        const btn = li.querySelector(".btn-copy-key") as HTMLElement;
        btn.textContent = "Copied!";
        setTimeout(() => {
          btn.textContent = "Copy SSH Key";
        }, 1500);
      }
    });
    li.querySelector(".btn-copy-config")?.addEventListener("click", () => {
      navigator.clipboard.writeText(
        "PubkeyAcceptedAlgorithms=+webauthn-sk-ecdsa-sha2-nistp256@openssh.com",
      );
      const btn = li.querySelector(".btn-copy-config") as HTMLElement;
      btn.textContent = "Copied!";
      setTimeout(() => {
        btn.textContent = "Copy sshd_config";
      }, 1500);
    });
    passkeyList.appendChild(li);
  }
}

async function refreshPasskeys() {
  passkeys = await listCredentials();
  renderPasskeys();
}

registerBtn.addEventListener("click", async () => {
  const label = prompt("Passkey label (e.g., YubiKey 5 NFC):");
  if (!label) return;
  try {
    await registerPasskey(label);
    await refreshPasskeys();
  } catch (err) {
    console.error("Passkey registration failed:", err);
    alert(`Registration failed: ${(err as Error).message}`);
  }
});

// --- Init ---

async function init() {
  endpoints = await fetchEndpoints();
  renderEndpoints();
  await refreshPasskeys();
}

init();
