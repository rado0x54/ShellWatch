import { closeSession, createSession, type Endpoint, fetchEndpoints } from "./api.js";
import { SettingsPage } from "./settings.js";
import { TerminalView } from "./terminal-view.js";
import { type SessionListEntry, WsClient } from "./ws-client.js";

const wsClient = new WsClient();
wsClient.connect();

const terminalView = new TerminalView(wsClient);

const endpointList = document.getElementById("endpoint-list") as HTMLElement;
const sessionList = document.getElementById("session-list") as HTMLElement;
const terminalContainer = document.getElementById("terminal-container") as HTMLElement;
const settingsContainer = document.getElementById("settings-page") as HTMLElement;
const settingsBtn = document.getElementById("settings-btn") as HTMLElement;

let endpoints: Endpoint[] = [];
let sessions: SessionListEntry[] = [];

// Settings page
const settingsPage = new SettingsPage(settingsContainer, () => {
  // On close: show terminal, refresh endpoints
  terminalContainer.style.display = "block";
  refreshEndpoints();
});

settingsBtn.addEventListener("click", () => {
  terminalContainer.style.display = "none";
  settingsPage.show();
});

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
          ${isObserver ? `<button class="btn btn-take-control" data-session-id="${sess.sessionId}">Take Control</button>` : `<button class="btn btn-release-control" data-session-id="${sess.sessionId}">Release</button>`}
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
    li.querySelector(".btn-release-control")?.addEventListener("click", () => {
      wsClient.releaseControl(sess.sessionId);
    });
    li.querySelector(".btn-close")?.addEventListener("click", () => onClose(sess.sessionId));
    sessionList.appendChild(li);
  }
}

async function onConnect(endpointId: string) {
  try {
    // Hide settings if open
    settingsPage.hide();
    terminalContainer.style.display = "block";
    const session = await createSession(endpointId);
    onAttach(session.sessionId, "control");
  } catch (err) {
    console.error("Failed to create session:", err);
  }
}

function onAttach(sessionId: string, mode: "control" | "observer" = "control") {
  settingsPage.hide();
  terminalContainer.style.display = "block";
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

  // Handle FIDO signing requests from the server
  if (msg.type === "fido:sign-request") {
    handleFidoSignRequest(msg);
  }
});

async function handleFidoSignRequest(request: {
  requestId: string;
  credentialId: string;
  challenge: string;
  rpId: string;
}) {
  try {
    // Convert standard base64 challenge to ArrayBuffer
    const decoded = atob(request.challenge);
    const challengeBytes = Uint8Array.from(decoded, (c) => c.charCodeAt(0));

    // Convert credentialId from base64url to ArrayBuffer
    const credIdBytes = Uint8Array.from(
      atob(request.credentialId.replace(/-/g, "+").replace(/_/g, "/")),
      (c) => c.charCodeAt(0),
    );

    const assertion = (await navigator.credentials.get({
      publicKey: {
        challenge: challengeBytes,
        rpId: request.rpId,
        allowCredentials: [
          {
            id: credIdBytes,
            type: "public-key",
            transports: ["usb", "nfc", "ble", "internal"],
          },
        ],
        userVerification: "discouraged",
        timeout: 60000,
      },
    })) as PublicKeyCredential;

    if (!assertion?.response) {
      throw new Error("No assertion returned");
    }

    const authResponse = assertion.response as AuthenticatorAssertionResponse;

    wsClient.send({
      type: "fido:sign-response",
      requestId: request.requestId,
      authenticatorData: bufferToBase64url(authResponse.authenticatorData),
      signature: bufferToBase64url(authResponse.signature),
      clientDataJSON: new TextDecoder().decode(authResponse.clientDataJSON),
    });
  } catch (err) {
    console.error("[FIDO] Signing failed:", err);
    wsClient.send({
      type: "fido:sign-error",
      requestId: request.requestId,
      error: (err as Error).message,
    });
  }
}

function bufferToBase64url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function refreshEndpoints() {
  endpoints = await fetchEndpoints();
  renderEndpoints();
}

async function init() {
  await refreshEndpoints();
}

init();
