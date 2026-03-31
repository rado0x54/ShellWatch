import { startAuthentication } from "@simplewebauthn/browser";
import { basePath } from "./base-path.js";

const btn = document.getElementById("login-btn") as HTMLButtonElement;
const errorMsg = document.getElementById("error-msg") as HTMLElement;
const statusMsg = document.getElementById("status-msg") as HTMLElement;

async function login() {
  btn.disabled = true;
  errorMsg.style.display = "none";
  statusMsg.textContent = "Waiting for passkey...";

  try {
    // Get assertion options
    const optionsRes = await fetch(`${basePath}/api/webauthn/login/options`, {
      method: "POST",
    });
    if (!optionsRes.ok) {
      const err = await optionsRes.json();
      throw new Error(err.error || "Failed to get login options");
    }
    const { challengeId, ...options } = await optionsRes.json();

    // Browser WebAuthn prompt
    const credential = await startAuthentication({ optionsJSON: options });

    // Verify with server
    statusMsg.textContent = "Verifying...";
    const verifyRes = await fetch(`${basePath}/api/webauthn/login/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ challengeId, credential }),
    });

    if (!verifyRes.ok) {
      const err = await verifyRes.json();
      throw new Error(err.error || "Verification failed");
    }

    // Success — redirect to app
    window.location.href = `${basePath}/`;
  } catch (err) {
    errorMsg.textContent = (err as Error).message;
    errorMsg.style.display = "block";
    statusMsg.textContent = "";
    btn.disabled = false;
  }
}

btn.addEventListener("click", login);
