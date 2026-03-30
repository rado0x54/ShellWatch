import { basePath } from "./base-path.js";
import {
  deleteCredential,
  listCredentials,
  registerPasskey,
  type WebAuthnCredential,
} from "./webauthn.js";

interface EndpointData {
  id: string;
  label: string;
  host: string;
  port: number;
  username: string;
  keyId: string | null;
}

interface SshKeyData {
  id: string;
  label: string;
  type: string;
  fingerprint: string;
  available: boolean;
  authorizedKeysEntry: string | null;
}

export class SettingsPage {
  private container: HTMLElement;
  private onClose: () => void;

  constructor(container: HTMLElement, onClose: () => void) {
    this.container = container;
    this.onClose = onClose;
  }

  async show(): Promise<void> {
    this.container.style.display = "block";
    await this.render();
  }

  hide(): void {
    this.container.style.display = "none";
    this.container.innerHTML = "";
  }

  private async render(): Promise<void> {
    const [endpoints, keys, passkeys] = await Promise.all([
      this.fetchEndpoints(),
      this.fetchKeys(),
      listCredentials(),
    ]);

    this.container.innerHTML = `
      <div class="settings">
        <div class="settings-header">
          <h1>Settings</h1>
          <button type="button" class="btn btn-close" id="settings-close">Back</button>
        </div>

        <section class="settings-section">
          <h2>SSH Endpoints</h2>
          <table class="settings-table">
            <thead>
              <tr><th>ID</th><th>Label</th><th>Host</th><th>Port</th><th>Username</th><th>Key</th><th></th></tr>
            </thead>
            <tbody id="endpoints-tbody">
              ${endpoints
                .map(
                  (ep) => `
                <tr>
                  <td>${ep.id}</td>
                  <td>${ep.label}</td>
                  <td>${ep.host}</td>
                  <td>${ep.port}</td>
                  <td>${ep.username}</td>
                  <td>${ep.keyId ?? "—"}</td>
                  <td><button type="button" class="btn btn-close btn-delete-endpoint" data-id="${ep.id}">Delete</button></td>
                </tr>
              `,
                )
                .join("")}
            </tbody>
          </table>
          <div class="settings-form" id="add-endpoint-form">
            <h3>Add Endpoint</h3>
            <div class="form-row">
              <input type="text" placeholder="ID" id="ep-id" />
              <input type="text" placeholder="Label" id="ep-label" />
              <input type="text" placeholder="Host" id="ep-host" />
              <input type="number" placeholder="Port" id="ep-port" value="22" />
              <input type="text" placeholder="Username" id="ep-username" />
              <select id="ep-keyId">
                <option value="">No key</option>
                ${keys.map((k) => `<option value="${k.id}">${k.label} (${k.type})</option>`).join("")}
              </select>
              <button type="button" class="btn btn-connect" id="ep-add-btn">Add</button>
            </div>
          </div>
        </section>

        <section class="settings-section">
          <h2>SSH Keys</h2>
          <table class="settings-table">
            <thead>
              <tr><th>ID</th><th>Label</th><th>Type</th><th>Status</th><th>Fingerprint</th><th></th></tr>
            </thead>
            <tbody>
              ${keys
                .map(
                  (k) => `
                <tr>
                  <td>${k.id}</td>
                  <td>${k.label}</td>
                  <td>${k.type}</td>
                  <td><span class="badge ${k.available ? "badge-available" : "badge-unavailable"}">${k.available ? "available" : "unavailable"}</span></td>
                  <td style="font-family:monospace;font-size:0.75rem">${k.fingerprint}</td>
                  <td>${k.authorizedKeysEntry ? `<button type="button" class="btn btn-copy-authkey" data-key="${encodeURIComponent(k.authorizedKeysEntry)}" style="font-size:0.65rem">Copy authorized_keys</button>` : ""}</td>
                </tr>
              `,
                )
                .join("")}
              ${keys.length === 0 ? '<tr><td colspan="6" style="color:#555">No keys found</td></tr>' : ""}
            </tbody>
          </table>
        </section>

        <section class="settings-section">
          <h2>Passkeys (WebAuthn)</h2>
          <table class="settings-table">
            <thead>
              <tr><th>Label</th><th>Algorithm</th><th>Fingerprint</th><th>Created</th><th></th></tr>
            </thead>
            <tbody id="passkeys-tbody">
              ${passkeys.map((pk) => this.renderPasskeyRow(pk)).join("")}
              ${passkeys.length === 0 ? '<tr><td colspan="5" style="color:#555">No passkeys registered</td></tr>' : ""}
            </tbody>
          </table>
          ${
            passkeys.some((pk) => pk.authorizedKeysEntry)
              ? `
            <div class="settings-info">
              <h3>SSH Server Setup</h3>
              <p>Add this line to <code>/etc/ssh/sshd_config</code> on your remote server:</p>
              <pre class="code-block" id="sshd-config-block">PubkeyAcceptedAlgorithms=+webauthn-sk-ecdsa-sha2-nistp256@openssh.com</pre>
              <p>Then add the passkey's SSH public key to <code>~/.ssh/authorized_keys</code>.</p>
            </div>
          `
              : ""
          }
          <div style="margin-top:1rem">
            <button type="button" class="btn btn-connect" id="register-passkey-settings">Register New Passkey</button>
          </div>
        </section>
      </div>
    `;

    this.attachEvents(passkeys);
  }

  private renderPasskeyRow(pk: WebAuthnCredential): string {
    return `
      <tr>
        <td>${pk.label}</td>
        <td>${pk.algorithm}</td>
        <td style="font-family:monospace;font-size:0.75rem">${pk.fingerprint.slice(0, 25)}...</td>
        <td>${pk.createdAt.slice(0, 10)}</td>
        <td>
          ${pk.authorizedKeysEntry ? `<button type="button" class="btn btn-copy-key" data-key="${encodeURIComponent(pk.authorizedKeysEntry)}" style="font-size:0.65rem">Copy SSH Key</button>` : ""}
          <button type="button" class="btn btn-close btn-delete-passkey" data-id="${pk.id}">Delete</button>
        </td>
      </tr>
    `;
  }

  private attachEvents(_passkeys: WebAuthnCredential[]): void {
    this.container.querySelector("#settings-close")?.addEventListener("click", () => {
      this.hide();
      this.onClose();
    });

    // Delete endpoint
    for (const btn of this.container.querySelectorAll(".btn-delete-endpoint")) {
      btn.addEventListener("click", async () => {
        const id = (btn as HTMLElement).dataset.id;
        if (id && confirm(`Delete endpoint "${id}"?`)) {
          await fetch(`${basePath}/api/endpoints/${id}`, { method: "DELETE" });
          await this.render();
        }
      });
    }

    // Add endpoint
    this.container.querySelector("#ep-add-btn")?.addEventListener("click", async () => {
      const get = (id: string) =>
        (this.container.querySelector(`#${id}`) as HTMLInputElement)?.value;
      const body = {
        id: get("ep-id"),
        label: get("ep-label"),
        host: get("ep-host"),
        port: Number.parseInt(get("ep-port") || "22", 10),
        username: get("ep-username"),
        keyId: get("ep-keyId") || undefined,
      };
      if (!body.id || !body.label || !body.host || !body.username) {
        alert("ID, Label, Host, and Username are required");
        return;
      }
      const res = await fetch(`${basePath}/api/endpoints`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      if (!res.ok) {
        const err = await res.json();
        alert(err.error || "Failed to create endpoint");
        return;
      }
      await this.render();
    });

    // Copy authorized_keys (SSH keys table + passkey table)
    for (const btn of this.container.querySelectorAll(".btn-copy-key, .btn-copy-authkey")) {
      btn.addEventListener("click", () => {
        const key = decodeURIComponent((btn as HTMLElement).dataset.key ?? "");
        navigator.clipboard.writeText(key);
        const originalText = (btn as HTMLElement).textContent;
        (btn as HTMLElement).textContent = "Copied!";
        setTimeout(() => {
          (btn as HTMLElement).textContent = originalText ?? "Copy";
        }, 1500);
      });
    }

    // Delete passkey
    for (const btn of this.container.querySelectorAll(".btn-delete-passkey")) {
      btn.addEventListener("click", async () => {
        const id = (btn as HTMLElement).dataset.id;
        if (id && confirm("Delete this passkey?")) {
          await deleteCredential(id);
          await this.render();
        }
      });
    }

    // Register passkey
    this.container
      .querySelector("#register-passkey-settings")
      ?.addEventListener("click", async () => {
        const label = prompt("Passkey label (e.g., YubiKey 5 NFC):");
        if (!label) return;
        try {
          await registerPasskey(label);
          await this.render();
        } catch (err) {
          alert(`Registration failed: ${(err as Error).message}`);
        }
      });
  }

  private async fetchEndpoints(): Promise<EndpointData[]> {
    const res = await fetch(`${basePath}/api/endpoints`);
    const data = await res.json();
    return data.endpoints;
  }

  private async fetchKeys(): Promise<SshKeyData[]> {
    const res = await fetch(`${basePath}/api/keys`);
    const data = await res.json();
    return data.keys;
  }
}
