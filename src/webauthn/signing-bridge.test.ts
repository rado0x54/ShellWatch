import { describe, expect, it, vi } from "vitest";
import { PendingActionStore } from "../pending-action/store.js";
import { NotificationDispatcher } from "../pending-action/dispatcher.js";
import type { SignRequest } from "./ssh-agent.js";
import type { FileKeySignRequest } from "./composite-ssh-agent.js";
import { SigningBridge } from "./signing-bridge.js";

function makeDispatcher(): NotificationDispatcher {
  const dispatcher = new NotificationDispatcher("https://example.com");
  dispatcher.register({ name: "mock", send: vi.fn() });
  return dispatcher;
}

describe("SigningBridge", () => {
  it("handleSignRequest creates a webauthn-sign action and dispatches", () => {
    const store = new PendingActionStore();
    const dispatcher = makeDispatcher();
    const dispatchSpy = vi.spyOn(dispatcher, "dispatch");
    const bridge = new SigningBridge({ actionStore: store, dispatcher });

    const resolve = vi.fn();
    const reject = vi.fn();
    const request: SignRequest = {
      credentialId: "cred-1",
      dataToSign: Buffer.from("challenge-data"),
      rpId: "localhost",
      passkeyLabel: "YubiKey",
      resolve,
      reject,
    };

    bridge.handleSignRequest(request, "acc-1", {
      source: "agent-proxy",
      sourceIp: "1.2.3.4",
      apiKeyLabel: "Test Key",
      apiKeyPrefix: "sw_test",
    });

    expect(dispatchSpy).toHaveBeenCalledOnce();
    const action = dispatchSpy.mock.calls[0][0];
    expect(action.type).toBe("webauthn-sign");
    expect(action.accountId).toBe("acc-1");
    expect(action.context.source).toBe("agent-proxy");
    if (action.type !== "webauthn-sign") throw new Error("expected webauthn-sign");
    expect(action.credentialId).toBe("cred-1");
    expect(action.challenge).toBe(Buffer.from("challenge-data").toString("base64"));
    expect(action.rpId).toBe("localhost");

    store.destroy();
  });

  it("handleKeyApproveRequest creates a key-approve action and dispatches", () => {
    const store = new PendingActionStore();
    const dispatcher = makeDispatcher();
    const dispatchSpy = vi.spyOn(dispatcher, "dispatch");
    const bridge = new SigningBridge({ actionStore: store, dispatcher });

    const resolve = vi.fn();
    const reject = vi.fn();
    const request: FileKeySignRequest = {
      fileKey: {
        publicKeyBlob: Buffer.from("pub"),
        privateKey: "-----BEGIN PRIVATE KEY-----",
        label: "Production Key",
        fingerprint: "SHA256:abc123",
      },
      dataToSign: Buffer.from("sign-data"),
      hash: "sha-512",
      resolve,
      reject,
    };

    bridge.handleKeyApproveRequest(request, "acc-1", {
      source: "endpoint-auth",
      endpointLabel: "Prod",
      endpointAddress: "deploy@host:22",
      trigger: { kind: "ui", sourceIp: "127.0.0.1" },
    });

    expect(dispatchSpy).toHaveBeenCalledOnce();
    const action = dispatchSpy.mock.calls[0][0];
    expect(action.type).toBe("key-approve");
    expect(action.accountId).toBe("acc-1");
    expect(action.context.source).toBe("endpoint-auth");
    if (action.type !== "key-approve") throw new Error("expected key-approve");
    expect(action.keyLabel).toBe("Production Key");
    expect(action.keyFingerprint).toBe("SHA256:abc123");

    // Resolve the action — should call the original resolve callback
    store.resolve(action.id);
    expect(resolve).toHaveBeenCalled();

    store.destroy();
  });
});
