import { beforeEach, describe, expect, it, vi } from "vitest";
import { PendingActionStore } from "../pending-action/store.js";
import type { CreateActionParams } from "../pending-action/types.js";
import type { SignResponse } from "../webauthn/ssh-agent.js";
import type { SigningRequestsRepository } from "./signing-requests-repo.js";
import { SigningRequestsWriter } from "./signing-requests-writer.js";

function makeRepo(): SigningRequestsRepository {
  return {
    insertCreated: vi.fn(),
    recordResolution: vi.fn(),
    list: vi.fn(),
    getById: vi.fn(),
  };
}

function webauthnAgentProxyParams(): CreateActionParams {
  return {
    type: "webauthn-sign",
    accountId: "acct_a",
    context: {
      source: "agent-proxy",
      sourceIp: "203.0.113.5",
      apiKeyLabel: "agent-key",
      apiKeyPrefix: "sw_abc",
      clientHostname: "laptop.local",
      clientOs: "darwin/arm64",
      clientVersion: "0.1.0",
    },
    credentialId: "cred-xyz",
    challenge: "Y2hhbGxlbmdl",
    rpId: "shellwatch.local",
    passkeyLabel: "YubiKey 5",
    userVerification: "required",
    resolve: vi.fn(),
    reject: vi.fn(),
  };
}

function webauthnEndpointAuthMcpParams(): CreateActionParams {
  return {
    type: "webauthn-sign",
    accountId: "acct_a",
    context: {
      source: "endpoint-auth",
      endpointLabel: "Prod DB",
      endpointAddress: "user@db.prod:22",
      trigger: {
        kind: "mcp",
        reason: "fetch nightly dump",
        sourceIp: "10.0.0.7",
        mcpClientName: "claude-code",
        mcpClientVersion: "0.10.0",
        apiKeyLabel: "mcp-key",
        apiKeyPrefix: "sw_def",
      },
    },
    credentialId: "cred-xyz",
    challenge: "Y2hhbGxlbmdl",
    rpId: "shellwatch.local",
    userVerification: "preferred",
    resolve: vi.fn(),
    reject: vi.fn(),
  };
}

function keyApproveAgentForwardingParams(): CreateActionParams {
  return {
    type: "key-approve",
    accountId: "acct_a",
    context: {
      source: "agent-forwarding",
      endpointLabel: "Bastion",
      endpointAddress: "user@bastion:22",
      sessionId: "sess_42",
    },
    keyLabel: "deploy-bot",
    keyFingerprint: "SHA256:abc123",
    connectionId: "conn-1",
    resolve: vi.fn(),
    reject: vi.fn(),
  };
}

const sigResponse: SignResponse = {
  requestId: "x",
  authenticatorData: Buffer.from("a"),
  signature: Buffer.from("s"),
  clientDataJSON: "{}",
};

describe("SigningRequestsWriter", () => {
  let store: PendingActionStore;
  let repo: SigningRequestsRepository;
  let writer: SigningRequestsWriter;

  beforeEach(() => {
    vi.useFakeTimers();
    store = new PendingActionStore();
    repo = makeRepo();
    writer = new SigningRequestsWriter({ actionStore: store, repo });
  });

  it("inserts a row when an action is created — agent-proxy webauthn", () => {
    const action = store.create(webauthnAgentProxyParams());
    expect(repo.insertCreated).toHaveBeenCalledTimes(1);
    const arg = vi.mocked(repo.insertCreated).mock.calls[0]![0];
    expect(arg.id).toBe(action.id);
    expect(arg.accountId).toBe("acct_a");
    expect(arg.type).toBe("webauthn-sign");
    expect(arg.source).toBe("agent-proxy");
    expect(arg.sourceIp).toBe("203.0.113.5");
    expect(arg.apiKeyLabel).toBe("agent-key");
    expect(arg.apiKeyPrefix).toBe("sw_abc");
    expect(arg.clientHostname).toBe("laptop.local");
    expect(arg.clientOs).toBe("darwin/arm64");
    expect(arg.clientVersion).toBe("0.1.0");
    expect(arg.credentialId).toBe("cred-xyz");
    expect(arg.passkeyLabel).toBe("YubiKey 5");
    expect(arg.userVerification).toBe("required");
    expect(arg.endpointLabel).toBeUndefined();
  });

  it("maps endpoint-auth + mcp trigger fields", () => {
    store.create(webauthnEndpointAuthMcpParams());
    const arg = vi.mocked(repo.insertCreated).mock.calls[0]![0];
    expect(arg.source).toBe("endpoint-auth");
    expect(arg.endpointLabel).toBe("Prod DB");
    expect(arg.endpointAddress).toBe("user@db.prod:22");
    expect(arg.sourceIp).toBe("10.0.0.7");
    expect(arg.mcpReason).toBe("fetch nightly dump");
    expect(arg.mcpClientName).toBe("claude-code");
    expect(arg.mcpClientVersion).toBe("0.10.0");
    expect(arg.apiKeyLabel).toBe("mcp-key");
    expect(arg.apiKeyPrefix).toBe("sw_def");
  });

  it("maps agent-forwarding + key-approve fields", () => {
    store.create(keyApproveAgentForwardingParams());
    const arg = vi.mocked(repo.insertCreated).mock.calls[0]![0];
    expect(arg.type).toBe("key-approve");
    expect(arg.source).toBe("agent-forwarding");
    expect(arg.endpointLabel).toBe("Bastion");
    expect(arg.sessionId).toBe("sess_42");
    expect(arg.keyLabel).toBe("deploy-bot");
    expect(arg.keyFingerprint).toBe("SHA256:abc123");
    expect(arg.credentialId).toBeUndefined();
  });

  it("records 'approved' on resolve", () => {
    const action = store.create(webauthnAgentProxyParams());
    vi.advanceTimersByTime(150);
    store.resolve(action.id, sigResponse);
    expect(repo.recordResolution).toHaveBeenCalledTimes(1);
    const arg = vi.mocked(repo.recordResolution).mock.calls[0]![0];
    expect(arg.id).toBe(action.id);
    expect(arg.outcome).toBe("approved");
    expect(arg.latencyMs).toBe(150);
    expect(arg.cancelReason).toBeUndefined();
  });

  it("records 'denied' on deny", () => {
    const action = store.create(webauthnAgentProxyParams());
    vi.advanceTimersByTime(50);
    store.deny(action.id);
    const arg = vi.mocked(repo.recordResolution).mock.calls[0]![0];
    expect(arg.outcome).toBe("denied");
    expect(arg.latencyMs).toBe(50);
  });

  it("records 'expired' when the sweep fires past the TTL", () => {
    const action = store.create(webauthnAgentProxyParams());
    // PendingActionStore TTL is 60s; sweep fires every 10s. Advance well past.
    vi.advanceTimersByTime(70_000);
    const arg = vi.mocked(repo.recordResolution).mock.calls[0]![0];
    expect(arg.id).toBe(action.id);
    expect(arg.outcome).toBe("expired");
  });

  it("records 'cancelled' with the cancel reason on cancelForConnection", () => {
    const params = keyApproveAgentForwardingParams();
    const action = store.create(params);
    store.cancelForConnection("conn-1", "ssh-client-disconnected");
    const arg = vi.mocked(repo.recordResolution).mock.calls[0]![0];
    expect(arg.id).toBe(action.id);
    expect(arg.outcome).toBe("cancelled");
    expect(arg.cancelReason).toBe("ssh-client-disconnected");
  });

  it("records 'expired' on destroy() for any still-pending action", () => {
    store.create(webauthnAgentProxyParams());
    store.destroy();
    const calls = vi.mocked(repo.recordResolution).mock.calls;
    expect(calls).toHaveLength(1);
    expect(calls[0]![0].outcome).toBe("expired");
  });

  it("dispose detaches both listeners — no inserts, no resolutions", () => {
    writer.dispose();
    const action = store.create(webauthnAgentProxyParams());
    store.resolve(action.id, sigResponse);
    expect(repo.insertCreated).not.toHaveBeenCalled();
    expect(repo.recordResolution).not.toHaveBeenCalled();
  });

  it("swallows repo errors on insert", () => {
    vi.mocked(repo.insertCreated).mockImplementation(() => {
      throw new Error("disk full");
    });
    expect(() => store.create(webauthnAgentProxyParams())).not.toThrow();
  });

  it("swallows repo errors on resolution", () => {
    vi.mocked(repo.recordResolution).mockImplementation(() => {
      throw new Error("disk full");
    });
    const action = store.create(webauthnAgentProxyParams());
    expect(() => store.deny(action.id)).not.toThrow();
  });
});
