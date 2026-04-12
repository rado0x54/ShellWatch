import { describe, expect, it, vi } from "vitest";
import { WebSocketChannel } from "../pending-action/ws-channel.js";

describe("WebSocketChannel as WsExtension", () => {
  it("tracks clients by account on connect/disconnect", () => {
    const channel = new WebSocketChannel();

    const socket1 = { readyState: 1, OPEN: 1, send: vi.fn() } as never;
    const socket2 = { readyState: 1, OPEN: 1, send: vi.fn() } as never;

    expect(channel.hasClientsForAccount("acc-1")).toBe(false);

    channel.onConnect(socket1, "acc-1");
    expect(channel.hasClientsForAccount("acc-1")).toBe(true);
    expect(channel.hasClientsForAccount("acc-2")).toBe(false);

    channel.onConnect(socket2, "acc-1");
    channel.onDisconnect(socket1);
    expect(channel.hasClientsForAccount("acc-1")).toBe(true);

    channel.onDisconnect(socket2);
    expect(channel.hasClientsForAccount("acc-1")).toBe(false);
  });

  it("ignores connections without accountId", () => {
    const channel = new WebSocketChannel();
    const socket = { readyState: 1, OPEN: 1, send: vi.fn() } as never;

    channel.onConnect(socket, undefined);
    expect(channel.hasClientsForAccount("any")).toBe(false);
  });

  it("does not handle any incoming messages", () => {
    const channel = new WebSocketChannel();
    const socket = {} as never;

    expect(channel.onMessage({ type: "anything" }, socket)).toBe(false);
  });

  it("sends sign:request only to clients for the correct account", async () => {
    const channel = new WebSocketChannel();
    const socket1 = { readyState: 1, OPEN: 1, send: vi.fn() } as never;
    const socket2 = { readyState: 1, OPEN: 1, send: vi.fn() } as never;

    channel.onConnect(socket1, "acc-1");
    channel.onConnect(socket2, "acc-2");

    const action = {
      id: "action-1",
      type: "webauthn-sign" as const,
      accountId: "acc-1",
      status: "pending" as const,
      createdAt: Date.now(),
      expiresAt: Date.now() + 60_000,
      context: { source: "agent-proxy" as const, sourceIp: "1.2.3.4", apiKeyPrefix: "sw_test" },
      credentialId: "cred-1",
      challenge: "dGVzdA==",
      rpId: "localhost",
      passkeyLabel: "YubiKey",
      resolve: vi.fn(),
      reject: vi.fn(),
    };

    await channel.send(action, "https://example.com/sign/action-1");

    expect((socket1 as unknown as { send: ReturnType<typeof vi.fn> }).send).toHaveBeenCalledTimes(
      1,
    );
    expect((socket2 as unknown as { send: ReturnType<typeof vi.fn> }).send).not.toHaveBeenCalled();

    const msg = JSON.parse(
      (socket1 as unknown as { send: ReturnType<typeof vi.fn> }).send.mock.calls[0][0] as string,
    );
    expect(msg.type).toBe("sign:request");
    expect(msg.actionId).toBe("action-1");
    expect(msg.actionType).toBe("webauthn-sign");
    expect(msg.source).toBe("agent-proxy");
    expect(msg.credentialId).toBe("cred-1");
    expect(msg.challenge).toBe("dGVzdA==");
    expect(msg.rpId).toBe("localhost");
  });

  it("sends key-approve message with correct fields", async () => {
    const channel = new WebSocketChannel();
    const socket = { readyState: 1, OPEN: 1, send: vi.fn() } as never;

    channel.onConnect(socket, "acc-1");

    const action = {
      id: "action-2",
      type: "key-approve" as const,
      accountId: "acc-1",
      status: "pending" as const,
      createdAt: Date.now(),
      expiresAt: Date.now() + 60_000,
      context: {
        source: "endpoint-auth" as const,
        endpointLabel: "Prod",
        endpointAddress: "user@host:22",
        trigger: { kind: "ui" as const, sourceIp: "127.0.0.1" },
      },
      keyLabel: "Test Key",
      keyFingerprint: "SHA256:abc123",
      resolve: vi.fn(),
      reject: vi.fn(),
    };

    await channel.send(action, "https://example.com/sign/action-2");

    const msg = JSON.parse(
      (socket as unknown as { send: ReturnType<typeof vi.fn> }).send.mock.calls[0][0] as string,
    );
    expect(msg.type).toBe("sign:request");
    expect(msg.actionType).toBe("key-approve");
    expect(msg.keyLabel).toBe("Test Key");
    expect(msg.keyFingerprint).toBe("SHA256:abc123");
    expect(msg.endpointLabel).toBe("Prod");
    expect(msg.credentialId).toBeUndefined();
  });

  it("broadcasts sign:resolved to all clients for the account", () => {
    const channel = new WebSocketChannel();
    const socket1 = { readyState: 1, OPEN: 1, send: vi.fn() } as never;
    const socket2 = { readyState: 1, OPEN: 1, send: vi.fn() } as never;

    channel.onConnect(socket1, "acc-1");
    channel.onConnect(socket2, "acc-1");

    channel.broadcastResolved("action-1", "acc-1");

    for (const sock of [socket1, socket2]) {
      const msg = JSON.parse(
        (sock as unknown as { send: ReturnType<typeof vi.fn> }).send.mock.calls[0][0] as string,
      );
      expect(msg.type).toBe("sign:resolved");
      expect(msg.actionId).toBe("action-1");
    }
  });
});
