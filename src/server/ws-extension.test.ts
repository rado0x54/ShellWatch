import { describe, expect, it, vi } from "vitest";
import { SigningBridge } from "../webauthn/signing-bridge.js";

describe("SigningBridge as WsExtension", () => {
  it("handles fido:sign-response messages", () => {
    const bridge = new SigningBridge();
    const mockSocket = {} as never;

    // Register a mock agent so handleSignResponse has something to route to
    const mockAgent = {
      handleSignResponse: vi.fn(),
      handleSignError: vi.fn(),
    } as unknown as import("../webauthn/ssh-agent.js").WebAuthnSshAgent;
    bridge.registerAgent("test-agent", mockAgent);

    const handled = bridge.onMessage(
      {
        type: "fido:sign-response",
        requestId: "req-1",
        authenticatorData: "AAAA", // base64url
        signature: "BBBB",
        clientDataJSON: '{"type":"webauthn.get"}',
      },
      mockSocket,
    );

    expect(handled).toBe(true);
    expect(mockAgent.handleSignResponse).toHaveBeenCalledWith(
      expect.objectContaining({ requestId: "req-1" }),
    );
  });

  it("handles fido:sign-error messages", () => {
    const bridge = new SigningBridge();
    const mockSocket = {} as never;

    const mockAgent = {
      handleSignResponse: vi.fn(),
      handleSignError: vi.fn(),
    } as unknown as import("../webauthn/ssh-agent.js").WebAuthnSshAgent;
    bridge.registerAgent("test-agent", mockAgent);

    const handled = bridge.onMessage(
      { type: "fido:sign-error", requestId: "req-2", error: "User cancelled" },
      mockSocket,
    );

    expect(handled).toBe(true);
    expect(mockAgent.handleSignError).toHaveBeenCalledWith("req-2", "User cancelled");
  });

  it("ignores non-fido messages", () => {
    const bridge = new SigningBridge();
    const mockSocket = {} as never;

    const handled = bridge.onMessage(
      { type: "terminal:input", sessionId: "s1", data: "hello" },
      mockSocket,
    );

    expect(handled).toBe(false);
  });

  it("tracks clients via onConnect/onDisconnect", () => {
    const bridge = new SigningBridge();

    const socket1 = { readyState: 1, OPEN: 1, send: vi.fn() } as never;
    const socket2 = { readyState: 1, OPEN: 1, send: vi.fn() } as never;

    expect(bridge.hasClients).toBe(false);

    bridge.onConnect(socket1);
    expect(bridge.hasClients).toBe(true);

    bridge.onConnect(socket2);
    bridge.onDisconnect(socket1);
    expect(bridge.hasClients).toBe(true);

    bridge.onDisconnect(socket2);
    expect(bridge.hasClients).toBe(false);
  });
});
