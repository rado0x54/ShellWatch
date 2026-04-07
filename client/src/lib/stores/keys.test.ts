import { get } from "svelte/store";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  apiKeys,
  fetchApiKeys,
  fetchSshKeys,
  generateApiKey,
  revokeApiKey,
  sshKeys,
} from "./keys.js";

describe("keys store", () => {
  beforeEach(() => {
    sshKeys.set([]);
    apiKeys.set([]);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe("SSH keys", () => {
    it("fetchSshKeys populates the store", async () => {
      const mockKeys = [
        {
          id: "k1",
          label: "Dev Key",
          type: "ed25519",
          fingerprint: "SHA256:abc",
          available: true,
          authorizedKeysEntry: "ssh-ed25519 AAAA...",
        },
      ];
      vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
        new Response(JSON.stringify({ keys: mockKeys })),
      );

      await fetchSshKeys();

      expect(get(sshKeys)).toEqual(mockKeys);
      expect(fetch).toHaveBeenCalledWith("/api/keys");
    });
  });

  describe("API keys", () => {
    it("fetchApiKeys populates the store", async () => {
      const mockKeys = [
        {
          id: "ak1",
          label: "Agent",
          keyPrefix: "sw_abc123",
          scopes: ["mcp"],
          enabled: true,
          createdAt: "2026-04-01",
        },
      ];
      vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
        new Response(JSON.stringify({ keys: mockKeys })),
      );

      await fetchApiKeys();

      expect(get(apiKeys)).toEqual(mockKeys);
    });

    it("fetchApiKeys sets empty array on error", async () => {
      apiKeys.set([
        { id: "old", label: "Old", keyPrefix: "sw_", scopes: [], enabled: true, createdAt: "" },
      ]);
      vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
        new Response("Not Found", { status: 404 }),
      );

      await fetchApiKeys();

      expect(get(apiKeys)).toEqual([]);
    });

    it("fetchApiKeys sets empty array on network error", async () => {
      vi.spyOn(globalThis, "fetch").mockRejectedValueOnce(new Error("Network error"));

      await fetchApiKeys();

      expect(get(apiKeys)).toEqual([]);
    });

    it("generateApiKey sends POST and returns raw key", async () => {
      const fetchSpy = vi.spyOn(globalThis, "fetch");
      // Generate response
      fetchSpy.mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            id: "ak2",
            label: "New",
            keyPrefix: "sw_new",
            key: "sw_full_secret_key",
          }),
        ),
      );
      // Refresh response
      fetchSpy.mockResolvedValueOnce(new Response(JSON.stringify({ keys: [] })));

      const key = await generateApiKey("New");

      expect(key).toBe("sw_full_secret_key");
      const [url, opts] = fetchSpy.mock.calls[0];
      expect(url).toBe("/api/keys/api");
      expect(opts?.method).toBe("POST");
      expect(JSON.parse(opts?.body as string)).toEqual({ label: "New" });
    });

    it("generateApiKey throws on error", async () => {
      vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
        new Response(JSON.stringify({ error: "Label required" }), { status: 400 }),
      );

      await expect(generateApiKey("")).rejects.toThrow("Label required");
    });

    it("revokeApiKey sends DELETE and refreshes", async () => {
      const fetchSpy = vi.spyOn(globalThis, "fetch");
      fetchSpy.mockResolvedValueOnce(new Response(JSON.stringify({ status: "revoked" })));
      fetchSpy.mockResolvedValueOnce(new Response(JSON.stringify({ keys: [] })));

      await revokeApiKey("ak1");

      expect(fetchSpy.mock.calls[0][0]).toBe("/api/keys/api/ak1");
      expect(fetchSpy.mock.calls[0][1]?.method).toBe("DELETE");
    });
  });
});
