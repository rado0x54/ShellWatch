// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { closeSession, createSession, fetchEndpoints, fetchSessions } from "./api.js";

describe("API client", () => {
  const mockFetch = vi.fn();

  beforeEach(() => {
    vi.stubGlobal("fetch", mockFetch);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe("fetchEndpoints", () => {
    it("fetches and returns endpoints", async () => {
      const endpoints = [
        { id: "dev", label: "Dev", host: "localhost", port: 22, username: "user" },
      ];
      mockFetch.mockResolvedValue({
        json: () => Promise.resolve({ endpoints }),
      });

      const result = await fetchEndpoints();
      expect(result).toEqual(endpoints);
      expect(mockFetch).toHaveBeenCalledWith("/api/endpoints");
    });
  });

  describe("createSession", () => {
    it("creates a session", async () => {
      const session = { sessionId: "sess_1", endpointId: "dev", status: "open" };
      mockFetch.mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(session),
      });

      const result = await createSession("dev");
      expect(result).toEqual(session);
      expect(mockFetch).toHaveBeenCalledWith("/api/sessions", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ endpointId: "dev" }),
      });
    });

    it("throws on error response", async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        statusText: "Bad Request",
        json: () => Promise.resolve({ message: "Unknown endpoint" }),
      });

      await expect(createSession("bad")).rejects.toThrow("Unknown endpoint");
    });

    it("throws with statusText when json parse fails", async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        statusText: "Internal Server Error",
        json: () => Promise.reject(new Error("parse error")),
      });

      await expect(createSession("bad")).rejects.toThrow("Internal Server Error");
    });
  });

  describe("fetchSessions", () => {
    it("fetches and returns sessions", async () => {
      const sessions = [{ sessionId: "sess_1", endpointId: "dev", status: "open" }];
      mockFetch.mockResolvedValue({
        json: () => Promise.resolve({ sessions }),
      });

      const result = await fetchSessions();
      expect(result).toEqual(sessions);
    });
  });

  describe("closeSession", () => {
    it("sends DELETE request", async () => {
      mockFetch.mockResolvedValue({});

      await closeSession("sess_1");
      expect(mockFetch).toHaveBeenCalledWith("/api/sessions/sess_1", { method: "DELETE" });
    });
  });
});
