import { afterEach, describe, expect, it, vi } from "vitest";
import { closeSession, createSession } from "./sessions-api.js";

describe("sessions-api store", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("createSession sends POST and returns session", async () => {
    const mockSession = {
      sessionId: "sess-1",
      endpointId: "dev",
      status: "open",
      createdAt: "2026-04-01T00:00:00Z",
      source: "ui",
    };
    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(new Response(JSON.stringify(mockSession)));

    const result = await createSession("dev");

    expect(result).toEqual(mockSession);
    expect(fetch).toHaveBeenCalledWith("/api/sessions", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ endpointId: "dev" }),
    });
  });

  it("createSession throws on error response", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
      new Response(JSON.stringify({ error: "Unknown endpoint" }), { status: 400 }),
    );

    await expect(createSession("nope")).rejects.toThrow("Unknown endpoint");
  });

  it("createSession handles non-JSON error body", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
      new Response("Internal Server Error", { status: 500, statusText: "Internal Server Error" }),
    );

    await expect(createSession("dev")).rejects.toThrow("Internal Server Error");
  });

  it("closeSession sends DELETE", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
      new Response(JSON.stringify({ status: "closed" })),
    );

    await closeSession("sess-1");

    expect(fetch).toHaveBeenCalledWith("/api/sessions/sess-1", { method: "DELETE" });
  });
});
