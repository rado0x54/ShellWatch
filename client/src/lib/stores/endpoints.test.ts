import { get } from "svelte/store";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createEndpoint, deleteEndpoint, endpoints, fetchEndpoints } from "./endpoints.js";

describe("endpoints store", () => {
  beforeEach(() => {
    endpoints.set([]);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("fetchEndpoints populates the store", async () => {
    const mockEndpoints = [
      { id: "dev", label: "Dev Box", host: "dev.example.com", port: 22, username: "ubuntu" },
    ];
    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
      new Response(JSON.stringify({ endpoints: mockEndpoints })),
    );

    await fetchEndpoints();

    expect(get(endpoints)).toEqual(mockEndpoints);
    expect(fetch).toHaveBeenCalledWith("/api/endpoints");
  });

  it("createEndpoint sends POST and refreshes", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch");

    // POST response
    fetchSpy.mockResolvedValueOnce(new Response(JSON.stringify({ status: "created" })));
    // Refresh GET response
    fetchSpy.mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          endpoints: [
            { id: "new", label: "New", host: "new.example.com", port: 22, username: "root" },
          ],
        }),
      ),
    );

    await createEndpoint({
      id: "new",
      label: "New",
      host: "new.example.com",
      port: 22,
      username: "root",
    });

    expect(fetchSpy).toHaveBeenCalledTimes(2);
    const [url, opts] = fetchSpy.mock.calls[0];
    expect(url).toBe("/api/endpoints");
    expect(opts?.method).toBe("POST");
    expect(JSON.parse(opts?.body as string)).toMatchObject({ id: "new", host: "new.example.com" });
    expect(get(endpoints)).toHaveLength(1);
  });

  it("createEndpoint throws on error response", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
      new Response(JSON.stringify({ error: "Duplicate ID" }), { status: 400 }),
    );

    await expect(
      createEndpoint({
        id: "dup",
        label: "Dup",
        host: "h",
        port: 22,
        username: "u",
      }),
    ).rejects.toThrow("Duplicate ID");
  });

  it("deleteEndpoint sends DELETE and refreshes", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    fetchSpy.mockResolvedValueOnce(new Response(JSON.stringify({ status: "deleted" })));
    fetchSpy.mockResolvedValueOnce(new Response(JSON.stringify({ endpoints: [] })));

    await deleteEndpoint("dev");

    expect(fetchSpy.mock.calls[0][0]).toBe("/api/endpoints/dev");
    expect(fetchSpy.mock.calls[0][1]?.method).toBe("DELETE");
  });

  it("deleteEndpoint throws on error response", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
      new Response(JSON.stringify({ error: "Active sessions" }), { status: 409 }),
    );

    await expect(deleteEndpoint("busy")).rejects.toThrow("Active sessions");
  });
});
