// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { get } from "svelte/store";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fetchSshKeys, sshKeys } from "./keys.js";

describe("keys store", () => {
  beforeEach(() => {
    sshKeys.set([]);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe("SSH keys", () => {
    it("fetchSshKeys populates the store (via apiFetch)", async () => {
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
      const fetchSpy = vi
        .spyOn(globalThis, "fetch")
        .mockResolvedValueOnce(new Response(JSON.stringify({ keys: mockKeys })));

      await fetchSshKeys();

      expect(get(sshKeys)).toEqual(mockKeys);
      // apiFetch calls fetch(path, init); no token is present in the test env,
      // so no Authorization header is attached.
      expect(fetchSpy.mock.calls[0][0]).toBe("/api/keys");
    });
  });
});
