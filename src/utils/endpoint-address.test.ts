// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { describe, expect, it } from "vitest";
import { formatEndpointAddress, parseEndpointAddress } from "./endpoint-address.js";

describe("parseEndpointAddress", () => {
  it("parses host only", () => {
    expect(parseEndpointAddress("example.com")).toEqual({
      username: "shellwatch",
      host: "example.com",
      port: 22,
    });
  });

  it("parses host:port", () => {
    expect(parseEndpointAddress("example.com:2222")).toEqual({
      username: "shellwatch",
      host: "example.com",
      port: 2222,
    });
  });

  it("parses user@host", () => {
    expect(parseEndpointAddress("deploy@example.com")).toEqual({
      username: "deploy",
      host: "example.com",
      port: 22,
    });
  });

  it("parses user@host:port", () => {
    expect(parseEndpointAddress("deploy@dev.example.com:62222")).toEqual({
      username: "deploy",
      host: "dev.example.com",
      port: 62222,
    });
  });

  it("parses IPv6 in brackets", () => {
    expect(parseEndpointAddress("[::1]:2222")).toEqual({
      username: "shellwatch",
      host: "::1",
      port: 2222,
    });
  });

  it("parses user@[IPv6]:port", () => {
    expect(parseEndpointAddress("root@[::1]:22")).toEqual({
      username: "root",
      host: "::1",
      port: 22,
    });
  });

  it("trims whitespace", () => {
    expect(parseEndpointAddress("  example.com  ")).toEqual({
      username: "shellwatch",
      host: "example.com",
      port: 22,
    });
  });

  it("throws on empty string", () => {
    expect(() => parseEndpointAddress("")).toThrow("cannot be empty");
  });

  it("throws on empty username", () => {
    expect(() => parseEndpointAddress("@host")).toThrow("empty username");
  });

  it("throws on empty host", () => {
    expect(() => parseEndpointAddress("user@:22")).toThrow("empty host");
  });

  it("throws on invalid port", () => {
    expect(() => parseEndpointAddress("host:99999")).toThrow("port out of range");
  });
});

describe("formatEndpointAddress", () => {
  it("omits defaults", () => {
    expect(formatEndpointAddress({ username: "shellwatch", host: "example.com", port: 22 })).toBe(
      "example.com",
    );
  });

  it("includes non-default username", () => {
    expect(formatEndpointAddress({ username: "deploy", host: "example.com", port: 22 })).toBe(
      "deploy@example.com",
    );
  });

  it("includes non-default port", () => {
    expect(formatEndpointAddress({ username: "shellwatch", host: "example.com", port: 2222 })).toBe(
      "example.com:2222",
    );
  });

  it("includes both non-defaults", () => {
    expect(
      formatEndpointAddress({ username: "deploy", host: "dev.example.com", port: 62222 }),
    ).toBe("deploy@dev.example.com:62222");
  });
});
