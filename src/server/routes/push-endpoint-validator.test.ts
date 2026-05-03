// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { describe, expect, it } from "vitest";
import { isAllowedPushEndpoint } from "./push-endpoint-validator.js";

describe("isAllowedPushEndpoint", () => {
  it("accepts FCM (Chrome/Edge)", () => {
    expect(isAllowedPushEndpoint("https://fcm.googleapis.com/fcm/send/abc")).toBe(true);
    expect(isAllowedPushEndpoint("https://fcm.googleapis.com/wp/abc")).toBe(true);
  });

  it("accepts Mozilla autopush (Firefox prod/stage/dev)", () => {
    expect(isAllowedPushEndpoint("https://updates.push.services.mozilla.com/wpush/v2/abc")).toBe(
      true,
    );
    expect(isAllowedPushEndpoint("https://updates-autopush.stage.mozaws.net/wpush/v2/abc")).toBe(
      true,
    );
    expect(isAllowedPushEndpoint("https://updates-autopush.dev.mozaws.net/wpush/v2/abc")).toBe(
      true,
    );
  });

  it("accepts legacy android.googleapis.com (Chrome legacy GCM)", () => {
    expect(isAllowedPushEndpoint("https://android.googleapis.com/gcm/send/abc")).toBe(true);
  });

  it("accepts Apple web push subdomains", () => {
    expect(isAllowedPushEndpoint("https://web.push.apple.com/abc")).toBe(true);
  });

  it("accepts WNS (Edge legacy) subdomains", () => {
    expect(isAllowedPushEndpoint("https://db5.notify.windows.com/?token=xyz")).toBe(true);
  });

  it("rejects non-https schemes", () => {
    expect(isAllowedPushEndpoint("http://fcm.googleapis.com/fcm/send/abc")).toBe(false);
    expect(isAllowedPushEndpoint("ftp://fcm.googleapis.com/abc")).toBe(false);
  });

  it("rejects RFC1918 / loopback / link-local hosts", () => {
    expect(isAllowedPushEndpoint("https://127.0.0.1/admin")).toBe(false);
    expect(isAllowedPushEndpoint("https://localhost:9090/admin")).toBe(false);
    expect(isAllowedPushEndpoint("https://10.0.0.1/")).toBe(false);
    expect(isAllowedPushEndpoint("https://192.168.1.1/")).toBe(false);
    expect(isAllowedPushEndpoint("https://169.254.169.254/latest/meta-data/")).toBe(false);
    expect(isAllowedPushEndpoint("https://[::1]/")).toBe(false);
  });

  it("rejects unrelated hosts even over https", () => {
    expect(isAllowedPushEndpoint("https://attacker.example.com/")).toBe(false);
    expect(isAllowedPushEndpoint("https://googleapis.com/")).toBe(false);
  });

  it("rejects host suffix spoofing", () => {
    // Naive endsWith without leading dot would match these.
    expect(isAllowedPushEndpoint("https://evilpush.apple.com/")).toBe(false);
    expect(isAllowedPushEndpoint("https://attacker-fcm.googleapis.com.evil.com/")).toBe(false);
    expect(isAllowedPushEndpoint("https://evilnotify.windows.com/")).toBe(false);
  });

  it("rejects URLs with embedded credentials", () => {
    expect(isAllowedPushEndpoint("https://user:pass@fcm.googleapis.com/fcm/send/abc")).toBe(false);
  });

  it("rejects malformed URLs and empty input", () => {
    expect(isAllowedPushEndpoint("")).toBe(false);
    expect(isAllowedPushEndpoint("not a url")).toBe(false);
  });

  it("treats hostname comparison as case-insensitive", () => {
    expect(isAllowedPushEndpoint("https://FCM.GoogleAPIs.com/fcm/send/abc")).toBe(true);
  });
});
