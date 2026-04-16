import { describe, expect, it } from "vitest";
import { sha256Fingerprint } from "./fingerprint.js";
import { toSkPublicKeyBlob } from "./ssh-key-format.js";

describe("sha256Fingerprint", () => {
  it("matches `ssh-keygen -lf` for a known Ed25519 public key", () => {
    // Generated via: ssh-keygen -t ed25519 -N '' -f k && ssh-keygen -lf k.pub
    //   pub:  ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHov4QIIRaFF+0IoDtZur6AS/I0vI0YaMv08BUIo0y6e
    //   -lf:  256 SHA256:3PWFagSOxHbNxVp/8JGsQb6vmiz6lMqy5XmiS8ReQC8
    const blob = Buffer.from(
      "AAAAC3NzaC1lZDI1NTE5AAAAIHov4QIIRaFF+0IoDtZur6AS/I0vI0YaMv08BUIo0y6e",
      "base64",
    );
    expect(sha256Fingerprint(blob)).toBe("SHA256:3PWFagSOxHbNxVp/8JGsQb6vmiz6lMqy5XmiS8ReQC8");
  });

  it("uses standard base64 (not base64url) and strips padding", () => {
    const fp = sha256Fingerprint(Buffer.alloc(1));
    expect(fp).toMatch(/^SHA256:[A-Za-z0-9+/]+$/);
    expect(fp).not.toMatch(/[_-]/);
    expect(fp).not.toContain("=");
  });
});

describe("toSkPublicKeyBlob", () => {
  function sshString(data: string | Buffer): Buffer {
    const payload = typeof data === "string" ? Buffer.from(data) : data;
    const len = Buffer.alloc(4);
    len.writeUInt32BE(payload.length, 0);
    return Buffer.concat([len, payload]);
  }

  it("rewrites webauthn-sk-... key type to sk-ecdsa-... and preserves the rest", () => {
    const tail = Buffer.concat([
      sshString("nistp256"),
      sshString(Buffer.from([0x04, ...new Array(64).fill(0xaa)])),
      sshString("example.com"),
    ]);
    const webauthnBlob = Buffer.concat([
      sshString("webauthn-sk-ecdsa-sha2-nistp256@openssh.com"),
      tail,
    ]);

    const skBlob = toSkPublicKeyBlob(webauthnBlob);
    const typeLen = skBlob.readUInt32BE(0);
    const typeStr = skBlob.subarray(4, 4 + typeLen).toString("utf-8");
    expect(typeStr).toBe("sk-ecdsa-sha2-nistp256@openssh.com");
    expect(skBlob.subarray(4 + typeLen).equals(tail)).toBe(true);
  });
});
