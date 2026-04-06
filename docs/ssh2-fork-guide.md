# ssh2 Fork: WebAuthn SK Key Support

## Goal

Add support for the custom `webauthn-sk-ecdsa-sha2-nistp256@openssh.com` key algorithm to ssh2, enabling ShellWatch to authenticate to SSH servers using WebAuthn credentials via a custom agent that delegates signing to the browser.

## Reference Implementation

The [ssheasy](https://github.com/hullarb/ssheasy) project (Go) implements this exact protocol. The wire formats below are based on their implementation.

## Algorithm Name

```
webauthn-sk-ecdsa-sha2-nistp256@openssh.com
```

This is NOT the standard `sk-ecdsa-sha2-nistp256@openssh.com` (which uses rp.id `"ssh:"`). The `webauthn-` prefix indicates the credential was created via the browser WebAuthn API with a web origin as the relying party.

## Server Requirement

The remote SSH server must have this in `sshd_config`:

```
PubkeyAcceptedAlgorithms=+webauthn-sk-ecdsa-sha2-nistp256@openssh.com
```

---

## Changes Required (4 files)

### 1. `lib/protocol/constants.js` — Add algorithm to supported list

**Location:** The `DEFAULT_SERVER_HOST_KEY` array (line ~64)

**Change:** Add the algorithm name so ssh2 doesn't reject it during negotiation:

```js
// Around line 64-76
const DEFAULT_SERVER_HOST_KEY = [
  "ecdsa-sha2-nistp256",
  "ecdsa-sha2-nistp384",
  "ecdsa-sha2-nistp521",
  "rsa-sha2-512",
  "rsa-sha2-256",
  "ssh-rsa",
  "webauthn-sk-ecdsa-sha2-nistp256@openssh.com", // ADD THIS
];
```

Also check if there are other algorithm lists (like `SUPPORTED_CIPHER`, `SUPPORTED_MAC`, etc.) — this algorithm only needs to be in the **public key** algorithm lists, not cipher/mac/kex.

Search for any `SUPPORTED` arrays that list key algorithms and add the new one.

### 2. `lib/protocol/keyParser.js` — Parse the custom public key format

**Location:** The `parseKey()` function (line ~1416) and the binary key parsing section (line ~1456)

**What to add:** A parser that recognizes the custom public key wire format:

```
string  "webauthn-sk-ecdsa-sha2-nistp256@openssh.com"
string  "nistp256"
string  0x04 || X (32 bytes) || Y (32 bytes)   (uncompressed EC point)
string  application                              (rp.id, e.g., "localhost")
```

**How:** Add a new key class (similar to the existing ECDSA key classes) that:

- Has `type` = `"webauthn-sk-ecdsa-sha2-nistp256@openssh.com"`
- Stores the EC point (x, y) and the application string
- Implements `getPublicSSH()` returning the wire-format blob above
- Implements `getPublicPEM()` (can throw "not supported" — we don't need PEM export)
- Has `[SYM_DECRYPTED] = true` so `isParsedKey()` returns true

**Concrete approach:** Hook into the existing binary parsing flow at line ~1456.

The existing code already does:

```js
if (origBuffer) {
  binaryKeyParser.init(origBuffer, 0);
  const type = binaryKeyParser.readString(true);
  if (type !== undefined) {
    data = binaryKeyParser.readRaw();
    if (data !== undefined) {
      ret = parseDER(data, type, "", type);
      // ...
    }
  }
  binaryKeyParser.clear();
}
```

Insert our check **after** `type` is read but **before** `parseDER` is called:

```js
if (origBuffer) {
  binaryKeyParser.init(origBuffer, 0);
  const type = binaryKeyParser.readString(true);
  if (type !== undefined) {
    // --- ADD: WebAuthn SK key handling ---
    if (type === "webauthn-sk-ecdsa-sha2-nistp256@openssh.com") {
      const curve = binaryKeyParser.readString(true); // "nistp256"
      const ecPoint = binaryKeyParser.readString(); // 0x04 || X || Y (65 bytes)
      const application = binaryKeyParser.readString(true); // rp.id
      binaryKeyParser.clear();
      if (curve === "nistp256" && ecPoint && ecPoint.length === 65 && ecPoint[0] === 0x04) {
        return new WebAuthnSKECDSAKey(ecPoint, application);
      }
      return new Error("Invalid WebAuthn SK ECDSA key format");
    }
    // --- END ADD ---

    data = binaryKeyParser.readRaw();
    if (data !== undefined) {
      ret = parseDER(data, type, "", type);
      // ...
    }
  }
  binaryKeyParser.clear();
}
```

This is clean because:

- The existing `binaryKeyParser.init()` and `readString(true)` already happened
- We intercept when `type` matches our algorithm name
- We read the remaining fields using the same `binaryKeyParser`
- We return early, so the existing `parseDER` path is never reached for our key type
- No code duplication

**New class `WebAuthnSKECDSAKey`:**

```js
class WebAuthnSKECDSAKey {
  constructor(ecPoint, application) {
    this[SYM_DECRYPTED] = true;
    this.type = "webauthn-sk-ecdsa-sha2-nistp256@openssh.com";
    this._ecPoint = ecPoint; // Buffer: 0x04 || X || Y
    this._application = application; // String: rp.id
  }

  getPublicSSH() {
    // Wire format: string type || string curve || string ecPoint || string application
    const algo = Buffer.from("webauthn-sk-ecdsa-sha2-nistp256@openssh.com");
    const curve = Buffer.from("nistp256");
    const app = Buffer.from(this._application);

    const buf = Buffer.allocUnsafe(
      4 + algo.length + 4 + curve.length + 4 + this._ecPoint.length + 4 + app.length,
    );
    let offset = 0;

    buf.writeUInt32BE(algo.length, offset);
    offset += 4;
    algo.copy(buf, offset);
    offset += algo.length;

    buf.writeUInt32BE(curve.length, offset);
    offset += 4;
    curve.copy(buf, offset);
    offset += curve.length;

    buf.writeUInt32BE(this._ecPoint.length, offset);
    offset += 4;
    this._ecPoint.copy(buf, offset);
    offset += this._ecPoint.length;

    buf.writeUInt32BE(app.length, offset);
    offset += 4;
    app.copy(buf, offset);

    return buf;
  }

  getPublicPEM() {
    throw new Error("PEM export not supported for WebAuthn SK keys");
  }

  getPrivatePEM() {
    throw new Error("WebAuthn SK keys have no exportable private key");
  }

  sign() {
    throw new Error("WebAuthn SK keys must be signed via agent");
  }

  verify() {
    throw new Error("Verification not implemented for WebAuthn SK keys");
  }

  isPrivateKey() {
    return false;
  }

  equals(key) {
    if (!(key instanceof WebAuthnSKECDSAKey)) return false;
    return this._ecPoint.equals(key._ecPoint) && this._application === key._application;
  }
}
```

### 3. `lib/client.js` — Allow custom algorithm in auth flow

**Location:** `getKeyAlgos()` function (line ~2155)

**Problem:** This function only returns algorithm tuples for `ssh-rsa` keys. For all other key types, it returns `undefined`, causing the key to be skipped during auth.

**Change:** Add a case for the WebAuthn key type:

```js
function getKeyAlgos(client, key, serverSigAlgs) {
  // ... existing RSA handling ...

  switch (key.type) {
    // ... existing cases ...

    case "webauthn-sk-ecdsa-sha2-nistp256@openssh.com":
      // Return the algorithm as-is — no algorithm negotiation needed
      // The hash is always SHA-256 for P-256
      return [["webauthn-sk-ecdsa-sha2-nistp256@openssh.com", "sha256"]];
  }
}
```

**Also check:** The `tryNextAgentKey()` function (line ~1083) — make sure it doesn't filter out unknown key types. It calls `getKeyAlgos()` and skips if the result is empty, so the fix above should be sufficient.

### 4. `lib/protocol/utils.js` — Pass through custom signature format

**Location:** `convertSignature()` function (line ~284)

**Current behavior:** This function has specific handling for `ssh-dss` and `ecdsa-sha2-*` key types. Unknown types are passed through unchanged.

**What to verify:** Ensure our custom algorithm falls through to the default case (pass-through). The function signature is:

```js
function convertSignature(signature, keyType) {
  switch (keyType) {
    case 'ssh-dss': { ... }
    case 'ecdsa-sha2-nistp256':
    case 'ecdsa-sha2-nistp384':
    case 'ecdsa-sha2-nistp521': { ... }
    default:
      return signature;  // <-- Our algorithm hits this — GOOD
  }
}
```

**Important:** The `ecdsa-sha2-*` case converts between ASN.1 and SSH signature formats. Our WebAuthn signature is NOT in standard ECDSA format — it has additional fields (flags, counter, origin, clientData). If `convertSignature` matched our algorithm to the ECDSA case, it would corrupt the signature. Since our algorithm name doesn't start with `ecdsa-sha2-`, it falls through to default. **No change needed here**, but verify this is the case.

---

## Signature Wire Format (for reference)

When the custom agent's `sign()` method is called, it must return the signature in this format:

```
string  "webauthn-sk-ecdsa-sha2-nistp256@openssh.com"   (algorithm name)
string  signature_blob                                    (see below)
```

Where `signature_blob` is:

```
string  ecdsa_signature    (SSH-encoded: uint32 R_len || R || uint32 S_len || S)
byte    flags              (authenticator data flags from WebAuthn)
uint32  counter            (authenticator counter)
string  origin             (e.g., "http://localhost:3000")
string  clientDataJSON     (the clientDataJSON from navigator.credentials.get())
string  extensions         (empty string for now)
```

The ECDSA signature (R, S) comes from the WebAuthn response's `signature` field, which is ASN.1 DER encoded. It must be decoded from ASN.1 and re-encoded as SSH wire format (length-prefixed R and S).

**Note:** ssh2's agent protocol handler (agent.js line 658-659) strips the algorithm name from the agent response and returns only the signature blob. The algorithm name is re-added by `Protocol.authPK()` when constructing the SSH packet. So the agent's `sign()` callback should return the FULL format (algorithm + blob), and ssh2 will extract just the blob.

---

## Testing the Fork

1. Apply the changes above
2. In ShellWatch, point to the fork: `pnpm add ../ssh2`
3. Create a test that:
   - Constructs a `WebAuthnSKECDSAKey` from a known EC point
   - Calls `parseKey()` with the binary wire format
   - Verifies `key.type` is correct
   - Verifies `key.getPublicSSH()` produces the correct blob
4. Integration test: connect to an SSH server with `PubkeyAcceptedAlgorithms` configured

---

## What ShellWatch Does (not in the fork)

The fork ONLY adds:

- Key format recognition (parsing)
- Algorithm acceptance (auth flow gate)
- Signature passthrough

ShellWatch handles:

- Creating the custom agent that delegates `sign()` to the browser via WebSocket
- The WebAuthn `navigator.credentials.get()` flow in the browser
- Wrapping the WebAuthn response in the SSH signature wire format
- Managing the WebSocket signing channel between server and browser

---

## Files Changed Summary

| File                        | Change                                         | Lines     |
| --------------------------- | ---------------------------------------------- | --------- |
| `lib/protocol/constants.js` | Add algorithm to key algo list                 | ~1 line   |
| `lib/protocol/keyParser.js` | Add `WebAuthnSKECDSAKey` class + binary parser | ~60 lines |
| `lib/client.js`             | Add case in `getKeyAlgos()`                    | ~3 lines  |
| `lib/protocol/utils.js`     | Verify passthrough (likely no change needed)   | 0 lines   |

**Total: ~65 lines of new code.**
