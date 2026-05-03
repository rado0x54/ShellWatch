// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
export {
  buildFileKeyEntry,
  type CompositeAgentParams,
  CompositeSshAgent,
  type FileKeyEntry,
  type FileKeySignRequest,
} from "./composite-ssh-agent.js";
export { registerWebAuthnRoutes } from "./routes.js";
export {
  buildSshSignatureBlob,
  parseAsn1Signature,
  parseWebAuthnSignature,
} from "./signature-format.js";
export { SigningBridge } from "./signing-bridge.js";
export {
  type AgentLogger,
  buildPasskeyEntry,
  type PasskeyEntry,
  type SignRequest,
  type SignResponse,
  type WebAuthnSshAgentParams,
  WebAuthnSshAgent,
} from "./ssh-agent.js";
export type { SigningBridgeParams } from "./signing-bridge.js";
export {
  buildPublicKeyBlob,
  coseToAuthorizedKeys,
  getSshdConfigLine,
  WEBAUTHN_SSH_ALGORITHM,
} from "./ssh-key-format.js";
