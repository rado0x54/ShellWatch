export {
  type AccountInfo,
  type AccountRepository,
  DrizzleAccountRepository,
  StubAccountRepository,
} from "./account-repo.js";
// ApiKeyAuthRepository is intentionally NOT re-exported here — it adds the
// cross-tenant findByHash primitive and is meant for the bearer gate + OAuth
// callback only. Importers needing it must reach into ./api-key-repo.js
// directly so the deep-import path makes "trusted internal" visible at the
// call site (#136).
export {
  type ApiKeyInfo,
  type ApiKeyRepository,
  DrizzleApiKeyRepository,
  InMemoryApiKeyRepository,
} from "./api-key-repo.js";
export { hasPasskeys } from "./credential-queries.js";
export {
  DrizzleEndpointRepository,
  type EndpointInfo,
  type EndpointRepository,
  InMemoryEndpointRepository,
} from "./endpoint-repo.js";
export {
  DrizzlePushSubscriptionRepository,
  type PushSubscriptionInfo,
  type PushSubscriptionRepository,
} from "./push-subscription-repo.js";
export {
  DrizzleSshKeyRepository,
  InMemorySshKeyRepository,
  type SshKeyInfo,
  type SshKeyRepository,
} from "./key-repo.js";
