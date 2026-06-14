// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
export {
  createHydraAdminClient,
  HydraApiError,
  type HydraAdminClient,
  type CreateHydraAdminClientParams,
} from "./admin-client.js";
export {
  createBearerResolver,
  type BearerPrincipal,
  type BearerResolver,
} from "./bearer-resolver.js";
export { ensureSpaClient } from "./ensure-client.js";
export { registerHydraRoutes, type RegisterHydraRoutesParams } from "./routes.js";
export type {
  HydraIntrospection,
  HydraOAuth2Client,
  HydraLoginRequest,
  HydraConsentRequest,
} from "./types.js";
