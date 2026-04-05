export { registerAgentProxyRoute, type AgentProxyRouteParams } from "./agent-proxy-route.js";
export {
  createAgentHandler,
  rewriteSkEcdsaSignRequest,
  buildWebauthnSignResponse,
  AgentProtocol,
  type AgentProtocolInstance,
  type AgentHandlerDeps,
} from "./socket-agent-handler.js";
