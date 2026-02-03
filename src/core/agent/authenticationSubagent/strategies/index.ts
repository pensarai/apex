/**
 * Authentication Strategies
 *
 * Exports strategy implementations for credential acquisition.
 */

export {
  selectAuthStrategy,
  buildAuthFlowDocumentation,
  validateCredentials,
  getLoginEndpointsToTry,
  COMMON_LOGIN_ENDPOINTS,
  type HttpAuthConfig,
  type BrowserAuthConfig,
  type AuthStrategyResult,
} from "./providedCredentials";
