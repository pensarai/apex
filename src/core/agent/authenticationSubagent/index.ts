/**
 * Authentication Subagent
 *
 * Autonomous authentication module for acquiring and maintaining credentials.
 * For autonomous mode only - operator mode has separate auth handling.
 *
 * Usage:
 * ```typescript
 * import { runAuthenticationSubagent, AuthStateManager } from './authenticationSubagent';
 *
 * const result = await runAuthenticationSubagent({
 *   input: {
 *     target: 'https://example.com',
 *     session,
 *     credentials: { username: 'user', password: 'pass' },
 *   },
 *   model,
 * });
 *
 * if (result.success) {
 *   // Use result.exportedHeaders and result.exportedCookies for authenticated requests
 * }
 * ```
 */

// Main agent runner
export {
  runAuthenticationSubagent,
  discoverAuthentication,
  type RunAuthenticationSubagentOpts,
  type DiscoverAuthenticationOpts,
} from "./agent";

// State management
export { AuthStateManager, parseJWT, getJWTExpiration, buildAuthHeaders, formatCookies, extractCookiesFromHeaders } from "./authStateManager";

// Tools factory
export { createAuthenticationTools, type AuthToolsConfig, type HttpRequestOpts, type HttpRequestResult, type BrowserTools, type AuthenticationTools } from "./tools";

// Types
export type {
  // Core types
  AuthMethod,
  TokenType,
  AuthStatus,
  RoleLevel,
  AuthBarrierType,
  AuthToken,
  AuthEndpoint,
  AuthState,
  AuthBarrier,
  // Flow documentation
  CsrfExtraction,
  TokenExtractionConfig,
  BrowserFlowConfig,
  AuthFlowDocumentation,
  // Input/Output types
  AuthCredentials,
  AuthFlowHints,
  AuthenticationSubagentInput,
  AuthenticationSubagentResult,
  ExportedAuthInfo,
  // Discovery mode types
  AuthDiscoveryInput,
  AuthDiscoveryResult,
  AuthDiscoveryEvidence,
  // Tool types
  DetectAuthSchemeInput,
  AuthenticateInput,
  ValidateSessionInput,
  RefreshSessionInput,
  GetAuthStateInput,
  ExportAuthForAgentInput,
  LoadAuthFlowInput,
  DocumentAuthFlowInput,
  DetectAuthSchemeResult,
  AuthenticateResult,
  ValidateSessionResult,
  RefreshSessionResult,
  GetAuthStateResult,
  ExportAuthForAgentResult,
  LoadAuthFlowResult,
  DocumentAuthFlowResult,
} from "./types";

// Constants
export { AUTH_METHODS, TOKEN_TYPES, AUTH_STATUSES, ROLE_LEVELS, AUTH_BARRIER_TYPES } from "./types";

// Zod schemas (for consumers who need validation)
export {
  AuthMethodSchema,
  TokenTypeSchema,
  DetectAuthSchemeInputSchema,
  AuthenticateInputSchema,
  ValidateSessionInputSchema,
  RefreshSessionInputSchema,
  GetAuthStateInputSchema,
  ExportAuthForAgentInputSchema,
  LoadAuthFlowInputSchema,
  DocumentAuthFlowInputSchema,
} from "./types";

// Prompts (for advanced use cases)
export {
  AUTH_SUBAGENT_SYSTEM_PROMPT,
  AUTH_DISCOVERY_SYSTEM_PROMPT,
  buildAuthUserPrompt,
  buildAuthDiscoveryPrompt,
  CONTEXT_RECOVERY_REMINDER,
  BROWSER_FLOW_GUIDANCE,
} from "./prompts";

// Strategies
export {
  selectAuthStrategy,
  buildAuthFlowDocumentation,
  validateCredentials,
  getLoginEndpointsToTry,
  COMMON_LOGIN_ENDPOINTS,
  type HttpAuthConfig,
  type BrowserAuthConfig,
  type AuthStrategyResult,
} from "./strategies";

// Integration utilities
export {
  ensureAuthenticated,
  checkAuthStatus,
  getExistingAuth,
  buildTargetAuthInfo,
  type AuthenticationConfig,
  type EnsureAuthenticatedOptions,
  type EnsureAuthenticatedResult,
} from "./integration";

// Delegate tool factory (for subagents)
export {
  createDelegateToAuthSubagentTool,
  createGetAuthSessionTool,
  mergeAuthCredentials,
  type CreateDelegateAuthToolOpts,
  type SessionAuthInfo,
} from "./delegateTool";
