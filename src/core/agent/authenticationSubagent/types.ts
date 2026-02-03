/**
 * Authentication Subagent Types
 *
 * Type definitions and Zod schemas for the autonomous authentication subagent.
 * This module is for autonomous mode only - operator mode has separate auth handling.
 */

import { z } from "zod";
import type { Session } from "../../session";

// =============================================================================
// Constants
// =============================================================================

export const AUTH_METHODS = [
  "form",
  "json",
  "basic",
  "bearer",
  "oauth",
  "api_key",
] as const;

export const TOKEN_TYPES = [
  "cookie",
  "jwt",
  "bearer",
  "api_key",
  "session_id",
] as const;

export const AUTH_STATUSES = [
  "pending",
  "authenticating",
  "active",
  "expired",
  "failed",
] as const;

export const ROLE_LEVELS = [
  "guest",
  "user",
  "admin",
  "superadmin",
] as const;

export const AUTH_BARRIER_TYPES = [
  "captcha",
  "mfa",
  "oauth_consent",
  "rate_limit",
  "invite_code",
  "admin_approval",
  "email_verification",
  "phone_verification",
  "unknown",
] as const;

export const REGISTRATION_BARRIERS = [
  "invite_code",
  "admin_approval",
  "captcha",
  "email_verification",
  "phone_verification",
  "closed",
] as const;

// =============================================================================
// Core Types
// =============================================================================

export type AuthMethod = (typeof AUTH_METHODS)[number];
export type TokenType = (typeof TOKEN_TYPES)[number];
export type AuthStatus = (typeof AUTH_STATUSES)[number];
export type RoleLevel = (typeof ROLE_LEVELS)[number];
export type AuthBarrierType = (typeof AUTH_BARRIER_TYPES)[number];
export type RegistrationBarrier = (typeof REGISTRATION_BARRIERS)[number];

/**
 * Authentication token stored in session
 */
export interface AuthToken {
  type: TokenType;
  name: string;
  value: string;
  scope?: string;
  expiresAt?: number;
  refreshEndpoint?: string;
}

/**
 * Authentication endpoint configuration
 */
export interface AuthEndpoint {
  url: string;
  method: string;
  contentType: string;
  usernameField: string;
  passwordField: string;
  csrfField?: string;
  additionalFields?: Record<string, string>;
}

/**
 * Authentication state persisted to session
 */
export interface AuthState {
  id: string;
  targetHost: string;
  strategy: "provided" | "registration" | "extraction" | "verification";
  status: AuthStatus;
  tokens: AuthToken[];
  authEndpoint?: AuthEndpoint;
  authenticatedAt?: number;
  expiresAt?: number;
  lastValidatedAt?: number;
  roleLevel?: RoleLevel;
  discoveredScopes?: string[];
}

/**
 * Authentication barrier information
 */
export interface AuthBarrier {
  type: AuthBarrierType;
  details: string;
  loginUrl?: string;
}

// =============================================================================
// Auth Flow Documentation Types (Context Recovery)
// =============================================================================

/**
 * CSRF token extraction configuration
 */
export interface CsrfExtraction {
  method: "meta_tag" | "input_hidden" | "cookie" | "header";
  selector?: string;
  cookieName?: string;
  headerName?: string;
}

/**
 * Token extraction configuration from response
 */
export interface TokenExtractionConfig {
  location: "header" | "body" | "cookie";
  path?: string;
  headerName?: string;
  cookieName?: string;
}

/**
 * Browser flow configuration for SPAs
 */
export interface BrowserFlowConfig {
  required: boolean;
  reason?: "spa" | "oauth" | "captcha" | "mfa";
  loginFormSelector?: string;
  submitButtonSelector?: string;
  postLoginIndicator?: string;
  usernameInputSelector?: string;
  passwordInputSelector?: string;
}

/**
 * Registration/signup information
 */
export interface RegistrationInfo {
  /** Registration endpoint URL */
  url: string;
  /** Whether registration is open to anyone */
  isOpen: boolean;
  /** Barriers preventing registration */
  barriers: RegistrationBarrier[];
  /** Fields required to register */
  requiredFields: string[];
  /** Optional fields for registration */
  optionalFields?: string[];
  /** Notes for manual registration */
  notes?: string;
}

/**
 * Documented auth flow for context recovery
 * Persisted to auth/auth-flow.json
 */
export interface AuthFlowDocumentation {
  targetHost: string;
  documentedAt: number;

  scheme: {
    method: AuthMethod;
    loginUrl: string;
    logoutUrl?: string;
    refreshUrl?: string;
  };

  fields: {
    usernameField: string;
    passwordField: string;
    csrfField?: string;
    additionalFields?: Record<string, string>;
  };

  csrfExtraction?: CsrfExtraction;

  tokenExtraction: {
    accessToken?: TokenExtractionConfig;
    refreshToken?: TokenExtractionConfig;
    sessionCookie?: {
      name: string;
    };
  };

  browserFlow?: BrowserFlowConfig;

  /** Registration information if discovered */
  registration?: RegistrationInfo;

  notes?: string[];
}

// =============================================================================
// Input/Output Types
// =============================================================================

/**
 * Credentials for authentication
 */
export interface AuthCredentials {
  username?: string;
  password?: string;
  apiKey?: string;
  loginUrl?: string;
  additionalFields?: Record<string, string>;

  /**
   * Pre-existing tokens to verify/use directly (bypasses login flow)
   * If provided, the agent will first try to verify these grant access
   */
  tokens?: {
    /** Bearer/JWT token to use in Authorization header */
    bearerToken?: string;
    /** Session cookie(s) to use directly */
    cookies?: string;
    /** Session ID or token value */
    sessionToken?: string;
    /** Custom headers to include with requests (e.g., X-API-Key, X-Auth-Token) */
    customHeaders?: Record<string, string>;
  };
}

/**
 * Hints about auth flow from attack surface analysis
 */
export interface AuthFlowHints {
  /** Login endpoints discovered during recon */
  loginEndpoints?: string[];
  /** Protected endpoints that require auth (for token verification) */
  protectedEndpoints?: string[];
  /** Detected auth scheme */
  authScheme?: AuthMethod;
  /** Registration endpoint if discovered */
  registrationEndpoint?: string;
  /** Whether CSRF protection was detected */
  csrfRequired?: boolean;
  /** Whether CAPTCHA was detected */
  captchaDetected?: boolean;
}

/**
 * Input for running the authentication subagent
 *
 * Strategies:
 * - provided: Use provided username/password to authenticate
 * - registration: Create new account and authenticate
 * - extraction: Extract tokens from existing authenticated session
 * - verification: Verify provided tokens grant access (no login flow)
 */
export interface AuthenticationSubagentInput {
  target: string;
  session: Session.SessionInfo;
  strategy?: "provided" | "registration" | "extraction" | "verification";
  credentials?: AuthCredentials;
  authFlowHints?: AuthFlowHints;
}

/**
 * Result from authentication subagent
 */
export interface AuthenticationSubagentResult {
  success: boolean;
  authState: AuthState;
  strategy: "provided" | "registration" | "extraction" | "verification";
  exportedHeaders?: Record<string, string>;
  exportedCookies?: string;
  discoveredEndpoints?: {
    protected: string[];
    public: string[];
  };
  authBarrier?: AuthBarrier;
  summary: string;
}

/**
 * Authentication info exported for other agents
 * Matches PentestTarget.authenticationInfo format
 */
export interface ExportedAuthInfo {
  method: string;
  details: string;
  credentials?: string;
  cookies?: string;
  headers?: string;
}

// =============================================================================
// Zod Schemas for Tool Inputs
// =============================================================================

export const AuthMethodSchema = z.enum(AUTH_METHODS);
export const TokenTypeSchema = z.enum(TOKEN_TYPES);

/**
 * Schema for detect_auth_scheme tool input
 */
export const DetectAuthSchemeInputSchema = z.object({
  endpoint: z.string().describe("Target endpoint URL to analyze for auth requirements"),
  toolCallDescription: z.string().describe("Why you are detecting auth scheme for this endpoint"),
});

export type DetectAuthSchemeInput = z.infer<typeof DetectAuthSchemeInputSchema>;

/**
 * Schema for authenticate tool input
 */
export const AuthenticateInputSchema = z.object({
  loginUrl: z.string().describe("Login endpoint URL"),
  method: z.enum(["form_post", "json_post", "basic_auth", "bearer", "api_key"])
    .describe("Authentication method to use"),
  credentials: z.object({
    username: z.string().optional().describe("Username or email"),
    password: z.string().optional().describe("Password"),
    apiKey: z.string().optional().describe("API key if using api_key method"),
    customFields: z.record(z.string(), z.string()).optional()
      .describe("Additional fields required for authentication"),
  }),
  usernameField: z.string().default("username")
    .describe("Form field name for username (e.g., 'email', 'user')"),
  passwordField: z.string().default("password")
    .describe("Form field name for password"),
  csrfToken: z.string().optional()
    .describe("CSRF token if required"),
  toolCallDescription: z.string()
    .describe("Why you are authenticating with these credentials"),
});

export type AuthenticateInput = z.infer<typeof AuthenticateInputSchema>;

/**
 * Schema for validate_session tool input
 */
export const ValidateSessionInputSchema = z.object({
  testEndpoint: z.string().describe("Protected endpoint to test access"),
  expectedStatus: z.number().default(200)
    .describe("Expected HTTP status code for valid session"),
  toolCallDescription: z.string()
    .describe("Why you are validating the session"),
  // Optional: provide tokens directly to test (instead of using stored auth state)
  providedTokens: z.object({
    bearerToken: z.string().optional().describe("Bearer/JWT token to test"),
    cookies: z.string().optional().describe("Cookie string to test"),
    customHeaders: z.record(z.string(), z.string()).optional()
      .describe("Custom headers to include (e.g., X-API-Key, X-Auth-Token)"),
  }).optional().describe("Pre-existing tokens to validate. If provided, these will be tested and stored on success."),
});

export type ValidateSessionInput = z.infer<typeof ValidateSessionInputSchema>;

/**
 * Schema for refresh_session tool input
 */
export const RefreshSessionInputSchema = z.object({
  refreshEndpoint: z.string().optional()
    .describe("Token refresh endpoint URL"),
  useOriginalCredentials: z.boolean().default(true)
    .describe("Whether to re-authenticate with original credentials if refresh fails"),
  toolCallDescription: z.string()
    .describe("Why you are refreshing the session"),
});

export type RefreshSessionInput = z.infer<typeof RefreshSessionInputSchema>;

/**
 * Schema for get_auth_state tool input
 */
export const GetAuthStateInputSchema = z.object({
  toolCallDescription: z.string()
    .describe("Why you need to check the current auth state"),
});

export type GetAuthStateInput = z.infer<typeof GetAuthStateInputSchema>;

/**
 * Schema for export_auth_for_agent tool input
 */
export const ExportAuthForAgentInputSchema = z.object({
  format: z.enum(["headers", "curl", "poc_script"]).default("headers")
    .describe("Export format for auth information"),
  toolCallDescription: z.string()
    .describe("Why you are exporting auth for another agent"),
});

export type ExportAuthForAgentInput = z.infer<typeof ExportAuthForAgentInputSchema>;

/**
 * Schema for load_auth_flow tool input
 */
export const LoadAuthFlowInputSchema = z.object({
  targetHost: z.string().describe("Target host to load auth flow for"),
  toolCallDescription: z.string()
    .describe("Why you are loading the documented auth flow"),
});

export type LoadAuthFlowInput = z.infer<typeof LoadAuthFlowInputSchema>;

/**
 * Schema for document_auth_flow tool input
 */
export const DocumentAuthFlowInputSchema = z.object({
  targetHost: z.string().describe("Target host this flow applies to"),
  scheme: z.object({
    method: AuthMethodSchema.describe("Authentication method discovered"),
    loginUrl: z.string().describe("Login endpoint URL"),
    logoutUrl: z.string().optional().describe("Logout endpoint URL if discovered"),
    refreshUrl: z.string().optional().describe("Token refresh endpoint URL if discovered"),
  }),
  fields: z.object({
    usernameField: z.string().describe("Form field name for username"),
    passwordField: z.string().describe("Form field name for password"),
    csrfField: z.string().optional().describe("CSRF token field name if required"),
    additionalFields: z.record(z.string(), z.string()).optional()
      .describe("Other required fields discovered"),
  }),
  csrfExtraction: z.object({
    method: z.enum(["meta_tag", "input_hidden", "cookie", "header"])
      .describe("How to extract CSRF token"),
    selector: z.string().optional().describe("CSS selector if meta_tag or input_hidden"),
    cookieName: z.string().optional().describe("Cookie name if from cookie"),
    headerName: z.string().optional().describe("Header name if from response header"),
  }).optional(),
  tokenExtraction: z.object({
    accessToken: z.object({
      location: z.enum(["header", "body", "cookie"]),
      path: z.string().optional().describe("JSON path if in body"),
      headerName: z.string().optional(),
      cookieName: z.string().optional(),
    }).optional(),
    refreshToken: z.object({
      location: z.enum(["header", "body", "cookie"]),
      path: z.string().optional(),
      headerName: z.string().optional(),
      cookieName: z.string().optional(),
    }).optional(),
    sessionCookie: z.object({
      name: z.string().describe("Session cookie name"),
    }).optional(),
  }),
  browserFlow: z.object({
    required: z.boolean().describe("Whether browser automation was needed"),
    reason: z.enum(["spa", "oauth", "captcha", "mfa"]).optional()
      .describe("Why browser was required"),
    loginFormSelector: z.string().optional(),
    submitButtonSelector: z.string().optional(),
    postLoginIndicator: z.string().optional()
      .describe("Element that appears after successful login"),
    usernameInputSelector: z.string().optional(),
    passwordInputSelector: z.string().optional(),
  }).optional(),
  notes: z.array(z.string()).optional()
    .describe("Notes for future runs (rate limits, quirks, etc.)"),
  toolCallDescription: z.string()
    .describe("Why you are documenting this auth flow"),
});

export type DocumentAuthFlowInput = z.infer<typeof DocumentAuthFlowInputSchema>;

/**
 * Schema for probe_auth_endpoints tool input
 */
export const ProbeAuthEndpointsInputSchema = z.object({
  baseUrl: z.string().describe("Base URL of the target (e.g., http://localhost:3002)"),
  toolCallDescription: z.string().describe("Why you are probing for auth endpoints"),
});

export type ProbeAuthEndpointsInput = z.infer<typeof ProbeAuthEndpointsInputSchema>;

/**
 * Schema for probe_registration tool input
 */
export const ProbeRegistrationInputSchema = z.object({
  baseUrl: z.string().describe("Base URL of the target (e.g., http://localhost:3002)"),
  toolCallDescription: z.string().describe("Why you are probing for registration functionality"),
});

export type ProbeRegistrationInput = z.infer<typeof ProbeRegistrationInputSchema>;

/**
 * Schema for attempt_registration tool input
 */
export const AttemptRegistrationInputSchema = z.object({
  registrationUrl: z.string().describe("Registration endpoint URL discovered from probe_registration"),
  requiredFields: z.record(z.string(), z.string()).describe("Required field values (e.g., { email: 'test@example.com', username: 'testuser', password: 'Test123!' })"),
  toolCallDescription: z.string().describe("Why you are attempting registration"),
});

export type AttemptRegistrationInput = z.infer<typeof AttemptRegistrationInputSchema>;

// =============================================================================
// Tool Result Types
// =============================================================================

/**
 * Result from detect_auth_scheme tool
 */
export interface DetectAuthSchemeResult {
  success: boolean;
  scheme?: {
    method: AuthMethod;
    loginUrl?: string;
    fields?: string[];
    csrfRequired?: boolean;
    browserRequired?: boolean;
    browserReason?: string;
  };
  barrier?: AuthBarrier;
  error?: string;
}

/**
 * Result from authenticate tool
 */
export interface AuthenticateResult {
  success: boolean;
  tokens?: AuthToken[];
  authState?: AuthState;
  barrier?: AuthBarrier;
  error?: string;
  message: string;
}

/**
 * Result from validate_session tool
 */
export interface ValidateSessionResult {
  success: boolean;
  valid: boolean;
  statusCode?: number;
  message: string;
  error?: string;
}

/**
 * Result from refresh_session tool
 */
export interface RefreshSessionResult {
  success: boolean;
  newTokens?: AuthToken[];
  error?: string;
  message: string;
}

/**
 * Result from get_auth_state tool
 */
export interface GetAuthStateResult {
  success: boolean;
  state: AuthState;
  headers: Record<string, string>;
  cookies: string;
  isValid: boolean;
  message: string;
}

/**
 * Result from export_auth_for_agent tool
 */
export interface ExportAuthForAgentResult {
  success: boolean;
  format: string;
  headers?: Record<string, string>;
  curlFlags?: string;
  pocScript?: string;
  authenticationInfo: ExportedAuthInfo;
  message: string;
}

/**
 * Result from load_auth_flow tool
 */
export interface LoadAuthFlowResult {
  success: boolean;
  flowExists: boolean;
  flow?: AuthFlowDocumentation;
  message: string;
}

/**
 * Result from document_auth_flow tool
 */
export interface DocumentAuthFlowResult {
  success: boolean;
  flowPath: string;
  message: string;
  error?: string;
}

/**
 * Result from probe_auth_endpoints tool
 */
export interface ProbeAuthEndpointsResult {
  success: boolean;
  endpoints: {
    path: string;
    methods: string[];
    authIndicators: string[];
    likelyPurpose: "login" | "token" | "refresh" | "user" | "unknown";
  }[];
  recommendedLoginEndpoint?: string;
  recommendedMethod?: string;
  message: string;
}

/**
 * Result from probe_registration tool
 */
export interface ProbeRegistrationResult {
  success: boolean;
  /** Whether self-registration appears possible */
  canRegister: boolean;
  /** Discovered registration URL */
  registrationUrl?: string;
  /** Barriers that may prevent registration */
  barriers: RegistrationBarrier[];
  /** Fields required for registration */
  requiredFields: string[];
  /** Optional fields available for registration */
  optionalFields?: string[];
  /** Notes about the registration process */
  notes?: string;
  message: string;
  error?: string;
}

/**
 * Result from attempt_registration tool
 */
export interface AttemptRegistrationResult {
  success: boolean;
  /** Generated credentials if registration succeeded */
  credentials?: {
    username: string;
    password: string;
    email?: string;
  };
  /** Barriers encountered during registration */
  barriers?: RegistrationBarrier[];
  /** Response status code */
  statusCode?: number;
  message: string;
  error?: string;
}

// =============================================================================
// Discovery Mode Types
// =============================================================================

/**
 * Input for auth discovery (standalone mode)
 */
export interface AuthDiscoveryInput {
  target: string;
  session: Session.SessionInfo;
  additionalEndpoints?: string[];
}

/**
 * Evidence collected during auth discovery
 */
export interface AuthDiscoveryEvidence {
  endpoint: string;
  statusCode?: number;
  headers?: Record<string, string>;
  hasLoginForm?: boolean;
  hasAuthHeader?: boolean;
  redirectsToLogin?: boolean;
  loginUrl?: string;
  notes: string;
}

/**
 * Result from auth discovery
 */
export interface AuthDiscoveryResult {
  /** Whether authentication is required */
  requiresAuth: boolean;

  /** Detected authentication type */
  authType: "none" | "form" | "json" | "basic" | "bearer" | "api_key" | "oauth" | "unknown";

  /** Confidence level 0-100 */
  confidence: number;

  /** Discovered login URL if found */
  loginUrl?: string;

  /** Step-by-step reasoning chain */
  reasoning: string[];

  /** Recommended approach for authentication */
  recommendedApproach?: string;

  /** Evidence collected during discovery */
  evidence: AuthDiscoveryEvidence[];

  /** Detected barriers (CAPTCHA, MFA, etc.) */
  barriers?: AuthBarrier[];

  /** Summary of findings */
  summary: string;
}
