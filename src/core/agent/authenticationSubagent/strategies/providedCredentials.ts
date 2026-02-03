/**
 * Provided Credentials Strategy
 *
 * Handles authentication using credentials provided by the user.
 * Supports both HTTP-based and browser-based authentication flows.
 *
 * HTTP-based: form_post, json_post, basic_auth, bearer, api_key
 * Browser-based: SPA login forms, OAuth flows, JS-rendered pages
 */

import type { AuthCredentials, AuthFlowDocumentation, AuthMethod } from "../types";

// =============================================================================
// Types
// =============================================================================

export interface HttpAuthConfig {
  method: "form_post" | "json_post" | "basic_auth" | "bearer" | "api_key";
  loginUrl: string;
  usernameField: string;
  passwordField: string;
  csrfRequired: boolean;
  additionalFields?: Record<string, string>;
}

export interface BrowserAuthConfig {
  loginUrl: string;
  usernameSelector?: string;
  passwordSelector?: string;
  submitSelector?: string;
  postLoginIndicator?: string;
  tokenExtractionScript: string;
}

export interface AuthStrategyResult {
  useHttp: boolean;
  useBrowser: boolean;
  httpConfig?: HttpAuthConfig;
  browserConfig?: BrowserAuthConfig;
  reason: string;
}

// =============================================================================
// Strategy Selection
// =============================================================================

/**
 * Determine the best authentication strategy based on detected scheme
 */
export function selectAuthStrategy(
  detectedScheme: {
    method?: AuthMethod;
    loginUrl?: string;
    fields?: string[];
    csrfRequired?: boolean;
    browserRequired?: boolean;
    browserReason?: string;
  },
  credentials: AuthCredentials
): AuthStrategyResult {
  // If browser is explicitly required
  if (detectedScheme.browserRequired) {
    return {
      useHttp: false,
      useBrowser: true,
      browserConfig: buildBrowserConfig(detectedScheme.loginUrl || "", detectedScheme),
      reason: detectedScheme.browserReason || "Browser authentication required",
    };
  }

  // API key or bearer token - use HTTP
  if (credentials.apiKey) {
    return {
      useHttp: true,
      useBrowser: false,
      httpConfig: {
        method: "api_key",
        loginUrl: detectedScheme.loginUrl || "",
        usernameField: "",
        passwordField: "",
        csrfRequired: false,
      },
      reason: "API key authentication",
    };
  }

  // Based on detected method
  switch (detectedScheme.method) {
    case "basic":
      return {
        useHttp: true,
        useBrowser: false,
        httpConfig: {
          method: "basic_auth",
          loginUrl: detectedScheme.loginUrl || "",
          usernameField: "username",
          passwordField: "password",
          csrfRequired: false,
        },
        reason: "HTTP Basic Auth detected",
      };

    case "bearer":
      return {
        useHttp: true,
        useBrowser: false,
        httpConfig: {
          method: "bearer",
          loginUrl: detectedScheme.loginUrl || "",
          usernameField: "",
          passwordField: "",
          csrfRequired: false,
        },
        reason: "Bearer token authentication",
      };

    case "json":
      return {
        useHttp: true,
        useBrowser: false,
        httpConfig: {
          method: "json_post",
          loginUrl: detectedScheme.loginUrl || "",
          usernameField: detectUsernameField(detectedScheme.fields),
          passwordField: "password",
          csrfRequired: detectedScheme.csrfRequired || false,
        },
        reason: "JSON API authentication",
      };

    case "form":
      return {
        useHttp: true,
        useBrowser: false,
        httpConfig: {
          method: "form_post",
          loginUrl: detectedScheme.loginUrl || "",
          usernameField: detectUsernameField(detectedScheme.fields),
          passwordField: "password",
          csrfRequired: detectedScheme.csrfRequired || false,
        },
        reason: "Form-based authentication",
      };

    case "oauth":
      // OAuth typically requires browser
      return {
        useHttp: false,
        useBrowser: true,
        browserConfig: buildBrowserConfig(detectedScheme.loginUrl || "", detectedScheme),
        reason: "OAuth flow requires browser",
      };

    default:
      // Default to form POST if we have username/password
      if (credentials.username && credentials.password) {
        return {
          useHttp: true,
          useBrowser: false,
          httpConfig: {
            method: "form_post",
            loginUrl: detectedScheme.loginUrl || "",
            usernameField: "username",
            passwordField: "password",
            csrfRequired: detectedScheme.csrfRequired || false,
          },
          reason: "Defaulting to form POST with credentials",
        };
      }

      return {
        useHttp: false,
        useBrowser: true,
        browserConfig: buildBrowserConfig(detectedScheme.loginUrl || "", detectedScheme),
        reason: "Unable to determine HTTP method, trying browser",
      };
  }
}

// =============================================================================
// Config Builders
// =============================================================================

/**
 * Build browser configuration for authentication
 */
function buildBrowserConfig(
  loginUrl: string,
  scheme: { fields?: string[] }
): BrowserAuthConfig {
  return {
    loginUrl,
    usernameSelector: "Username field",
    passwordSelector: "Password field",
    submitSelector: "Login button",
    postLoginIndicator: undefined,
    tokenExtractionScript: buildTokenExtractionScript(),
  };
}

/**
 * Detect username field name from discovered fields
 */
function detectUsernameField(fields?: string[]): string {
  if (!fields || fields.length === 0) {
    return "username";
  }

  // Common username field names in order of preference
  const usernameVariants = ["username", "user", "email", "login", "userid", "user_id"];

  for (const variant of usernameVariants) {
    if (fields.some((f) => f.toLowerCase() === variant)) {
      return variant;
    }
  }

  // Return first non-password field
  const nonPasswordField = fields.find((f) => !f.toLowerCase().includes("password"));
  return nonPasswordField || "username";
}

/**
 * Build JavaScript to extract auth tokens from browser context
 */
function buildTokenExtractionScript(): string {
  return `
(function() {
  const result = {
    localStorage: {},
    sessionStorage: {},
    cookies: document.cookie,
    tokens: []
  };

  // Extract localStorage items
  for (let i = 0; i < localStorage.length; i++) {
    const key = localStorage.key(i);
    if (key) {
      const value = localStorage.getItem(key);
      result.localStorage[key] = value;

      // Identify potential tokens
      if (key.toLowerCase().includes('token') ||
          key.toLowerCase().includes('auth') ||
          key.toLowerCase().includes('jwt') ||
          key.toLowerCase().includes('session')) {
        result.tokens.push({
          source: 'localStorage',
          key: key,
          value: value
        });
      }
    }
  }

  // Extract sessionStorage items
  for (let i = 0; i < sessionStorage.length; i++) {
    const key = sessionStorage.key(i);
    if (key) {
      const value = sessionStorage.getItem(key);
      result.sessionStorage[key] = value;

      // Identify potential tokens
      if (key.toLowerCase().includes('token') ||
          key.toLowerCase().includes('auth') ||
          key.toLowerCase().includes('jwt') ||
          key.toLowerCase().includes('session')) {
        result.tokens.push({
          source: 'sessionStorage',
          key: key,
          value: value
        });
      }
    }
  }

  return JSON.stringify(result);
})()
`.trim();
}

// =============================================================================
// Flow Documentation Helpers
// =============================================================================

/**
 * Build auth flow documentation from successful authentication
 */
export function buildAuthFlowDocumentation(
  targetHost: string,
  strategyResult: AuthStrategyResult,
  tokenExtractionDetails: {
    accessTokenPath?: string;
    refreshTokenPath?: string;
    sessionCookieName?: string;
  }
): Omit<AuthFlowDocumentation, "documentedAt"> {
  const flow: Omit<AuthFlowDocumentation, "documentedAt"> = {
    targetHost,
    scheme: {
      method: determineAuthMethod(strategyResult),
      loginUrl: strategyResult.httpConfig?.loginUrl || strategyResult.browserConfig?.loginUrl || "",
    },
    fields: {
      usernameField: strategyResult.httpConfig?.usernameField || "username",
      passwordField: strategyResult.httpConfig?.passwordField || "password",
    },
    tokenExtraction: {},
  };

  // Add CSRF if required
  if (strategyResult.httpConfig?.csrfRequired) {
    flow.fields.csrfField = "_token";
    flow.csrfExtraction = {
      method: "input_hidden",
      selector: 'input[name="_token"], input[name="csrf_token"], input[name="authenticity_token"]',
    };
  }

  // Add token extraction config
  if (tokenExtractionDetails.accessTokenPath) {
    flow.tokenExtraction.accessToken = {
      location: "body",
      path: tokenExtractionDetails.accessTokenPath,
    };
  }

  if (tokenExtractionDetails.refreshTokenPath) {
    flow.tokenExtraction.refreshToken = {
      location: "body",
      path: tokenExtractionDetails.refreshTokenPath,
    };
  }

  if (tokenExtractionDetails.sessionCookieName) {
    flow.tokenExtraction.sessionCookie = {
      name: tokenExtractionDetails.sessionCookieName,
    };
  }

  // Add browser flow config if browser was used
  if (strategyResult.useBrowser && strategyResult.browserConfig) {
    flow.browserFlow = {
      required: true,
      reason: strategyResult.reason.includes("SPA") ? "spa" : strategyResult.reason.includes("OAuth") ? "oauth" : undefined,
      loginFormSelector: strategyResult.browserConfig.usernameSelector,
      submitButtonSelector: strategyResult.browserConfig.submitSelector,
      postLoginIndicator: strategyResult.browserConfig.postLoginIndicator,
    };
  }

  return flow;
}

/**
 * Determine AuthMethod from strategy result
 */
function determineAuthMethod(result: AuthStrategyResult): AuthMethod {
  if (result.httpConfig) {
    switch (result.httpConfig.method) {
      case "form_post":
        return "form";
      case "json_post":
        return "json";
      case "basic_auth":
        return "basic";
      case "bearer":
        return "bearer";
      case "api_key":
        return "api_key";
    }
  }

  // Browser flow defaults to form
  return "form";
}

// =============================================================================
// Credential Validation
// =============================================================================

/**
 * Validate that required credentials are present for the strategy
 */
export function validateCredentials(
  credentials: AuthCredentials,
  strategy: AuthStrategyResult
): { valid: boolean; missing: string[] } {
  const missing: string[] = [];

  if (strategy.httpConfig) {
    switch (strategy.httpConfig.method) {
      case "form_post":
      case "json_post":
      case "basic_auth":
        if (!credentials.username) missing.push("username");
        if (!credentials.password) missing.push("password");
        break;

      case "bearer":
      case "api_key":
        if (!credentials.apiKey) missing.push("apiKey");
        break;
    }
  }

  if (strategy.useBrowser) {
    if (!credentials.username) missing.push("username");
    if (!credentials.password) missing.push("password");
  }

  return {
    valid: missing.length === 0,
    missing,
  };
}

// =============================================================================
// Common Login Endpoints
// =============================================================================

/**
 * Common login endpoint patterns to try if login URL not discovered
 */
export const COMMON_LOGIN_ENDPOINTS = [
  "/login",
  "/signin",
  "/auth/login",
  "/api/login",
  "/api/auth/login",
  "/api/v1/login",
  "/api/v1/auth/login",
  "/user/login",
  "/users/login",
  "/account/login",
  "/session",
  "/sessions",
  "/oauth/token",
  "/token",
];

/**
 * Get list of login endpoints to try based on target
 */
export function getLoginEndpointsToTry(
  baseUrl: string,
  hints?: { loginEndpoints?: string[] }
): string[] {
  const endpoints: string[] = [];

  // Add hinted endpoints first
  if (hints?.loginEndpoints) {
    endpoints.push(...hints.loginEndpoints);
  }

  // Add common endpoints
  for (const path of COMMON_LOGIN_ENDPOINTS) {
    try {
      const url = new URL(path, baseUrl);
      if (!endpoints.includes(url.toString())) {
        endpoints.push(url.toString());
      }
    } catch {
      // Invalid URL, skip
    }
  }

  return endpoints;
}
