/**
 * Authentication Subagent Tools
 *
 * Tool factory for authentication operations in autonomous mode.
 * Provides tools for detecting auth schemes, authenticating, validating sessions,
 * and exporting auth state for other agents.
 */

import { tool } from "ai";
import { z } from "zod";
import type { Session } from "../../session";
import type { Logger } from "../logger";
import {
  AuthStateManager,
  extractCookiesFromHeaders,
  getJWTExpiration,
} from "./authStateManager";
import {
  DetectAuthSchemeInputSchema,
  AuthenticateInputSchema,
  ValidateSessionInputSchema,
  RefreshSessionInputSchema,
  GetAuthStateInputSchema,
  ExportAuthForAgentInputSchema,
  LoadAuthFlowInputSchema,
  DocumentAuthFlowInputSchema,
  ProbeAuthEndpointsInputSchema,
  ProbeRegistrationInputSchema,
  AttemptRegistrationInputSchema,
  type DetectAuthSchemeResult,
  type AuthenticateResult,
  type ValidateSessionResult,
  type RefreshSessionResult,
  type GetAuthStateResult,
  type ExportAuthForAgentResult,
  type LoadAuthFlowResult,
  type DocumentAuthFlowResult,
  type ProbeAuthEndpointsResult,
  type ProbeRegistrationResult,
  type AttemptRegistrationResult,
  type AuthToken,
  type AuthBarrier,
  type RegistrationBarrier,
} from "./types";

// =============================================================================
// Types
// =============================================================================

export interface HttpRequestOpts {
  url: string;
  method: string;
  headers?: Record<string, string>;
  body?: string;
  followRedirects?: boolean;
  timeout?: number;
}

export interface HttpRequestResult {
  success: boolean;
  status: number;
  statusText: string;
  headers: Record<string, string | string[]>;
  body: string;
  error?: string;
  redirected?: boolean;
  url?: string;
}

// BrowserTools is the return type from createBrowserTools
// We use a generic record type to be compatible with the actual tool structure
export type BrowserTools = ReturnType<
  typeof import("../browserTools/playwrightMcp").createBrowserTools
>;

export interface AuthToolsConfig {
  session: Session.SessionInfo;
  authStateManager: AuthStateManager;
  httpRequest?: (opts: HttpRequestOpts) => Promise<HttpRequestResult>;
  browserTools?: BrowserTools;
  logger?: Logger;
  abortSignal?: AbortSignal;
}

// =============================================================================
// Default HTTP Request Implementation
// =============================================================================

async function defaultHttpRequest(
  opts: HttpRequestOpts,
): Promise<HttpRequestResult> {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(
      () => controller.abort(),
      opts.timeout || 30000,
    );

    const response = await fetch(opts.url, {
      method: opts.method,
      headers: opts.headers,
      body: opts.body,
      redirect: opts.followRedirects !== false ? "follow" : "manual",
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    const headers: Record<string, string | string[]> = {};
    response.headers.forEach((value, key) => {
      // Handle multiple Set-Cookie headers
      if (key.toLowerCase() === "set-cookie") {
        const existing = headers[key];
        if (Array.isArray(existing)) {
          existing.push(value);
        } else if (existing) {
          headers[key] = [existing, value];
        } else {
          headers[key] = [value];
        }
      } else {
        headers[key] = value;
      }
    });

    const body = await response.text();

    return {
      success: true,
      status: response.status,
      statusText: response.statusText,
      headers,
      body,
      redirected: response.redirected,
      url: response.url,
    };
  } catch (error) {
    return {
      success: false,
      status: 0,
      statusText: "",
      headers: {},
      body: "",
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

// =============================================================================
// Auth Barrier Detection
// =============================================================================

function detectAuthBarrier(
  responseBody: string,
  statusCode: number,
): AuthBarrier | null {
  const bodyLower = responseBody.toLowerCase();

  // CAPTCHA detection — these are specific enough to avoid false positives
  if (
    bodyLower.includes("captcha") ||
    bodyLower.includes("recaptcha") ||
    bodyLower.includes("hcaptcha") ||
    bodyLower.includes("g-recaptcha")
  ) {
    return {
      type: "captcha",
      details: "CAPTCHA detected on login form",
    };
  }

  // MFA/2FA detection — use word-boundary regex to avoid false positives from
  // substrings like "authenticator" (common on any auth page) or "mfa" appearing
  // in URLs/class names. Require multiple signals or very specific patterns that
  // indicate an actual MFA interstitial page, not just a page that mentions MFA.
  // const mfaInterstitialPatterns = [
  //   /\btwo-factor\s+auth/i,              // "two-factor authentication" as a prompt
  //   /\b2fa\s+(code|token|verify)/i,      // "2fa code", "2fa token", "2fa verify"
  //   /enter\s+(your\s+)?(verification|security|otp|2fa|mfa)\s*(code|token)/i, // "enter your verification code"
  //   /enter\s+(your\s+)?one-time\s+(password|code)/i,  // "enter your one-time password"
  //   /\botp\s+(code|token|verification)\b/i,  // "otp code", "otp verification"
  //   /\bcheck\s+your\s+(authenticator|email|phone)\s+(app|for)/i,  // "check your authenticator app"
  //   /multi-factor\s+auth/i,              // "multi-factor authentication" as a prompt
  // ];

  // if (mfaInterstitialPatterns.some((pattern) => pattern.test(bodyLower))) {
  //   return {
  //     type: "mfa",
  //     details: "Multi-factor authentication required",
  //   };
  // }

  // Rate limiting
  if (
    statusCode === 429 ||
    bodyLower.includes("rate limit") ||
    bodyLower.includes("too many")
  ) {
    return {
      type: "rate_limit",
      details: "Rate limiting detected",
    };
  }

  return null;
}

// =============================================================================
// Tool Factory
// =============================================================================

export function createAuthenticationTools(config: AuthToolsConfig) {
  const {
    session,
    authStateManager,
    httpRequest,
    browserTools,
    logger,
    abortSignal,
  } = config;

  const makeRequest = httpRequest || defaultHttpRequest;

  // ===========================================================================
  // Tool: load_auth_flow
  // ===========================================================================

  const load_auth_flow = tool({
    description: `Load previously documented authentication flow for context recovery.

CRITICAL: Call this FIRST when starting auth tasks.
If a flow exists, skip discovery and proceed directly to authentication.

Returns:
- Documented auth flow (if exists) with login URL, field names, token locations
- null if no prior documentation

This allows resumed agents to authenticate immediately without re-discovery.`,
    inputSchema: LoadAuthFlowInputSchema,
    execute: async ({
      targetHost,
      toolCallDescription,
    }): Promise<LoadAuthFlowResult> => {
      logger?.info(`load_auth_flow: ${targetHost}`);

      const flow = authStateManager.loadFlow(targetHost);

      if (flow) {
        return {
          success: true,
          flowExists: true,
          flow,
          message: `Loaded documented auth flow for ${targetHost}. Login URL: ${flow.scheme.loginUrl}, Method: ${flow.scheme.method}`,
        };
      }

      return {
        success: true,
        flowExists: false,
        message: `No documented auth flow found for ${targetHost}. Need to discover auth scheme.`,
      };
    },
  });

  // ===========================================================================
  // Tool: detect_auth_scheme
  // ===========================================================================

  const detect_auth_scheme = tool({
    description: `Analyze an endpoint to detect authentication scheme.

Identifies:
- Form-based login (username/password fields)
- HTTP Basic/Digest Auth (WWW-Authenticate header)
- Bearer Token / JWT requirements
- API Key authentication (X-API-Key, etc.)
- OAuth2 flows
- Custom authentication schemes

Also detects auth barriers (CAPTCHA, MFA) that block automated auth.

Returns detected scheme and required fields for authentication.`,
    inputSchema: DetectAuthSchemeInputSchema,
    execute: async ({
      endpoint,
      toolCallDescription,
    }): Promise<DetectAuthSchemeResult> => {
      logger?.info(`detect_auth_scheme: ${endpoint}`);

      // Check if aborted
      if (abortSignal?.aborted) {
        return { success: false, error: "Request aborted" };
      }

      try {
        // First, make a GET request to the endpoint
        const response = await makeRequest({
          url: endpoint,
          method: "GET",
          followRedirects: false,
          timeout: 30000,
        });

        if (!response.success) {
          return { success: false, error: response.error };
        }

        const bodyLower = response.body.toLowerCase();
        const headers = response.headers;

        // Check for auth barrier first
        const barrier = detectAuthBarrier(response.body, response.status);
        if (barrier) {
          return {
            success: true,
            barrier,
          };
        }

        // Check WWW-Authenticate header for Basic/Bearer auth
        const wwwAuth =
          headers["www-authenticate"] || headers["WWW-Authenticate"];
        if (wwwAuth) {
          const authHeader = Array.isArray(wwwAuth) ? wwwAuth[0] : wwwAuth;
          if (authHeader.toLowerCase().startsWith("basic")) {
            return {
              success: true,
              scheme: {
                method: "basic",
                loginUrl: endpoint,
                fields: ["username", "password"],
              },
            };
          }
          if (authHeader.toLowerCase().startsWith("bearer")) {
            return {
              success: true,
              scheme: {
                method: "bearer",
                loginUrl: endpoint,
              },
            };
          }
        }

        // Check for redirect to login page
        if (
          response.status === 301 ||
          response.status === 302 ||
          response.status === 303
        ) {
          const location = headers["location"] || headers["Location"];
          if (location) {
            const loginUrl = Array.isArray(location) ? location[0] : location;
            if (
              loginUrl.includes("login") ||
              loginUrl.includes("signin") ||
              loginUrl.includes("auth")
            ) {
              return {
                success: true,
                scheme: {
                  method: "form",
                  loginUrl,
                  browserRequired: true,
                  browserReason: "Redirect to login page detected",
                },
              };
            }
          }
        }

        // Check for form-based login indicators
        const hasLoginForm =
          bodyLower.includes('type="password"') ||
          bodyLower.includes("type='password'") ||
          bodyLower.includes('name="password"') ||
          bodyLower.includes('name="pass"');

        if (hasLoginForm) {
          const fields: string[] = [];

          // Detect username field
          if (
            bodyLower.includes('name="username"') ||
            bodyLower.includes('name="user"')
          ) {
            fields.push("username");
          } else if (bodyLower.includes('name="email"')) {
            fields.push("email");
          } else {
            fields.push("username");
          }

          // Password field
          fields.push("password");

          // CSRF token
          const csrfRequired =
            bodyLower.includes("csrf") ||
            bodyLower.includes("_token") ||
            bodyLower.includes("authenticity_token");

          // Check if browser is required (SPA indicators)
          const browserRequired =
            bodyLower.includes("__next_data__") ||
            bodyLower.includes("react") ||
            bodyLower.includes("vue") ||
            bodyLower.includes("angular");

          return {
            success: true,
            scheme: {
              method: "form",
              loginUrl: endpoint,
              fields,
              csrfRequired,
              browserRequired,
              browserReason: browserRequired
                ? "SPA framework detected"
                : undefined,
            },
          };
        }

        // Check for JSON API login patterns
        if (response.status === 401) {
          const contentType =
            headers["content-type"] || headers["Content-Type"];
          const isJson =
            contentType &&
            (Array.isArray(contentType)
              ? contentType[0]
              : contentType
            ).includes("json");

          if (isJson) {
            return {
              success: true,
              scheme: {
                method: "json",
                loginUrl: endpoint,
              },
            };
          }
        }

        // Default: couldn't determine scheme
        return {
          success: true,
          scheme: undefined,
        };
      } catch (error) {
        return {
          success: false,
          error: error instanceof Error ? error.message : String(error),
        };
      }
    },
  });

  // ===========================================================================
  // Tool: authenticate
  // ===========================================================================

  const authenticate = tool({
    description: `Authenticate with credentials to obtain session tokens.

Supports multiple methods:
- form_post: Traditional HTML form submission (application/x-www-form-urlencoded)
- json_post: JSON API login (application/json)
- basic_auth: HTTP Basic Authentication header
- bearer: Bearer token submission
- api_key: API key header

Returns session cookies/tokens on success.
Authentication state is automatically persisted for sharing with other agents.

NOTE: For SPAs or JavaScript-heavy apps, use browser tools instead (browser_navigate, browser_fill, browser_click, browser_evaluate).`,
    inputSchema: AuthenticateInputSchema,
    execute: async ({
      loginUrl,
      method,
      credentials,
      usernameField,
      passwordField,
      csrfToken,
      toolCallDescription,
    }): Promise<AuthenticateResult> => {
      logger?.info(
        `authenticate: ${loginUrl} method=${method} hasUsername=${!!credentials.username} hasPassword=${!!credentials.password} hasApiKey=${!!credentials.apiKey}`,
      );

      // Check if aborted
      if (abortSignal?.aborted) {
        return { success: false, message: "Request aborted", error: "Aborted" };
      }

      authStateManager.setStatus("authenticating");

      try {
        const headers: Record<string, string> = {};
        let body: string | undefined;

        switch (method) {
          case "form_post": {
            headers["Content-Type"] = "application/x-www-form-urlencoded";
            const params = new URLSearchParams();
            if (credentials.username) {
              params.set(usernameField, credentials.username);
            }
            if (credentials.password) {
              params.set(passwordField, credentials.password);
            }
            if (csrfToken) {
              params.set("_token", csrfToken);
            }
            if (credentials.customFields) {
              for (const [key, value] of Object.entries(
                credentials.customFields,
              )) {
                params.set(key, value);
              }
            }
            body = params.toString();
            break;
          }

          case "json_post": {
            headers["Content-Type"] = "application/json";
            const jsonBody: Record<string, string> = {};
            if (credentials.username) {
              jsonBody[usernameField] = credentials.username;
            }
            if (credentials.password) {
              jsonBody[passwordField] = credentials.password;
            }
            if (credentials.customFields) {
              Object.assign(jsonBody, credentials.customFields);
            }
            body = JSON.stringify(jsonBody);
            break;
          }

          case "basic_auth": {
            if (credentials.username && credentials.password) {
              const encoded = Buffer.from(
                `${credentials.username}:${credentials.password}`,
              ).toString("base64");
              headers["Authorization"] = `Basic ${encoded}`;
            }
            break;
          }

          case "bearer": {
            if (credentials.apiKey) {
              headers["Authorization"] = `Bearer ${credentials.apiKey}`;
            }
            break;
          }

          case "api_key": {
            if (credentials.apiKey) {
              headers["X-API-Key"] = credentials.apiKey;
            }
            break;
          }
        }

        const response = await makeRequest({
          url: loginUrl,
          method:
            method === "basic_auth" ||
            method === "bearer" ||
            method === "api_key"
              ? "GET"
              : "POST",
          headers,
          body,
          followRedirects: true,
          timeout: 30000,
        });

        if (!response.success) {
          authStateManager.markFailed(response.error);
          return {
            success: false,
            error: response.error,
            message: `HTTP request failed: ${response.error}`,
          };
        }

        // Check for auth barriers in response
        const barrier = detectAuthBarrier(response.body, response.status);
        if (barrier) {
          authStateManager.markFailed(barrier.details);
          return {
            success: false,
            barrier,
            message: `Authentication blocked: ${barrier.details}`,
          };
        }

        // Check for failed login indicators
        if (
          response.status === 401 ||
          response.status === 403 ||
          response.body.toLowerCase().includes("invalid credentials") ||
          response.body.toLowerCase().includes("incorrect password") ||
          response.body.toLowerCase().includes("login failed")
        ) {
          authStateManager.markFailed("Invalid credentials");
          return {
            success: false,
            message: "Authentication failed: Invalid credentials",
          };
        }

        // Extract tokens from response
        const tokens: AuthToken[] = [];

        // Extract cookies from Set-Cookie headers
        const cookieTokens = extractCookiesFromHeaders(
          response.headers as Record<string, string | string[]>,
        );
        tokens.push(...cookieTokens);

        // Check for JWT in response body
        try {
          const bodyJson = JSON.parse(response.body);
          if (bodyJson.token || bodyJson.access_token || bodyJson.accessToken) {
            const jwtValue =
              bodyJson.token || bodyJson.access_token || bodyJson.accessToken;
            const expiration = getJWTExpiration(jwtValue);
            tokens.push({
              type: "jwt",
              name: "Authorization",
              value: jwtValue,
              expiresAt: expiration || undefined,
            });
          }
          if (bodyJson.refresh_token || bodyJson.refreshToken) {
            tokens.push({
              type: "jwt",
              name: "refresh_token",
              value: bodyJson.refresh_token || bodyJson.refreshToken,
            });
          }
        } catch {
          // Not JSON, skip
        }

        // Check for auth header in response (some APIs return it)
        const authHeader =
          response.headers["authorization"] ||
          response.headers["Authorization"];
        if (authHeader) {
          const tokenValue = Array.isArray(authHeader)
            ? authHeader[0]
            : authHeader;
          if (tokenValue.startsWith("Bearer ")) {
            const jwtValue = tokenValue.substring(7);
            tokens.push({
              type: "bearer",
              name: "Authorization",
              value: jwtValue,
              expiresAt: getJWTExpiration(jwtValue) || undefined,
            });
          }
        }

        if (tokens.length === 0) {
          // Check if login was successful based on redirect or status
          if (response.status === 200 || response.status === 302) {
            // Might be successful but no tokens extracted
            authStateManager.setStatus("active");
            authStateManager.updateState({ authenticatedAt: Date.now() });
            return {
              success: true,
              tokens: [],
              authState: authStateManager.getState(),
              message:
                "Authentication appears successful but no tokens were extracted. Check cookies or response for session info.",
            };
          }
        }

        // Store all tokens
        for (const token of tokens) {
          authStateManager.addToken(token);
        }

        // Set auth endpoint info
        authStateManager.setAuthEndpoint({
          url: loginUrl,
          method:
            method === "json_post"
              ? "POST"
              : method === "form_post"
                ? "POST"
                : "GET",
          contentType: headers["Content-Type"] || "text/html",
          usernameField,
          passwordField,
        });

        return {
          success: true,
          tokens,
          authState: authStateManager.getState(),
          message: `Authentication successful. Obtained ${tokens.length} token(s).`,
        };
      } catch (error) {
        const errorMsg = error instanceof Error ? error.message : String(error);
        authStateManager.markFailed(errorMsg);
        return {
          success: false,
          error: errorMsg,
          message: `Authentication error: ${errorMsg}`,
        };
      }
    },
  });

  // ===========================================================================
  // Tool: document_auth_flow
  // ===========================================================================

  const document_auth_flow = tool({
    description: `Document discovered authentication flow for future reference.

CRITICAL: Call this AFTER successfully authenticating for the first time.
This allows future runs to skip discovery and authenticate immediately.

Documents:
- Login endpoint and method
- Field names (username, password, CSRF)
- Token extraction locations
- Browser flow requirements (if any)
- Rate limiting or other constraints

Persists to auth/auth-flow.json in session directory.`,
    inputSchema: DocumentAuthFlowInputSchema,
    execute: async (input): Promise<DocumentAuthFlowResult> => {
      logger?.info(`document_auth_flow: ${input.targetHost}`);

      try {
        authStateManager.saveFlow({
          targetHost: input.targetHost,
          documentedAt: Date.now(),
          scheme: input.scheme,
          fields: input.fields,
          csrfExtraction: input.csrfExtraction,
          tokenExtraction: input.tokenExtraction,
          browserFlow: input.browserFlow,
          notes: input.notes,
        });

        return {
          success: true,
          flowPath: "auth/auth-flow.json",
          message: `Auth flow documented for ${input.targetHost}. Future runs will skip discovery.`,
        };
      } catch (error) {
        return {
          success: false,
          flowPath: "",
          error: error instanceof Error ? error.message : String(error),
          message: "Failed to document auth flow",
        };
      }
    },
  });

  // ===========================================================================
  // Tool: validate_session
  // ===========================================================================

  const validate_session = tool({
    description: `Test if current authentication session is still valid.

Makes a request to a protected endpoint and checks response:
- 200/2xx: Session valid
- 401/403: Session expired or invalid
- 3xx redirect to login: Session expired

You can optionally provide tokens directly to test (bearerToken, cookies, customHeaders).
If provided tokens are valid, they will be stored in the auth state.

Updates session validity status in auth state.`,
    inputSchema: ValidateSessionInputSchema,
    execute: async ({
      testEndpoint,
      expectedStatus,
      toolCallDescription,
      providedTokens,
    }): Promise<ValidateSessionResult> => {
      logger?.info(
        `validate_session: ${testEndpoint} expectedStatus=${expectedStatus} hasProvidedTokens=${!!providedTokens}`,
      );

      if (abortSignal?.aborted) {
        return {
          success: false,
          valid: false,
          message: "Request aborted",
          error: "Aborted",
        };
      }

      try {
        // Build headers - use provided tokens if available, otherwise use stored auth state
        const headers: Record<string, string> = {};

        if (providedTokens) {
          // Use provided tokens directly
          if (providedTokens.bearerToken) {
            headers["Authorization"] = `Bearer ${providedTokens.bearerToken}`;
          }
          if (providedTokens.cookies) {
            headers["Cookie"] = providedTokens.cookies;
          }
          if (providedTokens.customHeaders) {
            Object.assign(headers, providedTokens.customHeaders);
          }
        } else {
          // Use stored auth state
          Object.assign(headers, authStateManager.getAuthHeaders());
          const cookies = authStateManager.getCookieString();
          if (cookies) {
            headers["Cookie"] = cookies;
          }
        }

        const response = await makeRequest({
          url: testEndpoint,
          method: "GET",
          headers,
          followRedirects: false,
          timeout: 30000,
        });

        if (!response.success) {
          return {
            success: false,
            valid: false,
            message: `Request failed: ${response.error}`,
            error: response.error,
          };
        }

        // Check for redirect to login
        if (
          response.status === 301 ||
          response.status === 302 ||
          response.status === 303
        ) {
          const location =
            response.headers["location"] || response.headers["Location"];
          if (location) {
            const locationStr = Array.isArray(location)
              ? location[0]
              : location;
            if (
              locationStr.includes("login") ||
              locationStr.includes("signin") ||
              locationStr.includes("auth")
            ) {
              if (!providedTokens) {
                authStateManager.setStatus("expired");
              }
              return {
                success: true,
                valid: false,
                statusCode: response.status,
                message: "Session expired - redirected to login page",
              };
            }
          }
        }

        // Check status code
        if (response.status === 401 || response.status === 403) {
          if (!providedTokens) {
            authStateManager.setStatus("expired");
          }
          return {
            success: true,
            valid: false,
            statusCode: response.status,
            message: `Session invalid - received ${response.status} ${response.statusText}`,
          };
        }

        if (response.status >= 200 && response.status < 300) {
          // Tokens are valid - store them if they were provided
          if (providedTokens) {
            // Store the provided tokens in auth state
            if (providedTokens.bearerToken) {
              const expiration = getJWTExpiration(providedTokens.bearerToken);
              authStateManager.addToken({
                type: "bearer",
                name: "Authorization",
                value: providedTokens.bearerToken,
                expiresAt: expiration || undefined,
              });
            }
            if (providedTokens.cookies) {
              // Parse and store cookies
              const cookieParts = providedTokens.cookies
                .split(";")
                .map((c) => c.trim());
              for (const cookie of cookieParts) {
                const [name, ...valueParts] = cookie.split("=");
                if (name && valueParts.length > 0) {
                  authStateManager.addToken({
                    type: "cookie",
                    name: name.trim(),
                    value: valueParts.join("=").trim(),
                  });
                }
              }
            }
            if (providedTokens.customHeaders) {
              // Store custom headers as tokens
              for (const [headerName, headerValue] of Object.entries(
                providedTokens.customHeaders,
              )) {
                authStateManager.addToken({
                  type: "api_key",
                  name: headerName,
                  value: headerValue,
                });
              }
            }
          }

          authStateManager.markValidated();
          return {
            success: true,
            valid: true,
            statusCode: response.status,
            message: providedTokens
              ? `Provided tokens are valid - received ${response.status} ${response.statusText}. Tokens stored for use.`
              : `Session valid - received ${response.status} ${response.statusText}`,
          };
        }

        return {
          success: true,
          valid: response.status === expectedStatus,
          statusCode: response.status,
          message: `Received status ${response.status}, expected ${expectedStatus}`,
        };
      } catch (error) {
        return {
          success: false,
          valid: false,
          message: `Validation error: ${error instanceof Error ? error.message : String(error)}`,
          error: error instanceof Error ? error.message : String(error),
        };
      }
    },
  });

  // ===========================================================================
  // Tool: refresh_session
  // ===========================================================================

  const refresh_session = tool({
    description: `Refresh an expired or expiring session.

Methods:
- Use refresh token endpoint (if available)
- Re-authenticate with original credentials

Automatically updates stored tokens on success.`,
    inputSchema: RefreshSessionInputSchema,
    execute: async ({
      refreshEndpoint,
      useOriginalCredentials,
      toolCallDescription,
    }): Promise<RefreshSessionResult> => {
      logger?.info(
        `refresh_session: refreshEndpoint=${refreshEndpoint} useOriginalCredentials=${useOriginalCredentials}`,
      );

      if (abortSignal?.aborted) {
        return { success: false, message: "Request aborted", error: "Aborted" };
      }

      try {
        // Try refresh token first
        const tokens = authStateManager.getTokens();
        const refreshToken = tokens.find(
          (t) => t.name === "refresh_token" || t.name === "refreshToken",
        );

        if (refreshEndpoint && refreshToken) {
          const response = await makeRequest({
            url: refreshEndpoint,
            method: "POST",
            headers: {
              "Content-Type": "application/json",
            },
            body: JSON.stringify({ refresh_token: refreshToken.value }),
            timeout: 30000,
          });

          if (response.success && response.status === 200) {
            try {
              const bodyJson = JSON.parse(response.body);
              const newTokens: AuthToken[] = [];

              if (
                bodyJson.token ||
                bodyJson.access_token ||
                bodyJson.accessToken
              ) {
                const jwtValue =
                  bodyJson.token ||
                  bodyJson.access_token ||
                  bodyJson.accessToken;
                newTokens.push({
                  type: "jwt",
                  name: "Authorization",
                  value: jwtValue,
                  expiresAt: getJWTExpiration(jwtValue) || undefined,
                });
              }

              if (bodyJson.refresh_token || bodyJson.refreshToken) {
                newTokens.push({
                  type: "jwt",
                  name: "refresh_token",
                  value: bodyJson.refresh_token || bodyJson.refreshToken,
                });
              }

              for (const token of newTokens) {
                authStateManager.addToken(token);
              }

              return {
                success: true,
                newTokens,
                message: `Session refreshed. Obtained ${newTokens.length} new token(s).`,
              };
            } catch {
              // Parse failed
            }
          }
        }

        // Fallback: re-authenticate with original credentials
        if (useOriginalCredentials) {
          const state = authStateManager.getState();
          if (state.authEndpoint) {
            return {
              success: false,
              message:
                "Refresh token failed. Use authenticate tool to re-authenticate with original credentials.",
              error: "Refresh failed, re-authentication required",
            };
          }
        }

        return {
          success: false,
          message:
            "Unable to refresh session. No refresh endpoint or original credentials available.",
          error: "No refresh method available",
        };
      } catch (error) {
        return {
          success: false,
          message: `Refresh error: ${error instanceof Error ? error.message : String(error)}`,
          error: error instanceof Error ? error.message : String(error),
        };
      }
    },
  });

  // ===========================================================================
  // Tool: get_auth_state
  // ===========================================================================

  const get_auth_state = tool({
    description: `Get current authentication state.

Returns:
- Current tokens (cookies, JWT, etc.)
- Session validity status
- Expiration times
- Discovered scopes/roles
- Headers to include in requests

Use this to check authentication status before making requests.`,
    inputSchema: GetAuthStateInputSchema,
    execute: async ({ toolCallDescription }): Promise<GetAuthStateResult> => {
      logger?.info("get_auth_state");

      const state = authStateManager.getState();
      const headers = authStateManager.getAuthHeaders();
      const cookies = authStateManager.getCookieString();
      const isValid =
        !authStateManager.isExpired() && state.status === "active";

      return {
        success: true,
        state,
        headers,
        cookies,
        isValid,
        message: `Auth state: ${state.status}. ${state.tokens.length} active token(s). Valid: ${isValid}`,
      };
    },
  });

  // ===========================================================================
  // Tool: store_browser_cookies
  // ===========================================================================

  const store_browser_cookies = tool({
    description: `Store cookies and tokens extracted from browser into the auth state.

CRITICAL: Call this AFTER browser_get_cookies and browser_evaluate to save auth credentials.

This tool stores:
- Cookies from browser_get_cookies (for Cookie header)
- Bearer token from localStorage/sessionStorage (for Authorization header)

The stored credentials will be available via exportedCookies and exportedHeaders for HTTP requests.`,
    inputSchema: z.object({
      cookies: z
        .array(
          z.object({
            name: z.string(),
            value: z.string(),
            domain: z.string().optional(),
            path: z.string().optional(),
            httpOnly: z.boolean().optional(),
            secure: z.boolean().optional(),
          }),
        )
        .optional()
        .describe("Cookies array from browser_get_cookies"),
      bearerToken: z
        .string()
        .optional()
        .describe(
          "Bearer/JWT token from localStorage or sessionStorage (e.g., from browser_evaluate extracting localStorage.getItem('token'))",
        ),
      accessToken: z
        .string()
        .optional()
        .describe("Access token if different from bearer token"),
      toolCallDescription: z
        .string()
        .describe("Why you are storing these credentials"),
    }),
    execute: async ({
      cookies,
      bearerToken,
      accessToken,
      toolCallDescription,
    }): Promise<{
      success: boolean;
      message: string;
      tokenCount: number;
      cookieHeader?: string;
      authHeader?: string;
    }> => {
      logger?.info(
        `store_browser_cookies: Storing ${cookies?.length || 0} cookies, bearer: ${!!bearerToken}`,
      );

      try {
        let storedCount = 0;

        // Store cookies
        if (cookies && cookies.length > 0) {
          for (const cookie of cookies) {
            authStateManager.addToken({
              type: "cookie",
              name: cookie.name,
              value: cookie.value,
              expiresAt: undefined,
            });
            storedCount++;
          }
        }

        // Store bearer token
        if (bearerToken) {
          authStateManager.addToken({
            type: "bearer",
            name: "Authorization",
            value: bearerToken,
            expiresAt: undefined,
          });
          storedCount++;
        }

        // Store access token (if different)
        if (accessToken && accessToken !== bearerToken) {
          authStateManager.addToken({
            type: "bearer",
            name: "access_token",
            value: accessToken,
            expiresAt: undefined,
          });
          storedCount++;
        }

        // Mark auth as active
        authStateManager.setStatus("active");
        authStateManager.updateState({ authenticatedAt: Date.now() });

        // Build response with ready-to-use headers
        const cookieHeader =
          cookies?.map((c) => `${c.name}=${c.value}`).join("; ") || "";
        const authHeader = bearerToken ? `Bearer ${bearerToken}` : undefined;

        return {
          success: true,
          message: `Stored ${storedCount} credential(s). Auth state is now active.${authHeader ? " Bearer token available." : ""}${cookieHeader ? " Cookies available." : ""}`,
          tokenCount: storedCount,
          cookieHeader: cookieHeader || undefined,
          authHeader,
        };
      } catch (error) {
        const errorMsg = error instanceof Error ? error.message : String(error);
        return {
          success: false,
          message: `Failed to store credentials: ${errorMsg}`,
          tokenCount: 0,
        };
      }
    },
  });

  // ===========================================================================
  // Tool: export_auth_for_agent
  // ===========================================================================

  const export_auth_for_agent = tool({
    description: `Export authentication state for use by other agents.

Creates exportable auth info including:
- HTTP headers to include in requests
- Cookies string
- Auth instructions for POC scripts

Formats:
- headers: Returns headers dict
- curl: Returns curl flags (-H, -b)
- poc_script: Returns bash script snippet

This allows other agents (vulnerability testers) to make authenticated requests.`,
    inputSchema: ExportAuthForAgentInputSchema,
    execute: async ({
      format,
      toolCallDescription,
    }): Promise<ExportAuthForAgentResult> => {
      logger?.info(`export_auth_for_agent: format=${format}`);

      const authInfo = authStateManager.exportForAgent();

      switch (format) {
        case "headers":
          return {
            success: true,
            format,
            headers: authStateManager.getAuthHeaders(),
            authenticationInfo: authInfo,
            message: "Auth exported as headers dict",
          };

        case "curl":
          return {
            success: true,
            format,
            curlFlags: authStateManager.exportAsCurlFlags(),
            authenticationInfo: authInfo,
            message: "Auth exported as curl flags",
          };

        case "poc_script":
          return {
            success: true,
            format,
            pocScript: authStateManager.exportAsPocScript(),
            authenticationInfo: authInfo,
            message: "Auth exported as POC script snippet",
          };

        default:
          return {
            success: true,
            format: "headers",
            headers: authStateManager.getAuthHeaders(),
            authenticationInfo: authInfo,
            message: "Auth exported as headers dict (default)",
          };
      }
    },
  });

  // ===========================================================================
  // Tool: probe_auth_endpoints
  // ===========================================================================

  // Common auth endpoint patterns to probe
  const AUTH_ENDPOINT_PATTERNS = {
    login: [
      "/api/login",
      "/api/auth/login",
      "/api/v1/login",
      "/api/v1/auth/login",
      "/api/signin",
      "/api/auth/signin",
      "/api/authenticate",
      "/auth/login",
      "/auth/signin",
      "/login",
      "/signin",
    ],
    token: [
      "/api/token",
      "/api/auth/token",
      "/api/oauth/token",
      "/oauth/token",
      "/token",
      "/api/session",
    ],
    user: [
      "/api/me",
      "/api/user",
      "/api/profile",
      "/api/users/me",
      "/me",
      "/user",
      "/api/account",
      "/account",
    ],
    refresh: [
      "/api/refresh",
      "/api/auth/refresh",
      "/api/token/refresh",
      "/refresh",
    ],
    // Protected resources that may reveal auth requirements (401/403)
    protected: [
      "/api/data",
      "/api/protected",
      "/api/private",
      "/api/secure",
      "/data",
      "/protected",
      "/private",
      "/secure",
      "/api/v1/data",
      "/api/v1/protected",
      "/admin",
      "/api/admin",
      "/dashboard",
      "/api/dashboard",
    ],
  };

  const probe_auth_endpoints = tool({
    description: `Probe common authentication endpoint patterns to discover where to authenticate.

Use this when:
- Target endpoint returns 404 or no clear auth scheme detected
- Need to find login/token endpoints for JSON APIs
- detect_auth_scheme didn't find form or auth headers

Probes ~40 common paths with both GET and POST methods:
- Login endpoints: /api/login, /api/auth/login, /login, etc.
- Token endpoints: /api/token, /oauth/token, etc.
- User endpoints: /api/me, /api/user, etc.
- Protected resources: /api/data, /api/protected, /admin, etc.

Also detects HTTP Basic Auth via WWW-Authenticate header.
Returns discovered endpoints and recommended login approach.`,
    inputSchema: ProbeAuthEndpointsInputSchema,
    execute: async ({
      baseUrl,
      toolCallDescription,
    }): Promise<ProbeAuthEndpointsResult> => {
      logger?.info(`probe_auth_endpoints: ${baseUrl}`);

      if (abortSignal?.aborted) {
        return { success: false, endpoints: [], message: "Request aborted" };
      }

      const discoveredEndpoints: ProbeAuthEndpointsResult["endpoints"] = [];
      const allPatterns = [
        ...AUTH_ENDPOINT_PATTERNS.login.map((p) => ({
          path: p,
          purpose: "login" as const,
        })),
        ...AUTH_ENDPOINT_PATTERNS.token.map((p) => ({
          path: p,
          purpose: "token" as const,
        })),
        ...AUTH_ENDPOINT_PATTERNS.user.map((p) => ({
          path: p,
          purpose: "user" as const,
        })),
        ...AUTH_ENDPOINT_PATTERNS.refresh.map((p) => ({
          path: p,
          purpose: "refresh" as const,
        })),
        ...AUTH_ENDPOINT_PATTERNS.protected.map((p) => ({
          path: p,
          purpose: "unknown" as const,
        })),
      ];

      for (const { path, purpose } of allPatterns) {
        if (abortSignal?.aborted) break;

        const url = baseUrl.replace(/\/$/, "") + path;
        const methods: string[] = [];
        const authIndicators: string[] = [];

        // Try GET
        try {
          const getResult = await makeRequest({
            url,
            method: "GET",
            timeout: 5000,
          });
          if (getResult.status !== 404 && getResult.status !== 0) {
            methods.push("GET");
            if (getResult.status === 401)
              authIndicators.push("requires auth (401)");
            if (getResult.status === 200)
              authIndicators.push("accessible (200)");
            if (getResult.status === 403)
              authIndicators.push("forbidden (403)");

            // Check WWW-Authenticate header for Basic/Bearer auth
            const wwwAuth =
              getResult.headers["www-authenticate"] ||
              getResult.headers["WWW-Authenticate"];
            if (wwwAuth) {
              const authHeader = Array.isArray(wwwAuth) ? wwwAuth[0] : wwwAuth;
              if (authHeader.toLowerCase().includes("basic")) {
                authIndicators.push("HTTP Basic Auth");
              } else if (authHeader.toLowerCase().includes("bearer")) {
                authIndicators.push("Bearer token required");
              }
            }
          }
        } catch {
          // Ignore errors for individual endpoints
        }

        // Try POST with empty JSON body
        try {
          const postResult = await makeRequest({
            url,
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: "{}",
            timeout: 5000,
          });
          if (postResult.status !== 404 && postResult.status !== 0) {
            methods.push("POST");
            if (postResult.status === 400)
              authIndicators.push("expects body (400)");
            if (postResult.status === 401)
              authIndicators.push("invalid credentials (401)");
            if (postResult.status === 200)
              authIndicators.push("POST accessible (200)");
            // Check for JSON response with auth-related fields
            if (
              postResult.body.includes("username") ||
              postResult.body.includes("password")
            ) {
              authIndicators.push("expects credentials");
            }
            if (
              postResult.body.includes("token") ||
              postResult.body.includes("jwt")
            ) {
              authIndicators.push("returns tokens");
            }
          }
        } catch {
          // Ignore errors for individual endpoints
        }

        if (methods.length > 0) {
          discoveredEndpoints.push({
            path,
            methods,
            authIndicators,
            likelyPurpose: purpose,
          });
        }
      }

      // Check for HTTP Basic Auth endpoints
      const basicAuthEndpoint = discoveredEndpoints.find((e) =>
        e.authIndicators.includes("HTTP Basic Auth"),
      );

      // Find recommended login endpoint - prefer POST endpoints with auth indicators
      const loginEndpoint =
        discoveredEndpoints.find(
          (e) =>
            e.likelyPurpose === "login" &&
            e.methods.includes("POST") &&
            (e.authIndicators.includes("expects body (400)") ||
              e.authIndicators.includes("invalid credentials (401)") ||
              e.authIndicators.includes("expects credentials")),
        ) ||
        discoveredEndpoints.find(
          (e) => e.likelyPurpose === "login" && e.methods.includes("POST"),
        );

      logger?.info(
        `probe_auth_endpoints: found ${discoveredEndpoints.length} endpoints`,
      );

      // Build result message
      let message = "";
      if (discoveredEndpoints.length === 0) {
        message = "No auth endpoints found at common paths";
      } else if (basicAuthEndpoint) {
        message = `Found HTTP Basic Auth protected endpoint: ${basicAuthEndpoint.path}. Use Authorization: Basic base64(username:password) header.`;
      } else if (loginEndpoint) {
        message = `Found ${discoveredEndpoints.length} potential auth endpoints. Recommended: POST ${loginEndpoint.path}`;
      } else {
        message = `Found ${discoveredEndpoints.length} potential auth endpoints`;
      }

      return {
        success: true,
        endpoints: discoveredEndpoints,
        recommendedLoginEndpoint:
          basicAuthEndpoint?.path || loginEndpoint?.path,
        recommendedMethod: basicAuthEndpoint
          ? "GET (with Basic Auth header)"
          : loginEndpoint
            ? "POST"
            : undefined,
        message,
      };
    },
  });

  // ===========================================================================
  // Tool: probe_registration
  // ===========================================================================

  // Common registration endpoint patterns to probe
  const REGISTRATION_ENDPOINT_PATTERNS = [
    "/register",
    "/signup",
    "/sign-up",
    "/create-account",
    "/join",
    "/api/register",
    "/api/signup",
    "/api/sign-up",
    "/api/users/register",
    "/api/v1/register",
    "/api/v1/signup",
    "/api/v1/users",
    "/auth/register",
    "/auth/signup",
    "/api/auth/register",
    "/api/auth/signup",
    "/account/register",
    "/account/signup",
    "/account/create",
    "/users/new",
    "/user/create",
    "/membership/register",
  ];

  const probe_registration = tool({
    description: `Probe for registration/signup functionality.

Use when:
- No credentials provided and need to determine if self-registration is possible
- Discovering available registration endpoints

Checks for:
- Registration endpoints (/register, /signup, /create-account, etc.)
- Open vs. invite-only registration
- Required fields (email, phone verification, captcha)
- Admin approval requirements

Returns whether registration is possible and what barriers exist.`,
    inputSchema: ProbeRegistrationInputSchema,
    execute: async ({
      baseUrl,
      toolCallDescription,
    }): Promise<ProbeRegistrationResult> => {
      logger?.info(`probe_registration: ${baseUrl}`);

      if (abortSignal?.aborted) {
        return {
          success: false,
          canRegister: false,
          barriers: [],
          requiredFields: [],
          message: "Request aborted",
          error: "Aborted",
        };
      }

      let registrationUrl: string | undefined;
      const barriers: RegistrationBarrier[] = [];
      const requiredFields: string[] = [];
      const optionalFields: string[] = [];
      let notes = "";

      // Probe each registration endpoint
      for (const path of REGISTRATION_ENDPOINT_PATTERNS) {
        if (abortSignal?.aborted) break;

        const url = baseUrl.replace(/\/$/, "") + path;

        try {
          // Try GET first to see if it's a registration page/form
          const getResult = await makeRequest({
            url,
            method: "GET",
            timeout: 5000,
          });

          if (getResult.status === 200) {
            registrationUrl = url;
            const bodyLower = getResult.body.toLowerCase();

            // Detect barriers
            if (
              bodyLower.includes("invite") ||
              bodyLower.includes("invitation")
            ) {
              barriers.push("invite_code");
              notes += "Requires invitation code. ";
            }
            if (
              bodyLower.includes("admin approval") ||
              bodyLower.includes("pending approval")
            ) {
              barriers.push("admin_approval");
              notes += "Requires admin approval after registration. ";
            }
            if (
              bodyLower.includes("captcha") ||
              bodyLower.includes("recaptcha") ||
              bodyLower.includes("hcaptcha")
            ) {
              barriers.push("captcha");
              notes += "CAPTCHA required. ";
            }
            if (
              bodyLower.includes("verify your email") ||
              bodyLower.includes("email verification")
            ) {
              barriers.push("email_verification");
              notes += "Email verification required. ";
            }
            if (
              bodyLower.includes("phone verification") ||
              bodyLower.includes("sms verification")
            ) {
              barriers.push("phone_verification");
              notes += "Phone verification required. ";
            }

            // Detect required fields from form
            if (
              bodyLower.includes('name="email"') ||
              bodyLower.includes('name="user_email"') ||
              bodyLower.includes('"email"')
            ) {
              requiredFields.push("email");
            }
            if (
              bodyLower.includes('name="username"') ||
              bodyLower.includes('name="user"') ||
              bodyLower.includes('"username"')
            ) {
              requiredFields.push("username");
            }
            if (
              bodyLower.includes('name="password"') ||
              bodyLower.includes('"password"')
            ) {
              requiredFields.push("password");
            }
            if (
              bodyLower.includes('name="password_confirmation"') ||
              bodyLower.includes('name="confirm_password"') ||
              bodyLower.includes('"confirmPassword"')
            ) {
              requiredFields.push("password_confirmation");
            }
            if (
              bodyLower.includes('name="name"') ||
              bodyLower.includes('name="full_name"') ||
              bodyLower.includes('"name"')
            ) {
              optionalFields.push("name");
            }
            if (
              bodyLower.includes('name="phone"') ||
              bodyLower.includes('"phone"')
            ) {
              optionalFields.push("phone");
            }

            // If we found a registration page, stop probing
            break;
          }

          // Try POST to see if it's a JSON API registration endpoint
          const postResult = await makeRequest({
            url,
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: "{}",
            timeout: 5000,
          });

          // 400 or 422 often means the endpoint exists but needs proper data
          if (postResult.status === 400 || postResult.status === 422) {
            registrationUrl = url;
            const bodyLower = postResult.body.toLowerCase();

            // Try to detect required fields from error message
            if (bodyLower.includes("email") || bodyLower.includes('"email"')) {
              requiredFields.push("email");
            }
            if (
              bodyLower.includes("username") ||
              bodyLower.includes('"username"')
            ) {
              requiredFields.push("username");
            }
            if (
              bodyLower.includes("password") ||
              bodyLower.includes('"password"')
            ) {
              requiredFields.push("password");
            }

            notes = "JSON API registration endpoint. ";
            break;
          }
        } catch {
          // Ignore errors for individual endpoints
        }
      }

      // Determine if registration is possible
      const canRegister = !!registrationUrl && !barriers.includes("closed");

      // Ensure basic fields if nothing detected
      if (registrationUrl && requiredFields.length === 0) {
        requiredFields.push("email", "password");
      }

      const message = registrationUrl
        ? canRegister
          ? `Registration available at ${registrationUrl}. Required fields: ${requiredFields.join(", ")}${barriers.length > 0 ? `. Barriers: ${barriers.join(", ")}` : ""}`
          : `Registration endpoint found at ${registrationUrl} but blocked by: ${barriers.join(", ")}`
        : "No registration endpoint found at common paths";

      logger?.info(
        `probe_registration: canRegister=${canRegister}, url=${registrationUrl}, barriers=${barriers.join(",")}`,
      );

      return {
        success: true,
        canRegister,
        registrationUrl,
        barriers,
        requiredFields,
        optionalFields: optionalFields.length > 0 ? optionalFields : undefined,
        notes: notes || undefined,
        message,
      };
    },
  });

  // ===========================================================================
  // Tool: attempt_registration
  // ===========================================================================

  const attempt_registration = tool({
    description: `Attempt to create a test account via self-registration.

Only use when:
- probe_registration showed open registration
- No credentials were provided by the user

Creates account with provided field values.
Generate realistic test credentials before calling:
- email: Use a test email like test-{timestamp}@example.com
- username: Use something like testuser-{timestamp}
- password: Use a strong password like Test123!@#

Returns the credentials if successful, or barriers if blocked.`,
    inputSchema: AttemptRegistrationInputSchema,
    execute: async ({
      registrationUrl,
      requiredFields,
      toolCallDescription,
    }): Promise<AttemptRegistrationResult> => {
      logger?.info(
        `attempt_registration: ${registrationUrl} fields=${Object.keys(requiredFields).join(",")}`,
      );

      if (abortSignal?.aborted) {
        return {
          success: false,
          message: "Request aborted",
          error: "Aborted",
        };
      }

      try {
        // Determine if it's a JSON API or form-based registration
        const getResult = await makeRequest({
          url: registrationUrl,
          method: "GET",
          timeout: 5000,
        });
        const isJsonApi =
          getResult.status === 405 ||
          getResult.status === 404 ||
          !getResult.body.includes("<html");

        let response: HttpRequestResult;

        if (isJsonApi) {
          // JSON API registration
          response = await makeRequest({
            url: registrationUrl,
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(requiredFields),
            timeout: 30000,
          });
        } else {
          // Form-based registration
          const params = new URLSearchParams();
          for (const [key, value] of Object.entries(requiredFields)) {
            params.set(key, value);
          }

          response = await makeRequest({
            url: registrationUrl,
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: params.toString(),
            followRedirects: true,
            timeout: 30000,
          });
        }

        if (!response.success) {
          return {
            success: false,
            message: `Registration request failed: ${response.error}`,
            error: response.error,
          };
        }

        const bodyLower = response.body.toLowerCase();
        const barriers: RegistrationBarrier[] = [];

        // Check for barriers in response
        if (bodyLower.includes("captcha") || bodyLower.includes("recaptcha")) {
          barriers.push("captcha");
        }
        if (
          bodyLower.includes("invite") ||
          bodyLower.includes("invitation code")
        ) {
          barriers.push("invite_code");
        }
        if (
          bodyLower.includes("admin approval") ||
          bodyLower.includes("pending approval")
        ) {
          barriers.push("admin_approval");
        }
        if (
          bodyLower.includes("verify your email") ||
          bodyLower.includes("check your email")
        ) {
          barriers.push("email_verification");
        }

        // Check for success indicators
        const isSuccess =
          response.status === 200 ||
          response.status === 201 ||
          response.status === 302 ||
          bodyLower.includes("success") ||
          bodyLower.includes("account created") ||
          bodyLower.includes("welcome") ||
          bodyLower.includes("registration complete") ||
          bodyLower.includes("thank you for registering");

        // Check for failure indicators
        const isFailure =
          response.status === 400 ||
          response.status === 422 ||
          response.status === 409 ||
          bodyLower.includes("already exists") ||
          bodyLower.includes("already taken") ||
          bodyLower.includes("error") ||
          bodyLower.includes("invalid");

        if (isSuccess && barriers.length === 0) {
          // Extract credentials from the fields provided
          const credentials = {
            username: requiredFields.username || requiredFields.email || "",
            password: requiredFields.password || "",
            email: requiredFields.email,
          };

          logger?.info(
            `attempt_registration: SUCCESS - created account ${credentials.username}`,
          );

          return {
            success: true,
            credentials,
            statusCode: response.status,
            message: `Registration successful! Account created with username: ${credentials.username}`,
          };
        }

        if (barriers.length > 0) {
          logger?.info(
            `attempt_registration: BLOCKED by ${barriers.join(", ")}`,
          );
          return {
            success: false,
            barriers,
            statusCode: response.status,
            message: `Registration blocked by: ${barriers.join(", ")}`,
          };
        }

        if (isFailure) {
          // Try to extract error message
          let errorMsg = "Registration failed";
          try {
            const jsonBody = JSON.parse(response.body);
            if (jsonBody.error) errorMsg = jsonBody.error;
            if (jsonBody.message) errorMsg = jsonBody.message;
            if (jsonBody.errors) errorMsg = JSON.stringify(jsonBody.errors);
          } catch {
            // Not JSON, try to find error in HTML
            const errorMatch = response.body.match(
              /<div[^>]*class="[^"]*error[^"]*"[^>]*>([^<]+)<\/div>/i,
            );
            if (errorMatch) errorMsg = errorMatch[1];
          }

          logger?.info(`attempt_registration: FAILED - ${errorMsg}`);
          return {
            success: false,
            statusCode: response.status,
            message: errorMsg,
            error: errorMsg,
          };
        }

        // Unclear result
        return {
          success: false,
          statusCode: response.status,
          message: `Registration result unclear. Status: ${response.status}. Manual verification may be needed.`,
        };
      } catch (error) {
        return {
          success: false,
          message: `Registration error: ${error instanceof Error ? error.message : String(error)}`,
          error: error instanceof Error ? error.message : String(error),
        };
      }
    },
  });

  // ===========================================================================
  // Return All Tools
  // ===========================================================================

  return {
    load_auth_flow,
    detect_auth_scheme,
    authenticate,
    document_auth_flow,
    validate_session,
    refresh_session,
    get_auth_state,
    store_browser_cookies,
    export_auth_for_agent,
    probe_auth_endpoints,
    probe_registration,
    attempt_registration,
  };
}

export type AuthenticationTools = ReturnType<typeof createAuthenticationTools>;
