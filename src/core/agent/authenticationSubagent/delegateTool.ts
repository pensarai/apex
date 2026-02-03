/**
 * Shared factory for creating the delegate_to_auth_subagent tool.
 * Used by both attackSurfaceAgent and subagents (init/attack agents).
 */

import { tool as aiTool, type Tool } from "ai";
import { z } from "zod";
import { join } from "path";
import { writeFileSync, existsSync, readFileSync } from "fs";
import type { Session } from "../../session";
import type { AIModel } from "../../ai";
import { runAuthenticationSubagent, type AuthCredentials } from "./index";

/**
 * Merge session-level credentials with explicitly passed credentials.
 * Explicit values take precedence over session defaults.
 */
export function mergeAuthCredentials(
  sessionCreds: Session.AuthCredentials | undefined,
  explicit: {
    username?: string;
    password?: string;
    apiKey?: string;
    loginUrl?: string;
    tokens?: {
      bearerToken?: string;
      cookies?: string;
      sessionToken?: string;
      customHeaders?: Record<string, string>;
    };
  }
): AuthCredentials | undefined {
  const hasExplicit =
    explicit.username ||
    explicit.password ||
    explicit.apiKey ||
    explicit.tokens;
  const hasSession =
    sessionCreds &&
    (sessionCreds.username ||
      sessionCreds.password ||
      sessionCreds.apiKey ||
      sessionCreds.tokens);

  if (!hasExplicit && !hasSession) {
    return undefined;
  }

  return {
    // Session-level defaults
    username: sessionCreds?.username,
    password: sessionCreds?.password,
    apiKey: sessionCreds?.apiKey,
    loginUrl: sessionCreds?.loginUrl,
    tokens: sessionCreds?.tokens
      ? {
          bearerToken: sessionCreds.tokens.bearerToken,
          cookies: sessionCreds.tokens.cookies,
          sessionToken: sessionCreds.tokens.sessionToken,
          customHeaders: sessionCreds.tokens.customHeaders,
        }
      : undefined,
    // Explicit overrides (take precedence)
    ...(explicit.username && { username: explicit.username }),
    ...(explicit.password && { password: explicit.password }),
    ...(explicit.apiKey && { apiKey: explicit.apiKey }),
    ...(explicit.loginUrl && { loginUrl: explicit.loginUrl }),
    ...(explicit.tokens && {
      tokens: {
        bearerToken: explicit.tokens.bearerToken,
        cookies: explicit.tokens.cookies,
        sessionToken: explicit.tokens.sessionToken,
        customHeaders: explicit.tokens.customHeaders,
      },
    }),
  };
}

export interface CreateDelegateAuthToolOpts {
  session: Session.SessionInfo;
  model: AIModel;
  abortSignal?: AbortSignal;
}

/**
 * Helper to define tools with proper typing.
 * Works around Zod v4 / AI SDK v6 type compatibility issues.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function tool<T extends z.ZodType, R>(config: {
  name?: string;
  description: string;
  inputSchema: T;
  execute: (input: z.infer<T>) => Promise<R>;
}): Tool<z.infer<T>, R> {
  return aiTool(config as any) as Tool<z.infer<T>, R>;
}

/**
 * Factory function to create the delegate_to_auth_subagent tool.
 * This tool can be used by any agent that needs to delegate authentication
 * to the specialized auth subagent.
 */
export function createDelegateToAuthSubagentTool(opts: CreateDelegateAuthToolOpts) {
  const { session, model, abortSignal } = opts;

  const delegate_to_auth_subagent = tool({
    name: 'delegate_to_auth_subagent',
    description: `Delegate authentication to the specialized auth subagent.

Use when:
- Complex auth flow detected (OAuth, SAML, CSRF tokens)
- Browser-based login required (SPA, JavaScript forms)
- Built-in authenticate_and_maintain_session tool failed
- MFA or CAPTCHA barrier detected
- Need to verify pre-existing tokens (bearer, API key, cookies)
- No credentials provided (will probe for open registration)

Credential options (pass what you have):
- username/password: For form or JSON login
- apiKey: For API key authentication
- tokens.bearerToken: For Bearer/JWT token verification
- tokens.cookies: For cookie-based session verification
- tokens.customHeaders: For custom header auth (X-API-Key, X-Auth-Token, etc.)

The auth subagent will:
1. Handle the authentication flow (HTTP or browser-based)
2. Document the process for re-auth
3. Return cookies/headers for authenticated requests
4. Verify tokens against protected endpoints if provided

IMPORTANT: Pass protectedEndpoints in authHints!
When you discover endpoints that return 401/403 during recon, pass them to the auth subagent
so it knows which endpoints to test tokens against (instead of guessing common paths).

Session credentials may be pre-configured. Call delegate_to_auth_subagent
without explicit credentials to use session defaults.`,
    inputSchema: z.object({
      target: z.string().describe('Target URL requiring authentication'),
      loginUrl: z.string().optional().describe('Discovered login URL if known'),
      username: z.string().optional().describe('Username if available'),
      password: z.string().optional().describe('Password if available'),
      apiKey: z.string().optional().describe('API key if available'),
      tokens: z
        .object({
          bearerToken: z
            .string()
            .optional()
            .describe('Bearer/JWT token to verify'),
          cookies: z.string().optional().describe('Cookie string to verify'),
          sessionToken: z
            .string()
            .optional()
            .describe('Session ID or token value'),
          customHeaders: z
            .record(z.string(), z.string())
            .optional()
            .describe(
              'Custom headers to verify (e.g., X-API-Key, X-Auth-Token)'
            ),
        })
        .optional()
        .describe(
          'Pre-existing tokens to verify (skips login flow, just validates these work)'
        ),
      authHints: z
        .object({
          authScheme: z
            .string()
            .optional()
            .describe('Detected auth scheme (form, json, oauth, etc.)'),
          csrfRequired: z
            .boolean()
            .optional()
            .describe('Whether CSRF protection was detected'),
          browserRequired: z
            .boolean()
            .optional()
            .describe('Whether browser automation is needed'),
          protectedEndpoints: z
            .array(z.string())
            .optional()
            .describe(
              'Protected endpoints discovered during recon that require auth (for token verification)'
            ),
        })
        .optional()
        .describe('Hints about the auth flow from discovery'),
      reason: z.string().describe('Why you are delegating to auth subagent'),
      toolCallDescription: z
        .string()
        .optional()
        .describe('A concise description of what this tool call is doing'),
    }),
    execute: async ({
      target,
      loginUrl,
      username,
      password,
      apiKey,
      tokens,
      authHints,
      reason,
    }) => {
      try {
        console.log(`\n🔐 Delegating to authentication subagent...`);
        console.log(`   Target: ${target}`);
        console.log(`   Reason: ${reason}`);

        // Log explicit credentials
        if (username) console.log(`   Username: ${username}`);
        if (apiKey) console.log(`   API Key: [PROVIDED]`);
        if (tokens?.bearerToken) console.log(`   Bearer Token: [PROVIDED]`);
        if (tokens?.cookies) console.log(`   Cookies: [PROVIDED]`);
        if (tokens?.customHeaders)
          console.log(
            `   Custom Headers: ${Object.keys(tokens.customHeaders).join(', ')}`
          );

        // Log session-level credentials that will be inherited
        const sessionCreds = session.config?.authCredentials;
        if (sessionCreds && !username && !apiKey && !tokens) {
          console.log(`   [Inheriting session credentials]`);
          if (sessionCreds.username)
            console.log(`   Session Username: ${sessionCreds.username}`);
          if (sessionCreds.apiKey)
            console.log(`   Session API Key: [PROVIDED]`);
          if (sessionCreds.tokens?.bearerToken)
            console.log(`   Session Bearer Token: [PROVIDED]`);
          if (sessionCreds.tokens?.cookies)
            console.log(`   Session Cookies: [PROVIDED]`);
          if (sessionCreds.tokens?.customHeaders)
            console.log(
              `   Session Custom Headers: ${Object.keys(sessionCreds.tokens.customHeaders).join(', ')}`
            );
        }
        if (authHints) {
          console.log(`   Auth Scheme: ${authHints.authScheme || 'unknown'}`);
          console.log(`   CSRF Required: ${authHints.csrfRequired || false}`);
          console.log(
            `   Browser Required: ${authHints.browserRequired || false}`
          );
          if (authHints.protectedEndpoints?.length) {
            console.log(
              `   Protected Endpoints: ${authHints.protectedEndpoints.join(', ')}`
            );
          }
        }

        // Merge session-level credentials with explicitly passed ones
        const credentials = mergeAuthCredentials(sessionCreds, {
          username,
          password,
          apiKey,
          loginUrl,
          tokens,
        });

        const result = await runAuthenticationSubagent({
          input: {
            target,
            session,
            credentials,
            authFlowHints: authHints
              ? {
                  loginEndpoints: loginUrl ? [loginUrl] : undefined,
                  protectedEndpoints: authHints.protectedEndpoints,
                  authScheme: authHints.authScheme as any,
                  csrfRequired: authHints.csrfRequired,
                }
              : undefined,
          },
          model,
          enableBrowserTools: authHints?.browserRequired !== false,
          abortSignal,
        });

        if (result.success) {
          // Save session info for other tools to use
          const sessionInfoPath = join(session.rootPath, 'session-info.json');
          const sessionInfo = {
            authenticated: true,
            username: username || sessionCreds?.username || 'via_subagent',
            sessionCookie: result.exportedCookies || '',
            headers: result.exportedHeaders || {},
            loginUrl: target,
            timestamp: new Date().toISOString(),
            delegatedToSubagent: true,
          };
          writeFileSync(sessionInfoPath, JSON.stringify(sessionInfo, null, 2));
        }

        // Build usage instructions for the calling agent
        const hasHeaders =
          result.exportedHeaders &&
          Object.keys(result.exportedHeaders).length > 0;
        const hasCookies =
          result.exportedCookies && result.exportedCookies.length > 0;

        let usageInstructions = '';
        if (result.success && (hasHeaders || hasCookies)) {
          usageInstructions =
            '\n\nTo make authenticated requests, use the returned values:\n';
          if (hasCookies) {
            usageInstructions += `- Pass sessionCookie to tools that accept it\n`;
            usageInstructions += `- For http_request, include Cookie header: "${result.exportedCookies}"\n`;
          }
          if (hasHeaders) {
            const headerList = Object.entries(result.exportedHeaders!)
              .map(([k, v]) => `${k}: ${v}`)
              .join(', ');
            usageInstructions += `- Include these headers in http_request calls: ${headerList}\n`;
          }
        }

        return {
          success: result.success,
          authenticated: result.success,
          strategy: result.strategy,
          sessionCookie: result.exportedCookies || '',
          headers: result.exportedHeaders || {},
          authBarrier: result.authBarrier,
          summary: result.summary,
          message: result.success
            ? `Authentication subagent succeeded. Strategy: ${result.strategy}. ${result.summary}${usageInstructions}`
            : `Authentication subagent failed. ${result.summary}${result.authBarrier ? ` Barrier: ${result.authBarrier.type} - ${result.authBarrier.details}` : ''}`,
        };
      } catch (error: any) {
        return {
          success: false,
          authenticated: false,
          message: `Auth subagent delegation failed: ${error.message}`,
        };
      }
    },
  });

  return delegate_to_auth_subagent;
}

/**
 * Schema for session-info.json file
 */
export interface SessionAuthInfo {
  authenticated: boolean;
  username?: string;
  sessionCookie?: string;
  headers?: Record<string, string>;
  loginUrl?: string;
  timestamp: string;
  delegatedToSubagent?: boolean;
}

/**
 * Factory function to create the get_auth_session tool.
 * This tool loads persisted auth info from session-info.json.
 */
export function createGetAuthSessionTool(session: Session.SessionInfo) {
  const get_auth_session = tool({
    name: 'get_auth_session',
    description: `Load persisted authentication session from session-info.json.

Use this to:
- Check if authentication has already been performed
- Get session cookies/headers for authenticated requests
- Avoid re-authenticating if valid session exists

Returns null if no session exists or session is invalid.`,
    inputSchema: z.object({
      toolCallDescription: z
        .string()
        .optional()
        .describe('A concise description of what this tool call is doing'),
    }),
    execute: async () => {
      try {
        const sessionInfoPath = join(session.rootPath, 'session-info.json');

        if (!existsSync(sessionInfoPath)) {
          return {
            success: false,
            authenticated: false,
            message: 'No session-info.json found. Authentication has not been performed.',
          };
        }

        const sessionInfo: SessionAuthInfo = JSON.parse(
          readFileSync(sessionInfoPath, 'utf-8')
        );

        if (!sessionInfo.authenticated) {
          return {
            success: false,
            authenticated: false,
            message: 'Session exists but is not authenticated.',
          };
        }

        return {
          success: true,
          authenticated: true,
          username: sessionInfo.username,
          sessionCookie: sessionInfo.sessionCookie || '',
          headers: sessionInfo.headers || {},
          loginUrl: sessionInfo.loginUrl,
          timestamp: sessionInfo.timestamp,
          message: `Found authenticated session for ${sessionInfo.username || 'unknown user'}. Use sessionCookie and headers for authenticated requests.`,
        };
      } catch (error: any) {
        return {
          success: false,
          authenticated: false,
          message: `Failed to load session info: ${error.message}`,
        };
      }
    },
  });

  return get_auth_session;
}
