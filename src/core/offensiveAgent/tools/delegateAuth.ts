import { tool } from "ai";
import { z } from "zod";
import { join } from "path";
import { writeFileSync } from "fs";
import type { ToolContext } from "./types";
import {
  runAuthenticationSubagent,
  type AuthCredentials,
  type AuthMethod,
} from "../../agents/legacy/authenticationSubagent";

/**
 * Merge session-level credentials with explicitly passed credentials.
 * Explicit values take precedence over session defaults.
 */
function mergeAuthCredentials(
  sessionCreds: AuthCredentials | undefined,
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
  },
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

/**
 * Factory for the `delegate_to_auth_subagent` tool.
 *
 * Delegates complex authentication flows (OAuth, SAML, CSRF, browser-based)
 * to the specialised authentication sub-agent. Requires `model` in the
 * tool context.
 */
export function delegateAuth(ctx: ToolContext) {
  return tool({
    description: `Delegate authentication to the specialized auth subagent.

Use when:
- Complex auth flow detected (OAuth, SAML, CSRF tokens)
- Browser-based login required (SPA, JavaScript forms)
- Built-in authenticate_session tool failed
- MFA or CAPTCHA barrier detected
- Need to verify pre-existing tokens (bearer, API key, cookies)
- No credentials provided (will probe for open registration)

The auth subagent will:
1. Handle the authentication flow (HTTP or browser-based)
2. Document the process for re-auth
3. Return cookies/headers for authenticated requests
4. Verify tokens against protected endpoints if provided

IMPORTANT: Pass protectedEndpoints in authHints when you've discovered 401/403 endpoints.

When to use delegate_to_auth_subagent vs authenticate_session:
- Simple form POST without CSRF -> use authenticate_session
- JSON API with username/password -> use authenticate_session
- Complex flow (OAuth, CSRF, SPA, browser required) -> delegate_to_auth_subagent
- If authenticate_session fails -> delegate_to_auth_subagent
- Token verification needed -> delegate_to_auth_subagent`,
    inputSchema: z.object({
      target: z.string().describe("Target URL requiring authentication"),
      loginUrl: z.string().optional().describe("Discovered login URL if known"),
      username: z.string().optional().describe("Username if available"),
      password: z.string().optional().describe("Password if available"),
      apiKey: z.string().optional().describe("API key if available"),
      tokens: z
        .object({
          bearerToken: z
            .string()
            .optional()
            .describe("Bearer/JWT token to verify"),
          cookies: z.string().optional().describe("Cookie string to verify"),
          sessionToken: z
            .string()
            .optional()
            .describe("Session ID or token value"),
          customHeaders: z
            .record(z.string(), z.string())
            .optional()
            .describe(
              "Custom headers to verify (e.g., X-API-Key, X-Auth-Token)",
            ),
        })
        .optional()
        .describe(
          "Pre-existing tokens to verify (skips login flow, just validates these work)",
        ),
      authHints: z
        .object({
          authScheme: z
            .string()
            .optional()
            .describe("Detected auth scheme (form, json, oauth, etc.)"),
          csrfRequired: z
            .boolean()
            .optional()
            .describe("Whether CSRF protection was detected"),
          browserRequired: z
            .boolean()
            .optional()
            .describe("Whether browser automation is needed"),
          protectedEndpoints: z
            .array(z.string())
            .optional()
            .describe(
              "Protected endpoints discovered during recon that require auth",
            ),
        })
        .optional()
        .describe("Hints about the auth flow from discovery"),
      reason: z.string().describe("Why you are delegating to auth subagent"),
      toolCallDescription: z
        .string()
        .describe("A concise description of what this tool call is doing"),
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
        if (!ctx.model) {
          return {
            success: false,
            authenticated: false,
            message:
              "delegate_to_auth_subagent requires a model in the tool context.",
          };
        }

        console.log(`\n🔐 Delegating to authentication subagent...`);
        console.log(`   Target: ${target}`);
        console.log(`   Reason: ${reason}`);

        if (username) console.log(`   Username: ${username}`);
        if (apiKey) console.log(`   API Key: [PROVIDED]`);
        if (tokens?.bearerToken) console.log(`   Bearer Token: [PROVIDED]`);
        if (tokens?.cookies) console.log(`   Cookies: [PROVIDED]`);
        if (tokens?.customHeaders)
          console.log(
            `   Custom Headers: ${Object.keys(tokens.customHeaders).join(", ")}`,
          );

        const sessionCreds = ctx.session.config?.authCredentials;
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
              `   Session Custom Headers: ${Object.keys(
                sessionCreds.tokens.customHeaders,
              ).join(", ")}`,
            );
        }

        if (authHints) {
          console.log(`   Auth Scheme: ${authHints.authScheme || "unknown"}`);
          console.log(`   CSRF Required: ${authHints.csrfRequired || false}`);
          console.log(
            `   Browser Required: ${authHints.browserRequired || false}`,
          );
          if (authHints.protectedEndpoints?.length) {
            console.log(
              `   Protected Endpoints: ${authHints.protectedEndpoints.join(
                ", ",
              )}`,
            );
          }
        }

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
            session: ctx.session,
            credentials,
            authFlowHints: authHints
              ? {
                  loginEndpoints: loginUrl ? [loginUrl] : undefined,
                  protectedEndpoints: authHints.protectedEndpoints,
                  authScheme: authHints.authScheme as AuthMethod,
                  csrfRequired: authHints.csrfRequired,
                }
              : undefined,
          },
          model: ctx.model,
          enableBrowserTools: authHints?.browserRequired !== false,
        });

        if (result.success) {
          const sessionInfoPath = join(
            ctx.session.rootPath,
            "session-info.json",
          );
          const sessionInfo = {
            authenticated: true,
            username: username || "via_subagent",
            sessionCookie: result.exportedCookies || "",
            headers: result.exportedHeaders || {},
            loginUrl: target,
            timestamp: new Date().toISOString(),
            delegatedToSubagent: true,
          };
          writeFileSync(sessionInfoPath, JSON.stringify(sessionInfo, null, 2));
        }

        const hasHeaders =
          result.exportedHeaders &&
          Object.keys(result.exportedHeaders).length > 0;
        const hasCookies =
          result.exportedCookies && result.exportedCookies.length > 0;

        let usageInstructions = "";
        if (result.success && (hasHeaders || hasCookies)) {
          usageInstructions =
            "\n\nTo make authenticated requests, use the returned values:\n";
          if (hasCookies) {
            usageInstructions += `- Pass sessionCookie to crawl_authenticated_area, extract_js_endpoints, and test_endpoint_variations tools\n`;
            usageInstructions += `- For http_request, include Cookie header: "${result.exportedCookies}"\n`;
          }
          if (hasHeaders) {
            const headerList = Object.entries(result.exportedHeaders!)
              .map(([k, v]) => `${k}: ${v}`)
              .join(", ");
            usageInstructions += `- Include these headers in http_request calls: ${headerList}\n`;
          }
        }

        return {
          success: result.success,
          authenticated: result.success,
          strategy: result.strategy,
          sessionCookie: result.exportedCookies || "",
          headers: result.exportedHeaders || {},
          authBarrier: result.authBarrier,
          summary: result.summary,
          message: result.success
            ? `Authentication subagent succeeded. Strategy: ${result.strategy}. ${result.summary}${usageInstructions}`
            : `Authentication subagent failed. ${result.summary}${
                result.authBarrier
                  ? ` Barrier: ${result.authBarrier.type} - ${result.authBarrier.details}`
                  : ""
              }`,
        };
      } catch (error: unknown) {
        const errorMessage =
          error instanceof Error ? error.message : String(error);
        return {
          success: false,
          authenticated: false,
          message: `Auth subagent delegation failed: ${errorMessage}`,
        };
      }
    },
  });
}
