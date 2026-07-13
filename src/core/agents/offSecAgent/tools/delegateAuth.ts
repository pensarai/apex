import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { tool } from "ai";
import { z } from "zod";
import { CredentialManager } from "../../../credentials";
import { AgentEventBus } from "../../../eventBus";
import { newSessionId } from "../../../id/id";
import { createLogger } from "../../../logger/structured";
import { scopedLogger } from "../../../util/lazyLogger";
import type { AuthCredentials } from "../../specialized/authenticationAgent/types";
import type { ToolContext } from "./types";

const log = scopedLogger(() => createLogger("delegate_auth"));

// runAuthenticationAgent is dynamically imported inside execute() to break
// the circular dependency: authAgent → offensiveSecurityAgent → tools → delegateAuth → authAgent

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

This is the single entry point for authenticating against a target. Use it for:
- Simple logins (form POST, JSON API, HTTP Basic)
- Complex auth flows (OAuth, SAML, CSRF tokens)
- Browser-based login (SPA, JavaScript forms)
- MFA or CAPTCHA barriers (will report a barrier if it can't proceed)
- Verifying pre-existing tokens (bearer, API key, cookies)
- No credentials provided (will probe for open registration)

The auth subagent will:
1. Handle the authentication flow (HTTP or browser-based)
2. Document the process for re-auth
3. Return cookies/headers for authenticated requests
4. Verify tokens against protected endpoints if provided

IMPORTANT: Pass protectedEndpoints in authHints when you've discovered 401/403 endpoints.`,
    inputSchema: z.object({
      target: z.string().describe("Target URL requiring authentication"),
      credentialId: z
        .string()
        .optional()
        .describe(
          "ID of a stored credential. When provided, secrets are resolved automatically — do not pass username/password/apiKey/tokens.",
        ),
      loginUrl: z.string().optional().describe("Discovered login URL if known"),
      username: z
        .string()
        .optional()
        .describe("Username if available (ignored if credentialId is set)"),
      password: z
        .string()
        .optional()
        .describe("Password if available (ignored if credentialId is set)"),
      apiKey: z
        .string()
        .optional()
        .describe("API key if available (ignored if credentialId is set)"),
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
      credentialId,
      loginUrl,
      username,
      password,
      apiKey,
      tokens,
      authHints,
      reason,
    }) => {
      // Outside the try so the failure-path subagent-complete reuses this id.
      const subagentId = newSessionId();
      const subagentName = "Authentication Agent";
      try {
        if (!ctx.model) {
          return {
            success: false,
            authenticated: false,
            message:
              "delegate_to_auth_subagent requires a model in the tool context.",
          };
        }

        // Resolve credential from manager when an ID is provided
        if (credentialId && ctx.credentialManager) {
          const stored = ctx.credentialManager.resolve(credentialId);
          if (!stored) {
            return {
              success: false,
              authenticated: false,
              message: `Unknown credential ID: ${credentialId}`,
            };
          }
          username = stored.username ?? username;
          password = stored.password ?? password;
          apiKey = stored.apiKey ?? apiKey;
          loginUrl = stored.loginUrl ?? loginUrl;
          if (stored.tokens && !tokens) {
            tokens = { ...stored.tokens };
          }
        }

        ctx.eventBus?.emit("subagent-spawn", {
          subagentId,
          name: subagentName,
          input: { target, reason },
          parentSubagentId: ctx.subagentId,
        });

        log.info("Delegating to authentication subagent", {
          target,
          reason,
          username: username || undefined,
          apiKey: apiKey ? "[PROVIDED]" : undefined,
          bearerToken: tokens?.bearerToken ? "[PROVIDED]" : undefined,
          cookies: tokens?.cookies ? "[PROVIDED]" : undefined,
          customHeaders: tokens?.customHeaders
            ? Object.keys(tokens.customHeaders)
            : undefined,
        });

        const rawSessionCreds = ctx.session.config?.authCredentials;
        const sessionCreds: AuthCredentials | undefined = rawSessionCreds
          ? Array.isArray(rawSessionCreds)
            ? rawSessionCreds[0]
            : rawSessionCreds
          : undefined;
        if (sessionCreds && !username && !apiKey && !tokens) {
          log.debug("Inheriting session credentials", {
            sessionUsername: sessionCreds.username || undefined,
            sessionApiKey: sessionCreds.apiKey ? "[PROVIDED]" : undefined,
            sessionBearerToken: sessionCreds.tokens?.bearerToken
              ? "[PROVIDED]"
              : undefined,
            sessionCookies: sessionCreds.tokens?.cookies
              ? "[PROVIDED]"
              : undefined,
            sessionCustomHeaders: sessionCreds.tokens?.customHeaders
              ? Object.keys(sessionCreds.tokens.customHeaders)
              : undefined,
          });
        }

        if (authHints) {
          log.debug("Auth hints", {
            authScheme: authHints.authScheme || "unknown",
            csrfRequired: authHints.csrfRequired || false,
            browserRequired: authHints.browserRequired || false,
            protectedEndpoints: authHints.protectedEndpoints?.length
              ? authHints.protectedEndpoints
              : undefined,
          });
        }

        const credentials = mergeAuthCredentials(sessionCreds, {
          username,
          password,
          apiKey,
          loginUrl,
          tokens,
        });

        // Ensure the session has a credential manager with the resolved credentials.
        // This is the single path for secret management — the auth agent reads
        // from session.credentialManager and never sees raw secrets.
        if (!ctx.session.credentialManager) {
          ctx.session.credentialManager = new CredentialManager();
        }
        if (credentials) {
          ctx.session.credentialManager.addFromAuthCredentials(credentials);
        }

        // Dynamic import to break circular dependency:
        // authAgent → offensiveSecurityAgent → tools/index → delegateAuth → api/authentication → authAgent
        // Routing through the api barrel would re-introduce the cycle, so we
        // import the per-feature module directly.
        const { runAuthenticationAgent } = await import(
          "../../../api/authentication"
        );

        const localBus = new AgentEventBus();
        AgentEventBus.attachChild(localBus, ctx.eventBus, subagentId);

        const result = await runAuthenticationAgent({
          target,
          session: ctx.session,
          authHints,
          model: ctx.model,
          authConfig: ctx.authConfig,
          abortSignal: ctx.abortSignal,
          eventBus: localBus,
          subagentId,
          subagentName,
        });

        ctx.eventBus?.emit("subagent-complete", {
          subagentId,
          status: result.success ? "completed" : "failed",
          parentSubagentId: ctx.subagentId,
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
          authDataPath: result.authDataPath || "",
          summary: result.summary,
          message: result.success
            ? `Authentication subagent succeeded. Strategy: ${result.strategy}. ${result.summary}${usageInstructions}${
                result.authDataPath
                  ? `\nAuth data saved to: ${result.authDataPath}`
                  : ""
              }`
            : `Authentication subagent failed. ${result.summary}${
                result.authBarrier
                  ? ` Barrier: ${result.authBarrier.type} - ${result.authBarrier.details}`
                  : ""
              }`,
        };
      } catch (error: unknown) {
        ctx.eventBus?.emit("subagent-complete", {
          subagentId,
          status: "failed",
          parentSubagentId: ctx.subagentId,
        });

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
