import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tool } from "ai";
import { z } from "zod";
import { createLogger } from "../../../logger/structured";
import { scopedLogger } from "../../../util/lazyLogger";
import type { ToolContext } from "./types";

const log = scopedLogger(() => createLogger("complete_authentication"));

const AUTH_DIR = "auth";
const AUTH_DATA_FILENAME = "auth-data.json";

/**
 * Factory for the `complete_authentication` tool.
 *
 * Signal tool — the authentication agent calls this to indicate
 * that the authentication process is finished (success or failure).
 * Used as a `stopWhen: hasToolCall("complete_authentication")` target.
 *
 * The agent MUST pass any extracted cookies, headers, and strategy so
 * they are available in the tool result for `resolveResult` to capture.
 *
 * On success the auth data is persisted to `<session>/auth/auth-data.json`
 * so other agents / resumed sessions can reload it without re-authenticating.
 */
export function completeAuthentication(ctx: ToolContext) {
  return tool({
    description: `Signal that the authentication process is complete.

Call this when you have either:
- Successfully authenticated and obtained session credentials
- Determined that authentication is not possible (barrier detected)
- Exhausted all authentication strategies

CRITICAL: When authentication succeeds, you MUST include the exported cookies and headers
so downstream agents can make authenticated requests. Pass:
- exportedCookies: The cookie string from browser_get_cookies (cookieHeader) or authenticate_session
- exportedHeaders: Any auth headers (e.g. {"Authorization": "Bearer <token>"}) from browser_evaluate or authenticate_session
- strategy: The method used ("browser", "form_post", "json_post", "basic_auth", "bearer", etc.)

On success the credentials are persisted to the session's auth/ directory for reuse.

This tool marks the end of the authentication flow.`,
    inputSchema: z.object({
      success: z.boolean().describe("Whether authentication was successful"),
      summary: z
        .string()
        .describe("Summary of authentication process and result"),
      exportedCookies: z
        .string()
        .optional()
        .describe(
          "Cookie header string from authentication (e.g. from browser_get_cookies cookieHeader field or Set-Cookie response). Format: 'name1=value1; name2=value2'",
        ),
      exportedHeaders: z
        .record(z.string(), z.string())
        .optional()
        .describe(
          'Auth headers to include in future requests (e.g. {"Authorization": "Bearer <token>"})',
        ),
      strategy: z
        .string()
        .optional()
        .describe(
          "Authentication strategy used (browser, form_post, json_post, basic_auth, bearer, api_key)",
        ),
      authBarrier: z
        .object({
          type: z.enum([
            "captcha",
            "mfa",
            "oauth_consent",
            "rate_limit",
            "unknown",
          ]),
          details: z.string(),
        })
        .optional()
        .describe("Auth barrier if one was encountered"),
      toolCallDescription: z
        .string()
        .describe("A concise description of what this tool call is doing"),
    }),
    execute: async (result) => {
      log.info(
        `Authentication complete: ${result.success ? "SUCCESS" : "FAILED"}`,
      );

      let authDataPath: string | undefined;

      try {
        const authDir = join(ctx.session.rootPath, AUTH_DIR);
        if (!existsSync(authDir)) {
          mkdirSync(authDir, { recursive: true });
        }

        authDataPath = join(authDir, AUTH_DATA_FILENAME);

        const authData = {
          authenticated: result.success,
          strategy: result.strategy || "unknown",
          cookies: result.exportedCookies || "",
          headers: result.exportedHeaders || {},
          summary: result.summary,
          target: ctx.target || "",
          timestamp: new Date().toISOString(),
          ...(result.authBarrier && { authBarrier: result.authBarrier }),
        };

        writeFileSync(authDataPath, JSON.stringify(authData, null, 2));
        log.debug(`Auth data persisted to ${authDataPath}`);
      } catch (err) {
        log.error(
          "Failed to persist auth data",
          err instanceof Error ? err : undefined,
          { error: String(err) },
        );
      }

      return {
        success: result.success,
        authenticated: result.success,
        summary: result.summary,
        exportedCookies: result.exportedCookies || "",
        exportedHeaders: result.exportedHeaders || {},
        strategy: result.strategy || "unknown",
        authBarrier: result.authBarrier,
        authDataPath: authDataPath || "",
        message: result.success
          ? "Authentication succeeded."
          : `Authentication failed.${result.authBarrier ? ` Barrier: ${result.authBarrier.type} — ${result.authBarrier.details}` : ""}`,
      };
    },
  });
}
