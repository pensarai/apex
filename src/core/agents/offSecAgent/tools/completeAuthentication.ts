import { tool } from "ai";
import { z } from "zod";
import { join } from "path";
import { existsSync, mkdirSync, writeFileSync } from "fs";
import type { ToolContext } from "./types";

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
    description:
      "Signal authentication complete. On success, MUST include exportedCookies and exportedHeaders for downstream agents. Credentials persisted to session auth/ directory.",
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
    }),
    execute: async (result) => {
      console.log(
        `Authentication complete: ${result.success ? "SUCCESS" : "FAILED"}`,
      );

      let authDataPath: string | undefined;

      if (
        result.success &&
        (result.exportedCookies || result.exportedHeaders)
      ) {
        try {
          const authDir = join(ctx.session.rootPath, AUTH_DIR);
          if (!existsSync(authDir)) {
            mkdirSync(authDir, { recursive: true });
          }

          authDataPath = join(authDir, AUTH_DATA_FILENAME);

          const authData = {
            authenticated: true,
            strategy: result.strategy || "unknown",
            cookies: result.exportedCookies || "",
            headers: result.exportedHeaders || {},
            summary: result.summary,
            target: ctx.target || "",
            timestamp: new Date().toISOString(),
          };

          writeFileSync(authDataPath, JSON.stringify(authData, null, 2));
          console.log(`Auth data persisted to ${authDataPath}`);
        } catch (err) {
          console.error(`Failed to persist auth data: ${err}`);
        }
      }

      return {
        success: true,
        authenticated: result.success,
        summary: result.summary,
        exportedCookies: result.exportedCookies || "",
        exportedHeaders: result.exportedHeaders || {},
        strategy: result.strategy || "unknown",
        authBarrier: result.authBarrier,
        authDataPath: authDataPath || "",
        message: "Authentication process completed.",
      };
    },
  });
}
