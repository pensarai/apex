import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tool } from "ai";
import { z } from "zod";
import { opaqueAuthHandle } from "../../../auth/targetSession";
import { createLogger } from "../../../logger/structured";
import { scopedLogger } from "../../../util/lazyLogger";
import type { ToolContext } from "./types";

const log = scopedLogger(() => createLogger("complete_authentication"));

const AUTH_DIR = "auth";
const AUTH_DATA_FILENAME = "auth-data.json";
const TARGET_SESSION_FILENAME = "target-session.json";

/**
 * Factory for the `complete_authentication` tool.
 *
 * Signal tool — the authentication agent calls this to indicate
 * that the authentication process is finished (success or failure).
 * Used as a `stopWhen: hasToolCall("complete_authentication")` target.
 *
 * Secrets stay in a target-only session file and a runtime handle.
 * Prompts and traces receive the handle, never cookie values.
 */
export function completeAuthentication(ctx: ToolContext) {
  return tool({
    description: `Signal that the authentication process is complete.

Call this when you have either:
- Successfully authenticated and obtained a target session
- Determined that authentication is not possible (barrier detected)
- Exhausted all authentication strategies

On success, pass exported cookies/headers so trusted code can store a
target-only session. Those values are never returned to the model.

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
          "Cookie header string from authentication. Format: 'name1=value1; name2=value2'",
        ),
      exportedHeaders: z
        .record(z.string(), z.string())
        .optional()
        .describe("Auth headers to include in future requests"),
      strategy: z
        .string()
        .optional()
        .describe(
          "Authentication strategy used (browser, form_post, json_post, basic_auth, bearer, managed_google)",
        ),
      authBarrier: z
        .object({
          type: z.enum([
            "captcha",
            "mfa",
            "oauth_consent",
            "rate_limit",
            "automation_block",
            "admin_policy",
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
      const handle = opaqueAuthHandle();

      try {
        const authDir = join(ctx.session.rootPath, AUTH_DIR);
        if (!existsSync(authDir)) {
          mkdirSync(authDir, { recursive: true });
        }

        authDataPath = join(authDir, AUTH_DATA_FILENAME);

        const authData = {
          authenticated: result.success,
          strategy: result.strategy || "unknown",
          handle,
          summary: result.summary,
          target: ctx.target || "",
          timestamp: new Date().toISOString(),
          ...(result.authBarrier && { authBarrier: result.authBarrier }),
        };

        writeFileSync(authDataPath, JSON.stringify(authData, null, 2));

        if (result.success) {
          writeFileSync(
            join(authDir, TARGET_SESSION_FILENAME),
            JSON.stringify({
              handle,
              cookies: result.exportedCookies || "",
              headers: result.exportedHeaders || {},
              timestamp: new Date().toISOString(),
            }),
            { mode: 0o600 },
          );
        }
        log.debug(`Auth handle persisted to ${authDataPath}`);
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
        handle,
        strategy: result.strategy || "unknown",
        authBarrier: result.authBarrier,
        authDataPath: authDataPath || "",
        message: result.success
          ? "Authentication succeeded. Use the runtime auth handle; cookie values are not returned."
          : `Authentication failed.${result.authBarrier ? ` Barrier: ${result.authBarrier.type} — ${result.authBarrier.details}` : ""}`,
      };
    },
  });
}
