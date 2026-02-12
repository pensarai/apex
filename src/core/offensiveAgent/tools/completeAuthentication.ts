import { tool } from "ai";
import { z } from "zod";

/**
 * Factory for the `complete_authentication` tool.
 *
 * Signal tool — the authentication agent calls this to indicate
 * that the authentication process is finished (success or failure).
 * Used as a `stopWhen: hasToolCall("complete_authentication")` target.
 */
export function completeAuthentication(_ctx: unknown) {
  return tool({
    description: `Signal that the authentication process is complete.

Call this when you have either:
- Successfully authenticated and obtained session credentials
- Determined that authentication is not possible (barrier detected)
- Exhausted all authentication strategies

This tool marks the end of the authentication flow.`,
    inputSchema: z.object({
      success: z.boolean().describe("Whether authentication was successful"),
      summary: z
        .string()
        .describe("Summary of authentication process and result"),
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
      console.log(
        `Authentication complete: ${result.success ? "SUCCESS" : "FAILED"}`
      );
      return {
        success: true,
        authenticated: result.success,
        summary: result.summary,
        authBarrier: result.authBarrier,
        message: "Authentication process completed.",
      };
    },
  });
}
