/**
 * Browser tool wrappers for the general agent harness.
 *
 * Delegates to the existing {@link createBrowserTools} factory from
 * `browserTools/playwrightMcp.ts`, which provisions 8 Playwright MCP
 * tools. The mode is set to `"operator"` (generic reconnaissance) by
 * default — the descriptions are broad enough for recon, auth flows,
 * and pentest use-cases alike.
 *
 * When a {@link CredentialManager} is present in the tool context,
 * `browser_fill` is wrapped so the agent can pass a `credentialId` +
 * `credentialField` instead of a raw secret value — the secret is
 * resolved at execution time and never appears in the agent prompt.
 *
 * Individual agents don't need to worry about Playwright initialisation
 * or MCP plumbing — they just list the browser tool names they want
 * in their `activeTools` array.
 */

import { tool } from "ai";
import { join } from "path";
import { z } from "zod";
import { createBrowserTools } from "./playwrightMcp";
import { createSandboxBrowserTools } from "./sandboxPlaywright";
import type { ToolContext } from "./types";

/**
 * All browser tool names that get registered in the harness.
 */
export const BROWSER_TOOL_NAMES = [
  "browser_navigate",
  "browser_snapshot",
  "browser_screenshot",
  "browser_click",
  "browser_fill",
  "browser_evaluate",
  "browser_console",
  "browser_get_cookies",
] as const;

/**
 * Create the full set of browser automation tools from a {@link ToolContext}.
 *
 * When `ctx.sandbox` is set, browser tools run inside the sandbox via direct
 * Playwright execution (no MCP). Playwright and Chromium are installed
 * on-demand in the sandbox on the first browser tool call.
 *
 * Otherwise, uses `"operator"` mode with the local Playwright MCP server.
 * The evidence directory is derived from `session.rootPath + "/evidence"`.
 * If `ctx.browserSession` is set, browser tools reuse that session instead
 * of opening a new Chromium — sub-agents inherit the parent's
 * authenticated context (cookies, localStorage, current page).
 *
 * When `ctx.credentialManager` is set, `browser_fill` is replaced with a
 * credential-aware wrapper that resolves secrets from IDs at execution time.
 */
export function createBrowserToolset(ctx: ToolContext) {
  // Sandbox mode: use direct Playwright execution inside the sandbox.
  // The sandbox path already shares browser state across tool calls via
  // the per-sandbox user-data dir, so a sub-agent running in the same
  // sandbox naturally inherits cookies / localStorage with no extra plumbing.
  const tools = ctx.sandbox
    ? createSandboxBrowserTools(ctx)
    : createBrowserTools(
        ctx.target ?? "",
        join(ctx.session.rootPath, "evidence"),
        "operator",
        undefined,
        ctx.abortSignal,
        undefined,
        undefined,
        undefined,
        ctx.browserSession,
      );

  if (!ctx.credentialManager) {
    return tools;
  }

  const originalFill = tools.browser_fill;
  const cm = ctx.credentialManager;

  const credentialAwareFill = tool({
    description:
      originalFill.description +
      `\n\nCredential mode: Instead of passing a raw secret as "value", you can pass ` +
      `"credentialId" + "credentialField" (e.g. "password") and the value will be ` +
      `resolved securely. Always prefer this when filling password or secret fields.`,
    inputSchema: z.object({
      element: z
        .string()
        .describe(
          "Description of form field, e.g., 'Username field' or 'Search input'",
        ),
      ref: z
        .string()
        .optional()
        .describe(
          "Element reference from browser_snapshot (e.g., 'e3'). If provided, uses exact element reference for precise filling.",
        ),
      value: z
        .string()
        .optional()
        .describe(
          "Value to fill into the field. Omit when using credentialId + credentialField.",
        ),
      credentialId: z
        .string()
        .optional()
        .describe(
          "ID of a stored credential. When provided with credentialField, the secret is resolved automatically.",
        ),
      credentialField: z
        .enum([
          "password",
          "username",
          "apiKey",
          "bearerToken",
          "cookies",
          "sessionToken",
        ])
        .optional()
        .describe(
          "Which field to extract from the credential (e.g. 'password'). Required when credentialId is set.",
        ),
      toolCallDescription: z
        .string()
        .describe("Why you are filling this field with this value"),
    }),
    execute: async (params) => {
      let { value } = params;
      const {
        element,
        ref,
        credentialId,
        credentialField,
        toolCallDescription,
      } = params;

      if (credentialId && credentialField) {
        const stored = cm.resolve(credentialId);
        if (!stored) {
          return {
            success: false,
            error: `Unknown credential ID: ${credentialId}`,
          };
        }
        if (
          credentialField === "bearerToken" ||
          credentialField === "cookies" ||
          credentialField === "sessionToken"
        ) {
          value = stored.tokens?.[credentialField] ?? "";
        } else {
          value = stored[credentialField] ?? "";
        }
        if (!value) {
          return {
            success: false,
            error: `Credential ${credentialId} has no ${credentialField} field`,
          };
        }
      }

      if (!value) {
        return {
          success: false,
          error:
            "Either value or credentialId + credentialField must be provided",
        };
      }

      return originalFill.execute!(
        { element, ref, value, toolCallDescription },
        { toolCallId: "", messages: [], abortSignal: undefined as never },
      );
    },
  });

  return {
    ...tools,
    browser_fill: credentialAwareFill,
  };
}
