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

import { join } from "node:path";
import { tool } from "ai";
import { z } from "zod";
import {
  getPromptInjectionLibrary,
  redactPromptInjectionPayloads,
} from "../../../prompt-injections";
import { type BrowserFillResult, createBrowserTools } from "./playwrightMcp";
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

  const cm = ctx.credentialManager;
  // A prompt-injection payload library lets the agent deliver hidden payloads
  // into text fields (chat boxes, comments, profile fields) by reference —
  // the raw payload is resolved at execution time and never shown to the model,
  // mirroring how execute_command / http_request handle refs. This is the only
  // delivery path for browser-rendered LLM chat UIs.
  const injectionEnabled = !!(
    ctx.promptInjectionLibrary || ctx.promptInjectionLibrarySource
  );

  // Nothing to wrap — return the raw browser tools unchanged.
  if (!cm && !injectionEnabled) {
    return tools;
  }

  const originalFill = tools.browser_fill;

  const shape: Record<string, z.ZodTypeAny> = {
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
        "Literal value to fill into the field. Omit when using promptInjection.id or credentialId + credentialField.",
      ),
    toolCallDescription: z
      .string()
      .describe("Why you are filling this field with this value"),
  };
  if (injectionEnabled) {
    shape.promptInjection = z
      .object({
        id: z
          .string()
          .describe(
            "Stable prompt-injection id returned by list_prompt_injections.",
          ),
      })
      .optional()
      .describe(
        "Deliver a hidden prompt-injection payload into this field instead of a literal `value`. The payload is resolved from the library by id and typed into the field WITHOUT being revealed to you; the echoed result is redacted. Use this to fire library payloads into chat boxes / text inputs, then click send.",
      );
  }
  if (cm) {
    shape.credentialId = z
      .string()
      .optional()
      .describe(
        "ID of a stored credential. When provided with credentialField, the secret is resolved automatically.",
      );
    shape.credentialField = z
      .string()
      .optional()
      .describe(
        "Which field to extract from the credential. One of: password, username, apiKey, " +
          "bearerToken, cookies, sessionToken — or the name of one of the credential's " +
          "extra secret fields. Required when credentialId is set.",
      );
  }

  let description = originalFill.description ?? "";
  if (injectionEnabled) {
    description +=
      `\n\nPrompt-injection delivery: to type a library payload into a field ` +
      `(chat box, comment, profile field, etc.), pass "promptInjection": ` +
      `{ "id": "<id from list_prompt_injections>" } and omit "value". The ` +
      `payload is injected without being revealed to you and the echoed result ` +
      `is redacted. Click send/submit afterward to deliver it.`;
  }
  if (cm) {
    description +=
      `\n\nCredential mode: Instead of passing a raw secret as "value", you can ` +
      `pass "credentialId" + "credentialField" (e.g. "password") and the value ` +
      `will be resolved securely. Always prefer this when filling password or ` +
      `secret fields.`;
  }

  const execOptions = {
    toolCallId: "",
    messages: [],
    abortSignal: undefined as never,
  };

  const wrappedFill = tool({
    description,
    inputSchema: z.object(shape),
    execute: async (rawParams) => {
      const params = rawParams as {
        element: string;
        ref?: string;
        value?: string;
        toolCallDescription: string;
        promptInjection?: { id?: string };
        credentialId?: string;
        credentialField?: string;
      };
      const { element, ref, toolCallDescription } = params;
      let value = params.value;

      // 1. Prompt-injection payload (highest precedence; never surfaced).
      if (injectionEnabled && params.promptInjection?.id) {
        const id = params.promptInjection.id;
        const library = await getPromptInjectionLibrary({
          library: ctx.promptInjectionLibrary,
          source: ctx.promptInjectionLibrarySource,
        });
        const payload = library.getPayload(id);
        if (!payload) {
          return {
            success: false,
            error: `Unknown prompt injection id: ${id}`,
          };
        }
        // The underlying browser_fill always resolves to a BrowserFillResult
        // object (never the streaming AsyncIterable form), so narrow to it.
        const fill = (await originalFill.execute?.(
          { element, ref, value: payload, toolCallDescription },
          execOptions,
        )) as BrowserFillResult | undefined;
        if (fill && fill.success === false) {
          return {
            success: false,
            element,
            error:
              redactPromptInjectionPayloads(
                String(fill.error ?? ""),
                library,
              ) || "browser_fill failed",
          };
        }
        // Redact the typed payload from the model-visible result.
        return {
          success: true,
          element,
          result: `[prompt_injection_ref ${id} typed into field; payload hidden]`,
        };
      }

      // 2. Credential resolution (only when a credential manager is present).
      if (cm && params.credentialId && params.credentialField) {
        const { credentialId, credentialField } = params;
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
        } else if (
          credentialField === "password" ||
          credentialField === "username" ||
          credentialField === "apiKey"
        ) {
          value = stored[credentialField] ?? "";
        } else {
          value = stored.additionalFields?.[credentialField] ?? "";
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
          error: injectionEnabled
            ? "Provide one of: value, promptInjection.id, or credentialId + credentialField"
            : "Either value or credentialId + credentialField must be provided",
        };
      }

      return originalFill.execute?.(
        { element, ref, value, toolCallDescription },
        execOptions,
      );
    },
  });

  return {
    ...tools,
    browser_fill: wrappedFill,
  };
}
