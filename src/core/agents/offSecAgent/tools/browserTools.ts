/** Credential and hidden-payload resolution stays above the shared browser backend. */

import { tool } from "ai";
import { z } from "zod";
import {
  getPromptInjectionLibrary,
  redactPromptInjectionPayloads,
} from "../../../prompt-injections";
import { resolveBackends } from "../../../tools/backends/resolve";
import type { BrowserFillResult } from "../../../tools/backends/types";
import { createBackendBrowserToolFactories } from "./browserToolFactories";
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
 * The wrapped fill forwards the raw fill's optional execute, so its result
 * includes the streaming/undefined forms.
 */
type WrappedFillResult =
  | BrowserFillResult
  | AsyncIterable<BrowserFillResult>
  | undefined;
/** Lazy member factories for all 8 browser tools; group state shared per call. */
export type BrowserToolsetFactories = ReturnType<
  typeof createBrowserToolsetFactories
>;

/**
 * Lazy per-member browser tool factories. Shared group state (the MCP or
 * sandbox session plumbing) is built once per call; each member's tool
 * object is constructed only when its factory is invoked, so selecting one
 * browser tool never allocates sibling tool schemas. `browser_fill` is
 * wrapped lazily so the credential/injection wrapper only exists when the
 * fill tool is actually selected.
 */
export function createBrowserToolsetFactories(ctx: ToolContext) {
  const factories = createBackendBrowserToolFactories(
    resolveBackends(ctx).browser,
    { targetUrl: ctx.target ?? "" },
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

  // Nothing to wrap — return the raw member factories unchanged.
  if (!cm && !injectionEnabled) {
    return factories;
  }

  const rawFillFactory = factories.browser_fill;

  // Fill-only schemas build inside the factory so a selection that omits
  // browser_fill never allocates them.
  const wrappedFill = () => {
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

    const execOptions = {
      toolCallId: "",
      messages: [],
      abortSignal: undefined as never,
    };

    const originalFill = rawFillFactory();
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
    return tool({
      description,
      inputSchema: z.object(shape),
      execute: async (rawParams): Promise<WrappedFillResult> => {
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
  };

  return {
    ...factories,
    browser_fill: wrappedFill,
  };
}

/**
 * Create the full browser toolset (all 8 member tools materialized).
 * Compat wrapper over the lazy member factories.
 */
/** Invokes each member factory, preserving the union's whole-object branches. */
type Materialized<F> = {
  [K in keyof F]: F[K] extends () => infer T ? T : never;
};

export function createBrowserToolset(
  ctx: ToolContext,
): Materialized<BrowserToolsetFactories> {
  const factories = createBrowserToolsetFactories(ctx);
  return {
    browser_navigate: factories.browser_navigate(),
    browser_snapshot: factories.browser_snapshot(),
    browser_screenshot: factories.browser_screenshot(),
    browser_click: factories.browser_click(),
    browser_fill: factories.browser_fill(),
    browser_evaluate: factories.browser_evaluate(),
    browser_console: factories.browser_console(),
    browser_get_cookies: factories.browser_get_cookies(),
  } as Materialized<BrowserToolsetFactories>;
}
