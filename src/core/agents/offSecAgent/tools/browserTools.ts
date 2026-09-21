/**
 * Browser tool wrappers for the general agent harness.
 *
 * Defines the eight `browser_*` tools' AI-facing schema and description once
 * and executes them against `resolveBackends(ctx).browser` — `LocalBackends`
 * drives Playwright-MCP (`./playwrightMcp`) for the CLI/TUI, a host-injected
 * sandbox backend (`SandboxBrowserBackend`, `./sandboxPlaywright`) drives
 * Playwright directly inside the box. Tools never branch on `ctx.sandbox`
 * themselves.
 *
 * When a {@link CredentialManager} is present in the tool context,
 * `browser_fill` is wrapped so the agent can pass a `credentialId` +
 * `credentialField` instead of a raw secret value — the secret is
 * resolved at execution time and never appears in the agent prompt.
 */

import { tool } from "ai";
import { z } from "zod";
import {
  getPromptInjectionLibrary,
  redactPromptInjectionPayloads,
} from "../../../prompt-injections";
import { resolveBackends } from "../../../tools/backends/resolve";
import type {
  BrowserClickResult,
  BrowserConsoleResult,
  BrowserCookiesResult,
  BrowserEvaluateResult,
  BrowserFillResult,
  BrowserNavigateResult,
  BrowserScreenshotResult,
  BrowserSnapshotResult,
} from "../../../tools/backends/types";
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

const BrowserNavigateInput = z.object({
  url: z.string().describe("Full URL to navigate to"),
  toolCallDescription: z
    .string()
    .describe("Why you are navigating to this URL"),
});

const BrowserScreenshotInput = z.object({
  filename: z
    .string()
    .describe("Descriptive filename for screenshot (without extension)"),
  toolCallDescription: z
    .string()
    .describe("What evidence this screenshot captures"),
});

const BrowserSnapshotInput = z.object({
  toolCallDescription: z
    .string()
    .describe("Why you need to get the page snapshot"),
});

const BrowserClickInput = z.object({
  element: z
    .string()
    .describe(
      "Description of element to click, e.g., 'Submit button' or 'Login link'",
    ),
  ref: z
    .string()
    .optional()
    .describe(
      "Element reference from browser_snapshot (e.g., 'e5'). If provided, uses exact element reference for precise clicking.",
    ),
  toolCallDescription: z.string().describe("Why you are clicking this element"),
});

const BrowserFillInput = z.object({
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
  value: z.string().describe("Value to fill into the field"),
  toolCallDescription: z
    .string()
    .describe("Why you are filling this field with this value"),
});

const BrowserEvaluateInput = z.object({
  script: z.string().describe("JavaScript code to execute in browser"),
  toolCallDescription: z
    .string()
    .describe("What you are testing with this script"),
});

const BrowserConsoleInput = z.object({
  toolCallDescription: z
    .string()
    .describe("Why you need to check console messages"),
});

const BrowserGetCookiesInput = z.object({
  urls: z
    .array(z.string())
    .optional()
    .describe(
      "Optional list of URLs to get cookies for. If not provided, gets all cookies.",
    ),
  toolCallDescription: z
    .string()
    .describe("Why you need to extract cookies from the browser"),
});

/**
 * Create the full set of browser automation tools from a {@link ToolContext}.
 *
 * Execution routes through `resolveBackends(ctx).browser` — `LocalBackends`
 * for the CLI/TUI (Playwright-MCP, reusing `ctx.browserSession` when set), or
 * whatever a host injected via `ctx.backends` (a sandbox-backed
 * implementation among agent flows that run inside a Daytona sandbox).
 *
 * When `ctx.credentialManager` is set, `browser_fill` is replaced with a
 * credential-aware wrapper that resolves secrets from IDs at execution time.
 */
export function createBrowserToolset(ctx: ToolContext) {
  const targetUrl = ctx.target ?? "";

  const browser_navigate = tool({
    description: `Navigate the browser to a URL to load and render a page.

Use this to load SPAs, JavaScript-heavy pages, or any page that requires full browser rendering.
The page will be fully loaded and JavaScript executed before returning.

Target base URL: ${targetUrl}`,
    inputSchema: BrowserNavigateInput,
    execute: ({ url }): Promise<BrowserNavigateResult> =>
      resolveBackends(ctx).browser.navigate(url),
  });

  const browser_screenshot = tool({
    description: `Take a screenshot of the current page for evidence/documentation.

Use this to document:
- Exposed admin panels or sensitive pages
- Interesting error pages or debug information
- Visual proof of discovered vulnerabilities
- Login pages and authentication flows`,
    inputSchema: BrowserScreenshotInput,
    execute: ({ filename }): Promise<BrowserScreenshotResult> =>
      resolveBackends(ctx).browser.screenshot({ filename }),
  });

  const browser_snapshot = tool({
    description: `Get the accessibility snapshot of the current page.

IMPORTANT: Call this BEFORE using browser_click or browser_fill to get element references (refs).
The snapshot returns an accessibility tree with elements marked like [ref=e5].
Use these refs in browser_click and browser_fill for precise element targeting.

Example workflow:
1. Call browser_snapshot to get the page structure
2. Find the element you need (e.g., "textbox 'Email'" with [ref=e3])
3. Call browser_fill with ref="e3" to fill that specific element`,
    inputSchema: BrowserSnapshotInput,
    execute: (): Promise<BrowserSnapshotResult> =>
      resolveBackends(ctx).browser.snapshot(),
  });

  const browser_click = tool({
    description: `Click on an element in the page by describing it.

Use this to:
- Navigate through multi-step flows
- Expand collapsed menus or sections
- Click buttons, links, or interactive elements
- Submit forms

The element is identified by a natural language description.

IMPORTANT: For reliable clicking, first call browser_snapshot to get element refs, then pass the ref parameter.`,
    inputSchema: BrowserClickInput,
    execute: ({ element, ref }): Promise<BrowserClickResult> =>
      resolveBackends(ctx).browser.click({ element, ref }),
  });

  const browser_fill = tool({
    description: `Fill a form field with a value.

Use this to:
- Enter credentials for authenticated reconnaissance
- Fill search boxes or input fields
- Enter test data into forms

The field is identified by a natural language description.

IMPORTANT: For reliable form filling, first call browser_snapshot to get element refs, then pass the ref parameter.`,
    inputSchema: BrowserFillInput,
    execute: ({ element, ref, value }): Promise<BrowserFillResult> =>
      resolveBackends(ctx).browser.fill({ element, ref, value }),
  });

  const browser_evaluate = tool({
    description: `Execute JavaScript in the browser context to extract information.

CRITICAL for SPA reconnaissance - use this to extract:
- React Router routes: window.__REACT_ROUTER_VERSION__
- Next.js data: window.__NEXT_DATA__ (reveals all page routes and API endpoints)
- Vue Router routes: window.__VUE_ROUTER__?.options?.routes
- API configuration: window.API_URL, window.API_BASE_URL, window.config
- Application state: window.__REDUX_STATE__, window.__INITIAL_STATE__
- All links on page: Array.from(document.querySelectorAll('a')).map(a => a.href)
- Service worker routes: navigator.serviceWorker?.controller

The JavaScript is executed in the page context and the result is returned.`,
    inputSchema: BrowserEvaluateInput,
    execute: ({ script }): Promise<BrowserEvaluateResult> =>
      resolveBackends(ctx).browser.evaluate({ script }),
  });

  const browser_console = tool({
    description: `Get console messages from the browser.

Use this to check for:
- Leaked API keys or secrets in console output
- Debug messages revealing internal URLs or endpoints
- Error messages exposing application structure
- Warnings about deprecated endpoints
- Network request failures revealing API patterns`,
    inputSchema: BrowserConsoleInput,
    execute: (): Promise<BrowserConsoleResult> =>
      resolveBackends(ctx).browser.console(),
  });

  const browser_get_cookies = tool({
    description: `Extract cookies from the browser context, including httpOnly cookies.

CRITICAL: Use this after successful browser authentication to get session cookies that can be used in HTTP requests.

Returns all cookies including:
- Session cookies (often httpOnly, not accessible via document.cookie)
- Authentication tokens
- CSRF tokens

The returned cookies can be formatted as a Cookie header for use with http_request tool.`,
    inputSchema: BrowserGetCookiesInput,
    execute: ({ urls }): Promise<BrowserCookiesResult> =>
      resolveBackends(ctx).browser.getCookies({ urls }),
  });

  const tools = {
    browser_navigate,
    browser_snapshot,
    browser_screenshot,
    browser_click,
    browser_fill,
    browser_evaluate,
    browser_console,
    browser_get_cookies,
  };

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
