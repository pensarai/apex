/**
 * Daemon-backed browser tool factory — the Phase 4 parallel to
 * `createSandboxBrowserTools` in sandboxPlaywright.ts.
 *
 * Contract: tool names, input zod schemas, and output shapes are
 * IDENTICAL to the per-call implementation. The agent's system prompt
 * and tool-call arguments are unchanged. Only the execution substrate
 * switches: instead of launching a fresh Chromium per tool call, every
 * action goes over HTTP to the long-lived daemon inside the sandbox
 * (see sandbox-pw-daemon/daemon.cjs + sandboxPlaywrightClient.ts).
 *
 * Why this exists as a separate file rather than a branch inside
 * sandboxPlaywright.ts: the per-call path will be deleted in Phase 7,
 * and keeping the two implementations in separate files makes the
 * feature-flag swap + eventual cleanup diff-friendly.
 */

import { tool } from "ai";
import { z } from "zod";
import { mkdirSync, writeFileSync, existsSync } from "fs";
import { dirname, join } from "path";
import type {
  BrowserClickResult,
  BrowserConsoleResult,
  BrowserEvaluateResult,
  BrowserFillResult,
  BrowserNavigateResult,
  BrowserScreenshotResult,
} from "./playwrightMcp";
import type { ToolContext } from "./types";
import { callDaemon, ensureDaemon } from "./sandboxPlaywrightClient";

// --- Input schemas (intentional duplicates from sandboxPlaywright.ts) -------
// Kept in-sync by hand; will converge to a shared module when the per-call
// path is deleted in Phase 7. Every field description exactly matches the
// existing tool so the LLM's system prompt doesn't shift.

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

const BrowserSnapshotInput = z.object({
  toolCallDescription: z
    .string()
    .describe("Why you need to get the page snapshot"),
});

const BrowserEvaluateInput = z.object({
  script: z.string().describe("JavaScript code to execute in browser"),
  toolCallDescription: z
    .string()
    .describe("What you are testing with this script"),
});

const BrowserPressKeyInput = z.object({
  key: z
    .string()
    .describe(
      "Key name (Playwright format): 'Enter', 'Escape', 'Tab', 'ArrowDown', 'Backspace', or a modifier combo like 'Control+A', 'Shift+Tab'. Fires a TRUSTED keyboard event — use this instead of dispatching synthetic KeyboardEvent via browser_evaluate (which React rejects as isTrusted:false).",
    ),
  toolCallDescription: z
    .string()
    .describe("Why you are pressing this key (e.g. 'submit form via Enter')"),
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

// --- factory -----------------------------------------------------------------

export function createDaemonBrowserTools(ctx: ToolContext) {
  const sandbox = ctx.sandbox;
  if (!sandbox) {
    // createDaemonBrowserTools is only meant to be reached from the
    // `ctx.sandbox` branch of the tool factory. Guard anyway so a
    // misrouted caller fails loudly rather than silently.
    throw new Error(
      "createDaemonBrowserTools requires ctx.sandbox — use createBrowserTools (local MCP) for non-sandbox runs",
    );
  }
  const targetUrl = ctx.target ?? "";
  const evidenceDir = join(ctx.session.rootPath, "evidence");

  // Prewarm the daemon in the background so the first tool call avoids
  // a ~3s cold-start stall on top of its own latency. Non-blocking; if
  // the prewarm fails the first real call will respawn. Swallowed so
  // an unhandled rejection doesn't crash the worker.
  void ensureDaemon(sandbox).catch(() => {});

  const browser_navigate = tool({
    description: `Navigate the browser to a URL to load and render a page.

Use this to load SPAs, JavaScript-heavy pages, or any page that requires full browser rendering.
The page will be fully loaded and JavaScript executed before returning.

Target base URL: ${targetUrl}`,
    inputSchema: BrowserNavigateInput,
    execute: async ({ url }): Promise<BrowserNavigateResult> => {
      try {
        return await callDaemon<BrowserNavigateResult>(sandbox, "navigate", {
          url,
        });
      } catch (err) {
        return {
          success: false,
          url,
          error: err instanceof Error ? err.message : String(err),
        };
      }
    },
  });

  const browser_screenshot = tool({
    description: `Take a screenshot of the current page for evidence/documentation.

Use this to document:
- Exposed admin panels or sensitive pages
- Interesting error pages or debug information
- Visual proof of discovered vulnerabilities
- Login pages and authentication flows`,
    inputSchema: BrowserScreenshotInput,
    execute: async ({ filename }): Promise<BrowserScreenshotResult> => {
      try {
        const result = await callDaemon<{
          success: boolean;
          sandboxPath?: string;
          bytesB64?: string;
          error?: string;
        }>(sandbox, "screenshot", { filename });
        if (!result.success || !result.bytesB64) {
          return {
            success: false,
            error: result.error ?? "no screenshot data",
          };
        }
        // Decode base64 bytes to a local file so the host-side evidence
        // dir mirrors the production sandbox-layout contract. Matches
        // sandboxPlaywright.ts:529-540 behavior exactly.
        const basename =
          result.sandboxPath?.split("/").pop() ?? `${filename}.png`;
        const localPath = join(evidenceDir, basename);
        const parent = dirname(localPath);
        if (!existsSync(parent)) mkdirSync(parent, { recursive: true });
        writeFileSync(localPath, Buffer.from(result.bytesB64, "base64"));
        return {
          success: true,
          path: localPath,
          message: `Screenshot saved to ${localPath}`,
        };
      } catch (err) {
        return {
          success: false,
          error: err instanceof Error ? err.message : String(err),
        };
      }
    },
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
    execute: async (): Promise<{
      success: boolean;
      snapshot?: string;
      error?: string;
    }> => {
      try {
        return await callDaemon<{
          success: boolean;
          snapshot?: string;
          error?: string;
        }>(sandbox, "snapshot", {});
      } catch (err) {
        return {
          success: false,
          error: err instanceof Error ? err.message : String(err),
        };
      }
    },
  });

  const browser_click = tool({
    description: `Click on an element in the page by describing it.

Use this to:
- Navigate through multi-step flows
- Expand collapsed menus or sections
- Click buttons, links, or interactive elements
- Submit forms

IMPORTANT: For reliable clicking, first call browser_snapshot to get element refs, then pass the ref parameter.`,
    inputSchema: BrowserClickInput,
    execute: async ({ element, ref }): Promise<BrowserClickResult> => {
      try {
        return await callDaemon<BrowserClickResult>(sandbox, "click", {
          element,
          ref,
        });
      } catch (err) {
        return {
          success: false,
          error: err instanceof Error ? err.message : String(err),
        };
      }
    },
  });

  const browser_fill = tool({
    description: `Fill a form field with a value.

Use this to:
- Enter credentials for authenticated reconnaissance
- Fill search boxes or input fields
- Enter test data into forms

IMPORTANT: For reliable form filling, first call browser_snapshot to get element refs, then pass the ref parameter.`,
    inputSchema: BrowserFillInput,
    execute: async ({ element, ref, value }): Promise<BrowserFillResult> => {
      try {
        return await callDaemon<BrowserFillResult>(sandbox, "fill", {
          element,
          ref,
          value,
        });
      } catch (err) {
        return {
          success: false,
          error: err instanceof Error ? err.message : String(err),
        };
      }
    },
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
    execute: async ({ script }): Promise<BrowserEvaluateResult> => {
      try {
        return await callDaemon<BrowserEvaluateResult>(sandbox, "evaluate", {
          script,
        });
      } catch (err) {
        return {
          success: false,
          error: err instanceof Error ? err.message : String(err),
        };
      }
    },
  });

  const browser_press_key = tool({
    description: `Press a keyboard key on the currently focused element.

Use this when a form, button, or input responds to keyboard shortcuts but not to a plain click:
- Submit-on-Enter: many SPAs wire submit to the form's onSubmit handler, which fires on trusted Enter keypresses but NOT on synthetic KeyboardEvents dispatched via JS.
- Escape to close modals, Tab to navigate focus, arrow keys for option lists, etc.

Playwright fires a trusted OS-level keyboard event that modern frameworks accept. This is the CORRECT way to simulate typing — do NOT use browser_evaluate with "element.dispatchEvent(new KeyboardEvent(...))", those events are marked isTrusted: false and will be ignored by React, Vue, and Next.js form handlers.

Typical flow: browser_fill a value into a textarea → browser_press_key with key: "Enter" → the form submits.`,
    inputSchema: BrowserPressKeyInput,
    execute: async ({
      key,
    }): Promise<{ success: boolean; key?: string; error?: string }> => {
      try {
        return await callDaemon<{
          success: boolean;
          key?: string;
          error?: string;
        }>(sandbox, "press_key", { key });
      } catch (err) {
        return {
          success: false,
          error: err instanceof Error ? err.message : String(err),
        };
      }
    },
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
    execute: async (): Promise<BrowserConsoleResult> => {
      try {
        return await callDaemon<BrowserConsoleResult>(sandbox, "console", {});
      } catch (err) {
        return {
          success: false,
          error: err instanceof Error ? err.message : String(err),
        };
      }
    },
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
    execute: async ({
      urls,
    }): Promise<{
      success: boolean;
      cookies?: Array<{
        name: string;
        value: string;
        domain: string;
        path: string;
        httpOnly: boolean;
        secure: boolean;
      }>;
      cookieHeader?: string;
      error?: string;
    }> => {
      try {
        return await callDaemon<{
          success: boolean;
          cookies?: Array<{
            name: string;
            value: string;
            domain: string;
            path: string;
            httpOnly: boolean;
            secure: boolean;
          }>;
          cookieHeader?: string;
          error?: string;
        }>(sandbox, "cookies", { urls });
      } catch (err) {
        return {
          success: false,
          error: err instanceof Error ? err.message : String(err),
        };
      }
    },
  });

  return {
    browser_navigate,
    browser_snapshot,
    browser_screenshot,
    browser_click,
    browser_fill,
    browser_evaluate,
    browser_press_key,
    browser_console,
    browser_get_cookies,
  };
}
